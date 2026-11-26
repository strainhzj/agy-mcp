#!/bin/sh
# launch-pi.sh: controlled launcher for a protected single-project agy-mcp
# instance (the pi profile).
#
# What it assembles, per the hardening plan (section 4.6):
#
#   outer bubblewrap namespace (the control plane)
#     agy-mcp (HTTP, bearer token, pi profile)
#       run-job supervisor (spawned by agy-mcp)
#         worker wrapper (AGY_MCP_AGY_PATH points here)
#           inner bubblewrap namespace (the worker view)
#             real agy, read-only snapshot, private HOME and /tmp
#
# The outer namespace gives the control plane a minimal host view: the
# read-only snapshot, its own state dir, the staged binaries and the bare
# shared libraries and certificate files agy needs. Host personal directories
# (~/.gemini, ~/.ssh, ~/.gnupg, ~/.aws, ~/.config, ~/.pi) are never bound, so
# neither the control plane nor anything it spawns can open them.
#
# The inner namespace takes the worker's view further: no state dir, no
# control-plane stage, no token file, a fresh HOME and a private /tmp, so a
# workspace hook or an agy tool cannot read control-plane storage even though
# MEASURED workspace hooks run on the host outside agy's own sandbox (agy
# 1.5.17, Phase 0 T3). The worker's environment is rebuilt from a whitelist,
# so the bearer token cannot reach agy or anything it spawns even before the
# mount boundary applies.
#
# The launcher is fail closed: every precondition is checked before the
# server starts, and a missing tool, snapshot or binary aborts rather than
# degrading. The bearer token is generated once, stored 0600 in the
# control-plane dir, and read by the server from a file inside the namespace:
# it never appears in an argv.
#
# Isolation claims this script does NOT make: the mount set has been
# smoke-tested (nested bwrap starts, masked directories stay masked), not
# deployment-verified. The Phase 1 acceptance checklist in deploy/README.md
# (synthetic credentials, egress targets, restart recovery) is what turns
# this script into a verified boundary. Until that checklist passes on your
# host, treat this file as a template, not a proven boundary.

set -eu

# ---------------------------------------------------------------------------
# Configuration, all from the environment (see pi.env.example).
# ---------------------------------------------------------------------------

: "${PI_PROJECT_ID:?set PI_PROJECT_ID (the deployment-assigned project id)}"
: "${PI_SNAPSHOT_DIR:?set PI_SNAPSHOT_DIR (the host directory the read-only snapshot is served from)}"
: "${PI_STATE_DIR:?set PI_STATE_DIR (this instance's private job-state directory)}"
: "${PI_CONTROL_DIR:?set PI_CONTROL_DIR (the launcher's private control-plane directory)}"
: "${PI_LISTEN_ADDR:=127.0.0.1:8765}"
PI_AGY_BIN="${PI_AGY_BIN:-$(command -v agy || true)}"
PI_BWRAP="${PI_BWRAP:-$(command -v bwrap || true)}"
PI_AGY_MCP_BIN="${PI_AGY_MCP_BIN:-$(command -v agy-mcp || true)}"
PI_AGY_CONFIG_DIR="${PI_AGY_CONFIG_DIR:-}"
PI_PROXY_URL="${PI_PROXY_URL:-}"
PI_MAX_TIMEOUT="${PI_MAX_TIMEOUT:-20m}"
PI_MAX_CONCURRENCY="${PI_MAX_CONCURRENCY:-2}"
PI_SYNC_WAIT_CAP="${PI_SYNC_WAIT_CAP:-50s}"

# ---------------------------------------------------------------------------
# Precondition checks (fail closed).
# ---------------------------------------------------------------------------

die() {
    printf 'launch-pi: %s\n' "$1" >&2
    exit 1
}

[ -n "$PI_BWRAP" ] || die "bwrap not found on PATH; the pi profile requires the bubblewrap isolation layer"
[ -x "$PI_BWRAP" ] || die "bwrap at $PI_BWRAP is not executable"
[ -n "$PI_AGY_BIN" ] || die "agy not found on PATH; set PI_AGY_BIN to the pinned agy binary"
[ -x "$PI_AGY_BIN" ] || die "agy at $PI_AGY_BIN is not executable"
[ -n "$PI_AGY_MCP_BIN" ] || die "agy-mcp not found on PATH; set PI_AGY_MCP_BIN to the server binary"
[ -x "$PI_AGY_MCP_BIN" ] || die "agy-mcp at $PI_AGY_MCP_BIN is not executable"
[ -d "$PI_SNAPSHOT_DIR" ] || die "snapshot dir $PI_SNAPSHOT_DIR does not exist"
PI_SNAPSHOT_DIR=$(cd "$PI_SNAPSHOT_DIR" && pwd -P)
case "$PI_LISTEN_ADDR" in
    127.0.0.1:*|localhost:*|\[::1\]:*) ;;
    *) die "PI_LISTEN_ADDR must be loopback; publish the endpoint with a dedicated bridge instead" ;;
esac
if [ -n "$PI_AGY_CONFIG_DIR" ]; then
    [ -d "$PI_AGY_CONFIG_DIR" ] || die "PI_AGY_CONFIG_DIR $PI_AGY_CONFIG_DIR does not exist"
    # The service identity is staged under the control dir so the outer
    # namespace can mount it at a fixed path for the worker view; the
    # launcher re-points its snapshot at the staged copy.
    mkdir -p "$PI_CONTROL_DIR"
    cp -a "$PI_AGY_CONFIG_DIR" "$PI_CONTROL_DIR/gemini"
fi

# Nested namespaces: the worker view nests bwrap. MEASURED against this
# host's bwrap build: nesting starts and one masked directory stays masked
# (Phase 0 T5); refuse early if this build cannot nest at all.
"$PI_BWRAP" --ro-bind / / /bin/true >/dev/null 2>&1 \
    || die "nested bubblewrap test failed; this build cannot host the two-level isolation"

mkdir -p "$PI_CONTROL_DIR" "$PI_STATE_DIR"
chmod 700 "$PI_CONTROL_DIR" "$PI_STATE_DIR"

# ---------------------------------------------------------------------------
# Instance identity and bearer token, both control-plane private.
# ---------------------------------------------------------------------------

# The instance id is created once and reused across restarts of the same
# instance; a rebuilt isolation boundary or a moved instance gets a fresh
# control dir and therefore a fresh id, which is the contract: an instance
# keeps its identity, a new one never inherits it.
instance_file="$PI_CONTROL_DIR/instance-id"
if [ ! -s "$instance_file" ]; then
    od -An -N16 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n' > "$instance_file" || true
    [ -s "$instance_file" ] || die "cannot generate an instance id from /dev/urandom"
    chmod 600 "$instance_file"
fi
PI_INSTANCE_ID=$(cat "$instance_file")

# The bearer token is generated once and handed only to the server process,
# which reads it from a file inside the namespace. It never appears in an
# argv, and the worker wrapper below rebuilds agy's environment from a
# whitelist, so it cannot reach agy or anything agy spawns.
token_file="$PI_CONTROL_DIR/token"
if [ ! -s "$token_file" ]; then
    od -An -N32 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n' > "$token_file" || true
    [ -s "$token_file" ] || die "cannot generate a bearer token from /dev/urandom"
    chmod 600 "$token_file"
fi

# ---------------------------------------------------------------------------
# Staging directory: the read-only view the sandboxes mount.
# ---------------------------------------------------------------------------

stage="$PI_CONTROL_DIR/stage"
rm -rf "$stage"
mkdir -p "$stage/bin" "$stage/run-control"
cp "$token_file" "$stage/run-control/token"
chmod 400 "$stage/run-control/token"
chmod 700 "$stage" "$stage/bin" "$stage/run-control"

# Pin the binaries at launch time: the worker view mounts the real agy at a
# fixed path, and a host-side upgrade mid-run cannot swap binaries under the
# sandbox (the supervisor is the same server binary re-executed).
cp "$PI_AGY_BIN" "$stage/bin/agy-real"
chmod 555 "$stage/bin/agy-real"
cp "$PI_AGY_MCP_BIN" "$stage/bin/agy-mcp"
chmod 555 "$stage/bin/agy-mcp"

# agy-wrapped: the supervisor execs whatever AGY_MCP_AGY_PATH names, so this
# wrapper is how the worker gets its own namespace without touching the
# supervisor. It rebuilds agy's environment from a short whitelist (nothing
# the control plane holds survives), then starts agy inside the inner
# namespace: shared read-only system files, the read-only snapshot, a private
# HOME and /tmp, and no control-plane mounts at all.
#
# Every generated line goes through printf with a single-quoted format, so
# each trailing double-backslash lands as one literal backslash continuation
# in the generated script and every path is baked in at write time: the
# generated wrapper runs with an empty PI_* environment, so nothing may stay
# symbolic.
{
    printf '#!/bin/sh\n'
    printf '# Worker wrapper written by launch-pi.sh; do not edit in place.\n'
    printf 'set -eu\n'
    printf 'export HOME=/home/worker\n'
    printf 'export PATH=/usr/local/bin:/usr/bin:/bin\n'
    if [ -n "$PI_PROXY_URL" ]; then
        printf "export HTTPS_PROXY='%s'\n" "$PI_PROXY_URL"
        printf "export HTTP_PROXY='%s'\n" "$PI_PROXY_URL"
        printf "export NO_PROXY=localhost,127.0.0.1,::1\n"
    fi
    printf 'exec "%s" \\\n' "$PI_BWRAP"
    printf '  --ro-bind /usr /usr \\\n'
    printf '  --ro-bind-try /lib /lib \\\n'
    printf '  --ro-bind-try /lib64 /lib64 \\\n'
    printf '  --dev /dev \\\n'
    printf '  --proc /proc \\\n'
    printf '  --ro-bind-try /etc/ssl /etc/ssl \\\n'
    printf '  --ro-bind-try /etc/resolv.conf /etc/resolv.conf \\\n'
    printf '  --ro-bind-try /etc/hosts /etc/hosts \\\n'
    printf '  --tmpfs /tmp \\\n'
    printf '  --tmpfs /run \\\n'
    printf '  --tmpfs /home \\\n'
    printf '  --tmpfs /home/worker \\\n'
    printf '  --ro-bind /workspace /workspace \\\n'
    if [ -n "$PI_AGY_CONFIG_DIR" ]; then
        # The service identity is the worker's own, mounted rw into its
        # private view: agy needs to record fresh-run session state there.
        # It is not the operator's personal config and it never appears in
        # the control plane's view.
        printf '  --bind /worker-gemini /home/worker/.gemini \\\n'
    else
        # No service identity provisioned: agy starts unconfigured, and the
        # cold-start check in the entrypoint refuses the service when agy
        # cannot answer in that state.
        printf '  --tmpfs /home/worker/.gemini \\\n'
    fi
    printf '  --ro-bind /stage/bin/agy-real /agy/agy \\\n'
    printf '  -- \\\n'
    printf '  /agy/agy "$@"\n'
} > "$stage/bin/agy-wrapped"
chmod 555 "$stage/bin/agy-wrapped"

# launch.sh: the control-plane entrypoint inside the outer namespace. It
# reads the token from the mounted control file (never from an argv), runs
# the cold-start worker check, and only then execs the server. A worker that
# cannot even start its own namespace refuses the service here, before any
# job exists.
{
    printf '#!/bin/sh\n'
    printf '# Control-plane entrypoint written by launch-pi.sh; do not edit in place.\n'
    printf 'set -eu\n'
    printf 'export HOME=/home\n'
    printf 'export PATH=/usr/local/bin:/usr/bin:/bin\n'
    printf 'export AGY_MCP_PROFILE=pi\n'
    printf "export AGY_MCP_PROJECT_ID='%s'\n" "$PI_PROJECT_ID"
    printf "export AGY_MCP_INSTANCE_ID='%s'\n" "$PI_INSTANCE_ID"
    printf 'export AGY_MCP_STATE_DIR=/state\n'
    printf 'export AGY_MCP_ALLOWED_ROOTS=/workspace\n'
    printf 'export AGY_MCP_DEFAULT_CWD=/workspace\n'
    printf 'export AGY_MCP_FORCE_SANDBOX=true\n'
    printf 'export AGY_MCP_SESSION_POLICY=disabled\n'
    printf 'export AGY_MCP_DISABLE_CONTINUE_LATEST=true\n'
    printf "export AGY_MCP_MAX_TIMEOUT='%s'\n" "$PI_MAX_TIMEOUT"
    printf "export AGY_MCP_MAX_CONCURRENCY='%s'\n" "$PI_MAX_CONCURRENCY"
    printf "export AGY_MCP_SYNC_WAIT_CAP='%s'\n" "$PI_SYNC_WAIT_CAP"
    printf 'export AGY_MCP_REQUIRE_HTTP_TOKEN=true\n'
    printf 'export AGY_MCP_HTTP_TOKEN="$(cat /stage/run-control/token)"\n'
    printf 'export AGY_MCP_AGY_PATH=/stage/bin/agy-wrapped\n'
    printf '# Cold start: the worker path (wrapper, inner namespace, pinned agy) must\n'
    printf '# answer before the service opens its port.\n'
    printf '/stage/bin/agy-wrapped --version >/dev/null\n'
    printf 'exec /stage/bin/agy-mcp -http "%s"\n' "$PI_LISTEN_ADDR"
} > "$stage/launch.sh"
chmod 555 "$stage/launch.sh"

# ---------------------------------------------------------------------------
# Launch the control plane inside the outer namespace.
# ---------------------------------------------------------------------------

exec "$PI_BWRAP" \
    --ro-bind /usr /usr \
    --ro-bind-try /lib /lib \
    --ro-bind-try /lib64 /lib64 \
    --ro-bind-try /bin /bin \
    --dev /dev \
    --proc /proc \
    --ro-bind-try /etc/ssl /etc/ssl \
    --ro-bind-try /etc/resolv.conf /etc/resolv.conf \
    --ro-bind-try /etc/hosts /etc/hosts \
    --ro-bind-try /etc/nsswitch.conf /etc/nsswitch.conf \
    --ro-bind-try /etc/passwd /etc/passwd \
    --tmpfs /tmp \
    --tmpfs /home \
    --tmpfs /run \
    --ro-bind "$PI_SNAPSHOT_DIR" /workspace \
    --bind "$PI_STATE_DIR" /state \
    --ro-bind "$stage" /stage \
    --bind-try "$PI_CONTROL_DIR/gemini" /worker-gemini \
    --die-with-parent \
    --new-session \
    -- \
    /bin/sh /stage/launch.sh
