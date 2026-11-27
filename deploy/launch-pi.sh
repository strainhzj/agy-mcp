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
# deployment-verified. The worker namespace is a PID namespace, so when the
# worker's bwrap exits (cancel, timeout, supervisor death) the kernel reaps
# every process left inside it, including setsid descendants no process-group
# kill could reach; that reclaim path and the rest of the boundary still
# belong to the Phase 1 acceptance checklist in deploy/README.md. Until that
# checklist passes on your host, treat this file as a template, not a proven
# boundary.

set -eu

# ---------------------------------------------------------------------------
# Configuration, all from the environment (see pi.env.example).
# ---------------------------------------------------------------------------

: "${PI_PROJECT_ID:?set PI_PROJECT_ID (the deployment-assigned project id)}"
# The charset is the project-manifest contract, not a shell convenience: the
# server validates project_id against lowercase letters, digits, dot, dash and
# underscore, so an id the launcher accepts but the manifest would refuse is a
# launch that dies at startup with a confusing message. Refuse it here, where
# the operator is looking.
case "$PI_PROJECT_ID" in
    *[!a-z0-9._-]*) die "PI_PROJECT_ID must be lowercase letters, digits, dot, dash or underscore; the project manifest validates the same shape" ;;
esac
: "${PI_SNAPSHOT_DIR:?set PI_SNAPSHOT_DIR (the host directory the read-only snapshot is served from)}"
: "${PI_STATE_DIR:?set PI_STATE_DIR (this instance's private job-state directory)}"
: "${PI_CONTROL_DIR:?set PI_CONTROL_DIR (the launcher's private control-plane directory)}"
# The default is this instance's DEDICATED loopback address: the loopback /8
# is per-instance address space, and the unit's egress drop-in admits exactly
# this one address, so a worker that dials any other host loopback service is
# denied by the kernel. The shared 127.0.0.1 cannot give that guarantee (on
# it the allowlist cannot tell this endpoint from every other host service),
# which is why it is refused below.
: "${PI_LISTEN_ADDR:=127.0.0.8:8765}"
PI_AGY_BIN="${PI_AGY_BIN:-$(command -v agy || true)}"
PI_BWRAP="${PI_BWRAP:-$(command -v bwrap || true)}"
PI_AGY_MCP_BIN="${PI_AGY_MCP_BIN:-$(command -v agy-mcp || true)}"
PI_AGY_CONFIG_DIR="${PI_AGY_CONFIG_DIR:-}"
PI_PROXY_URL="${PI_PROXY_URL:-}"
PI_MAX_TIMEOUT="${PI_MAX_TIMEOUT:-20m}"
PI_MAX_CONCURRENCY="${PI_MAX_CONCURRENCY:-2}"
PI_SYNC_WAIT_CAP="${PI_SYNC_WAIT_CAP:-50s}"
PI_SESSION_POLICY="${PI_SESSION_POLICY:-disabled}"
PI_SESSION_TTL="${PI_SESSION_TTL:-168h}"
PI_GEMINI_TMPFS_SIZE="${PI_GEMINI_TMPFS_SIZE:-256MiB}"
# Optional cgroup subtree the whole instance tree self-enrolls into (resource
# caps plus the nft egress whitelist scope). Prepared by the root-side setup
# script on hosts without systemd; unset keeps upstream behavior.
PI_CGROUP="${PI_CGROUP:-}"

# Locale and timezone are baked into the generated scripts, so their values
# must be ones a single-quoted shell string can carry safely; anything odd
# falls back to a safe default instead of reaching the sandbox.
sanitize_word() {
    case "$1" in
        "") printf '%s\n' "$2" ;;
        *[!A-Za-z0-9._@/+-]*) printf '%s\n' "$2" ;;
        *) printf '%s\n' "$1" ;;
    esac
}
PI_LANG=$(sanitize_word "${LANG:-}" "C.UTF-8")
PI_TZ=$(sanitize_word "${TZ:-}" "UTC")
if [ -n "$PI_PROXY_URL" ]; then
    case "$PI_PROXY_URL" in
        http://*|https://*) ;;
        *) die "PI_PROXY_URL must be an http(s) URL" ;;
    esac
    case "$PI_PROXY_URL" in
        # note: no '&' in the allowed set; dash cannot parse it in a case
        # pattern and a proxy URL with a query string can be percent-encoded.
        *[!A-Za-z0-9.:/_?=%@+-]*) die "PI_PROXY_URL contains characters the launcher will not bake into a script" ;;
    esac
fi

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
    127.0.0.1:*|localhost:*)
        die "PI_LISTEN_ADDR must name this instance's dedicated loopback address (for example 127.0.0.8:8765), never the shared 127.0.0.1 or localhost: the unit's egress allowlist can only isolate a dedicated address, and on a shared one the worker could reach every other host loopback service" ;;
    127.*:*) ;;
    *) die "PI_LISTEN_ADDR must be a loopback 127.x.x.x address; publish the endpoint with a dedicated bridge instead" ;;
esac
case "$PI_SESSION_POLICY" in
    disabled|managed-only) ;;
    *) die "PI_SESSION_POLICY must be disabled or managed-only" ;;
esac
if [ -n "$PI_CGROUP" ]; then
    case "$PI_CGROUP" in /*) ;; *) die "PI_CGROUP must be an absolute path" ;; esac
    [ -d "$PI_CGROUP" ] || die "PI_CGROUP $PI_CGROUP does not exist; run the root-side setup (deploy/setup-pi-local-root.sh) first"
    [ -w "$PI_CGROUP/cgroup.procs" ] || die "PI_CGROUP $PI_CGROUP is not writable by this user; the root-side setup must chown the subtree to the running user"
fi
if [ -n "$PI_AGY_CONFIG_DIR" ]; then
    [ -d "$PI_AGY_CONFIG_DIR" ] || die "PI_AGY_CONFIG_DIR $PI_AGY_CONFIG_DIR does not exist"
    # The service identity is staged under the control dir so the outer
    # namespace can mount it at a fixed path for the worker view; the
    # launcher re-points its snapshot at the staged copy. Replace the staged
    # copy whole: a cp -a into an existing directory would nest a second
    # .gemini inside the old one instead of updating it.
    mkdir -p "$PI_CONTROL_DIR"
    rm -rf "$PI_CONTROL_DIR/gemini"
    cp -a "$PI_AGY_CONFIG_DIR" "$PI_CONTROL_DIR/gemini"
fi

# Fingerprint the snapshot the deployment serves. The fingerprint binds job
# ownership and idempotent replay to one snapshot version (the server refuses
# both across versions), so it must change when the served CONTENT changes.
#
# The hash therefore covers each file's contents, not only its metadata: a
# metadata-only digest (path, size, mtime) survives an in-place edit that keeps
# the size and restores the timestamps, which is exactly the shape a redeploy
# produces when a controlled pipeline rewrites a file. Cost is one content pass
# over the snapshot at launch time, which is the price of making a redeploy a
# new deployment instead of a silent continuation of stale answers.
#
# Directories contribute their path only (a directory has no content), and the
# whole list is sorted before hashing so the digest does not depend on
# filesystem iteration order. Symlinks are skipped rather than followed: a link
# pointing outside the snapshot is a deployment error the snapshot pipeline is
# responsible for stripping, and following it here would fold outside content
# into this deployment's identity.
PI_SNAPSHOT_FINGERPRINT=$(cd "$PI_SNAPSHOT_DIR" && find . -xdev \( -type f -o -type d \) -print 2>/dev/null | LC_ALL=C sort | while IFS= read -r p; do
    if [ -f "$p" ]; then
        printf 'f %s %s ' "$p" "$(wc -c < "$p" | tr -d ' ')"
        sha256sum "$p" | cut -d' ' -f1
    else
        printf 'd %s\n' "$p"
    fi
done | sha256sum | cut -d' ' -f1)
[ -n "$PI_SNAPSHOT_FINGERPRINT" ] || die "cannot fingerprint the snapshot dir $PI_SNAPSHOT_DIR"
PI_SNAPSHOT_FINGERPRINT="sha256:$PI_SNAPSHOT_FINGERPRINT"

# Nested namespaces: the worker view nests bwrap. MEASURED against this
# host's bwrap build: nesting starts and one masked directory stays masked
# (Phase 0 T5); refuse early if this build cannot nest at all. The worker's
# .gemini tmpfs is bounded with --size, so this build must also know that
# option: a tmpfs without a size limit is only as bounded as the unit's
# memory cap, and the disk-bound guarantee wants the kernel-enforced one.
"$PI_BWRAP" --ro-bind / / /bin/true >/dev/null 2>&1 \
    || die "nested bubblewrap test failed; this build cannot host the two-level isolation"
"$PI_BWRAP" --help 2>&1 | grep -q -- '--size' \
    || die "this bubblewrap has no --size option; the worker's .gemini tmpfs cannot be bounded"

# gemini_size_bytes converts 256MiB-style suffixes (case-insensitive) or a
# bare byte count to bytes, so PI_GEMINI_TMPFS_SIZE reads like a size.
gemini_size_bytes() {
    v=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    case "$v" in
        *kib) mul=1024; v=${v%kib} ;;
        *mib) mul=1048576; v=${v%mib} ;;
        *gib) mul=1073741824; v=${v%gib} ;;
        *tib) mul=1099511627776; v=${v%tib} ;;
        *b) mul=1; v=${v%b} ;;
        *) mul=1 ;;
    esac
    case "$v" in ''|*[!0-9]*) return 1 ;;
    esac
    echo $((v * mul))
}
PI_GEMINI_TMPFS_BYTES=$(gemini_size_bytes "$PI_GEMINI_TMPFS_SIZE") \
    || die "PI_GEMINI_TMPFS_SIZE must be like 256MiB or a plain byte count"
[ "$PI_GEMINI_TMPFS_BYTES" -gt 0 ] || die "PI_GEMINI_TMPFS_SIZE must be positive"

# The fixed neutral path the OUTER namespace binds the host snapshot at, and
# what the project manifest names as its snapshot root. It is deliberately not
# /workspace: the control plane runs in the host view, where no such mount
# exists, and the mapping from the worker view (/workspace) onto this path is
# exactly what the server implements from the manifest. The worker's inner
# namespace binds this path at /workspace.
PI_SNAPSHOT_MOUNT="/snapshot"

# The HTTP Host allowlist the server enforces. No default: it names the
# published endpoint the client actually reaches and this instance's own listen
# address, and guessing either would lock the real client out or admit an
# endpoint nobody chose. The server refuses to start under the profile without
# it, so a missing value here is a deployment error, not a silent widening.
: "${PI_ALLOWED_HOSTS:?set PI_ALLOWED_HOSTS (comma-separated host[:port]: the published endpoint and this instance's listen address, e.g. 192.168.5.45:8865,127.0.0.8:8765)}"
case "$PI_ALLOWED_HOSTS" in
    *,*|*:*) ;;
    *) die "PI_ALLOWED_HOSTS must name at least the published endpoint and this instance's listen address (host:port), comma-separated" ;;
esac
for h in $(printf '%s' "$PI_ALLOWED_HOSTS" | tr ',' ' '); do
    case "$h" in
        *[!A-Za-z0-9.:_-]*|'') die "PI_ALLOWED_HOSTS entry $h: want host[:port] with no scheme, path or whitespace" ;;
    esac
done

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

# The deployment record is the server's proof that this state dir belongs to
# this launcher-written deployment (project, instance and snapshot version).
# The server refuses to start without a matching record, so a bare start of
# the profile, two instances sharing one state dir, and a snapshot change
# reusing an old identity are all refused before any job exists. Written
# atomically; an existing record for a different deployment aborts the launch
# instead of being overwritten.
record_tmp="$PI_STATE_DIR/.instance.json.tmp"
printf '{"contract":1,"project_id":"%s","instance_id":"%s","snapshot_fingerprint":"%s"}\n' \
    "$PI_PROJECT_ID" "$PI_INSTANCE_ID" "$PI_SNAPSHOT_FINGERPRINT" > "$record_tmp"
if [ -s "$PI_STATE_DIR/instance.json" ] && ! cmp -s "$record_tmp" "$PI_STATE_DIR/instance.json"; then
    die "state dir $PI_STATE_DIR holds a deployment record for another project, instance or snapshot; use a fresh state dir for a new deployment"
fi
mv "$record_tmp" "$PI_STATE_DIR/instance.json"
chmod 600 "$PI_STATE_DIR/instance.json"

# ---------------------------------------------------------------------------
# Project manifest: the deployment-side statement of what this instance serves.
# ---------------------------------------------------------------------------

# The manifest is what the server loads at startup to learn the project it
# serves and where the snapshot lives. It is written HERE rather than read from
# the workspace so that nothing a workspace write can reach can change it, and
# it lives in the control dir rather than the state dir because it is
# deployment configuration, not job state: the job-store budget and GC must not
# account for it, and a manifest inside the state dir is refused at startup.
#
# snapshot_root names the path the CONTROL PLANE resolves. The outer namespace
# binds the host snapshot at the fixed neutral path below (never at /workspace:
# the control plane runs in the host view, where no such mount exists, and that
# is exactly the mapping the server implements). PI_SNAPSHOT_DIR stays the host
# path, used as the bind source and recorded for the operator.
manifest_file="$PI_CONTROL_DIR/project-manifest.json"
manifest_tmp="$manifest_file.tmp"
printf '{"schema_version":1,"project_id":"%s","snapshot_root":"%s","snapshot_fingerprint":"%s","worker_mount":"/workspace","read_only":true}\n' \
    "$PI_PROJECT_ID" "$PI_SNAPSHOT_MOUNT" "$PI_SNAPSHOT_FINGERPRINT" > "$manifest_tmp"
if [ -s "$manifest_file" ] && ! cmp -s "$manifest_tmp" "$manifest_file"; then
    die "control dir $PI_CONTROL_DIR holds a manifest for another project or snapshot; use a fresh control dir for a new deployment"
fi
mv "$manifest_tmp" "$manifest_file"
# Read-only for everyone but the owner: the server only reads it, and a
# group- or world-writable manifest is refused at startup.
chmod 440 "$manifest_file"

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

# The project manifest rides into the namespace read-only, next to the token:
# the server reads it at startup and nothing else may write it. It is staged
# rather than pointed at directly so the control plane's only view of it is the
# read-only one the sandbox mounts.
cp "$manifest_file" "$stage/project-manifest.json"
chmod 400 "$stage/project-manifest.json"

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
# HOME and /tmp, and no control-plane mounts at all. The inner namespace is a
# PID namespace: from inside it, the control plane's processes do not exist
# (no /proc handles into their mounts, no signal can address them), and when
# this bwrap exits (cancel, timeout, or the supervisor dying) the kernel SIGKILLs
# everything left inside the namespace, including setsid descendants a
# process-group kill would never reach.
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
    printf "export LANG='%s'\n" "$PI_LANG"
    printf "export TZ='%s'\n" "$PI_TZ"
    if [ -n "$PI_PROXY_URL" ]; then
        printf "export HTTPS_PROXY='%s'\n" "$PI_PROXY_URL"
        printf "export HTTP_PROXY='%s'\n" "$PI_PROXY_URL"
        printf "export NO_PROXY=localhost,127.0.0.1,::1\n"
    fi
    printf 'exec "%s" \\\n' "$PI_BWRAP"
    printf '  --ro-bind /usr /usr \\\n'
    printf '  --ro-bind-try /lib /lib \\\n'
    printf '  --ro-bind-try /lib64 /lib64 \\\n'
    printf '  --ro-bind-try /bin /bin \\\n'
    printf '  --dev /dev \\\n'
    printf '  --unshare-pid \\\n'
    printf '  --proc /proc \\\n'
    printf '  --cap-drop ALL \\\n'
    printf '  --die-with-parent \\\n'
    printf '  --ro-bind-try /etc/ssl /etc/ssl \\\n'
    printf '  --ro-bind-try /etc/resolv.conf /etc/resolv.conf \\\n'
    printf '  --ro-bind-try /etc/hosts /etc/hosts \\\n'
    printf '  --tmpfs /tmp \\\n'
    printf '  --tmpfs /run \\\n'
    printf '  --tmpfs /home \\\n'
    printf '  --tmpfs /home/worker \\\n'
    # The worker's view of the project: the neutral mount point agy and the
    # caller's --add-dir arguments speak. It is bound from the outer
    # namespace's snapshot mount, never from the host path, so nothing
    # inside the worker can name the host directory the snapshot came from.
    printf '  --ro-bind /snapshot /workspace \\\n'
    if [ -n "$PI_AGY_CONFIG_DIR" ]; then
        # The service identity is the worker's own, but it never arrives as a
        # writable host mount: /seed is the READ-ONLY staged copy (bound by
        # the outer namespace), and each job starts with a fresh copy of it
        # on a size-limited tmpfs (the seed line below runs inside the
        # namespace before agy). A stuck or malicious job therefore cannot
        # fill the host disk through its agy config, and no job's writes
        # (token refreshes included) survive into the next job; re-provision
        # the service identity if a provider rotates refresh tokens between
        # jobs (see README.md).
        printf '  --ro-bind-try /seed /seed \\\n'
        printf '  --size %s --tmpfs /home/worker/.gemini \\\n' "$PI_GEMINI_TMPFS_BYTES"
    else
        # No service identity provisioned: agy starts unconfigured, and the
        # cold-start check in the entrypoint refuses the service when agy
        # cannot answer in that state. The tmpfs is still size-bounded: an
        # unconfigured agy must not become the one unbounded writable path.
        printf '  --size %s --tmpfs /home/worker/.gemini \\\n' "$PI_GEMINI_TMPFS_BYTES"
    fi
    printf '  --ro-bind /stage/bin/agy-real /agy/agy \\\n'
    printf '  -- \\\n'
    if [ -n "$PI_AGY_CONFIG_DIR" ]; then
        # Seed the fresh .gemini from the read-only staged copy, then exec
        # agy with the wrapper's own arguments. The cp is best effort: a
        # missing /seed leaves an empty .gemini, which the cold-start check
        # would already have refused the service over.
        printf '  /bin/sh -c '\''cp -a /seed/. /home/worker/.gemini/ 2>/dev/null || true; exec /agy/agy "$@"'\'' agy "$@"\n'
    else
        printf '  /agy/agy "$@"\n'
    fi
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
    printf "export LANG='%s'\n" "$PI_LANG"
    printf "export TZ='%s'\n" "$PI_TZ"
    printf '# Cold start: the worker path (wrapper, inner namespace, pinned agy) must\n'
    printf '# answer before the service opens its port. This runs BEFORE any\n'
    printf '# AGY_MCP_* variable is exported, so the probe proves the worker starts\n'
    printf '# without ever holding the bearer token in its environment.\n'
    printf '/stage/bin/agy-wrapped --version >/dev/null\n'
    printf 'export AGY_MCP_PROFILE=pi\n'
    printf "export AGY_MCP_PROJECT_ID='%s'\n" "$PI_PROJECT_ID"
    printf "export AGY_MCP_INSTANCE_ID='%s'\n" "$PI_INSTANCE_ID"
    printf 'export AGY_MCP_STATE_DIR=/state\n'
    printf 'export AGY_MCP_ALLOWED_ROOTS=/workspace\n'
    printf 'export AGY_MCP_DEFAULT_CWD=/workspace\n'
    printf 'export AGY_MCP_FORCE_SANDBOX=true\n'
    # The project manifest is how the control plane learns the project it
    # serves and where the snapshot lives. Without it the profile refuses to
    # start, so a bare start outside the controlled pipeline cannot serve.
    printf 'export AGY_MCP_PROJECT_MANIFEST=/stage/project-manifest.json\n'
    printf "export AGY_MCP_SNAPSHOT_FINGERPRINT='%s'\n" "$PI_SNAPSHOT_FINGERPRINT"
    # The Host allowlist the bridge deployment publishes. The bridge forwards
    # the client's Host header, so the server must admit the published endpoint
    # and its own listen address, and refuse anything else.
    printf "export AGY_MCP_HTTP_ALLOWED_HOSTS='%s'\n" "$PI_ALLOWED_HOSTS"
    # Agent selection is off by default under the profile: an agent name is a
    # host-side concept a caller cannot be trusted to pick. Opening it is a
    # deliberate act that also names the whitelist.
    printf 'export AGY_MCP_DISABLE_AGENT_SELECTION=true\n'
    printf "export AGY_MCP_SESSION_POLICY='%s'\n" "$PI_SESSION_POLICY"
    if [ "$PI_SESSION_POLICY" = managed-only ]; then
        printf "export AGY_MCP_SESSION_TTL='%s'\n" "$PI_SESSION_TTL"
    fi
    printf 'export AGY_MCP_DISABLE_CONTINUE_LATEST=true\n'
    printf "export AGY_MCP_MAX_TIMEOUT='%s'\n" "$PI_MAX_TIMEOUT"
    printf "export AGY_MCP_MAX_CONCURRENCY='%s'\n" "$PI_MAX_CONCURRENCY"
    printf "export AGY_MCP_SYNC_WAIT_CAP='%s'\n" "$PI_SYNC_WAIT_CAP"
    printf 'export AGY_MCP_REQUIRE_HTTP_TOKEN=true\n'
    printf 'export AGY_MCP_HTTP_TOKEN="$(cat /stage/run-control/token)"\n'
    printf 'export AGY_MCP_AGY_PATH=/stage/bin/agy-wrapped\n'
    if [ -n "$PI_CGROUP" ]; then
        printf '# Enroll this process tree into the prepared cgroup subtree: resource\n'
        printf '# caps and the nft egress whitelist scope apply from here on, worker\n'
        printf '# included (membership is inherited).\n'
        printf 'echo "$$" > /cgroup/cgroup.procs\n'
    fi
    printf 'exec /stage/bin/agy-mcp -http "%s"\n' "$PI_LISTEN_ADDR"
} > "$stage/launch.sh"
chmod 555 "$stage/launch.sh"

# ---------------------------------------------------------------------------
# Launch the control plane inside the outer namespace.
# ---------------------------------------------------------------------------

# The instance's cgroup subtree is bound read-write into the control plane's
# view (at the fixed path /cgroup) so the generated entrypoint can enroll the
# server into it; membership is inherited by every child, worker included.
# The worker's inner namespace binds none of it.
CG_BIND=""
if [ -n "$PI_CGROUP" ]; then
    CG_BIND="--bind $PI_CGROUP /cgroup"
fi

exec "$PI_BWRAP" \
    --clearenv \
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
    # The snapshot is bound at the neutral path the project manifest names as
    # its snapshot root, NOT at /workspace: the control plane runs in the host
    # view, where no /workspace mount exists, and the mapping from the worker
    # view (/workspace) onto this path is what the server implements from the
    # manifest. Binding it at /workspace here would give the control plane the
    # very mount the mapping is meant to abstract away.
    --ro-bind "$PI_SNAPSHOT_DIR" "$PI_SNAPSHOT_MOUNT" \
    --bind "$PI_STATE_DIR" /state \
    --ro-bind "$stage" /stage \
    --ro-bind-try "$PI_CONTROL_DIR/gemini" /seed \
    $CG_BIND \
    --die-with-parent \
    --new-session \
    -- \
    /bin/sh /stage/launch.sh
