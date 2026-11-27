#!/bin/sh
# setup-pi-local-root.sh: one-time (idempotent) root-side preparation for a
# protected pi instance on a host WITHOUT systemd (a container): a writable
# cgroup subtree with resource limits, owned by the running user, plus an
# nftables egress whitelist scoped to that subtree. Everything the instance
# does afterwards runs as the unprivileged user; this script only prepares
# the kernel boundaries the systemd unit would otherwise enforce.
#
#   sudo ./setup-pi-local-root.sh [cgroup-path] [run-user] [proxy-port]
#
# Defaults: /sys/fs/cgroup/agy-pi-review, piagent, 3128.
# The launcher enrolls itself when PI_CGROUP names the subtree (it refuses a
# set-but-unusable PI_CGROUP, so ordering matters: run this first).
#
# If the container runtime forbids remounting the cgroup hierarchy
# read-write, resource caps AND the cgroup-scoped egress rules are
# unavailable: the deployment falls back to the residuals documented in
# README.md and the endpoint must not be exposed without accepting them.
set -eu

CG=${1:-/sys/fs/cgroup/agy-pi-review}
RUN_USER=${2:-piagent}
PROXY_PORT=${3:-3128}
# Comma-separated outbound TCP port whitelist (defaults to the proxy port).
# On a host where agy reaches the model endpoints directly, pass 443 here
# (and keep the proxy port if one is used); the whitelist is destination
# port only, so keep the list to exactly what the model traffic needs.
ALLOW_TCP=${PI_SETUP_ALLOW_TCP:-$PROXY_PORT}
MEM_MAX=${PI_SETUP_MEM_MAX:-1G}
CPU_MAX=${PI_SETUP_CPU_MAX:-200000 100000}
PIDS_MAX=${PI_SETUP_PIDS_MAX:-128}
# The nft table is recreated on every run, so each instance of a multi-project
# deployment needs its own table name or a second run would delete the first
# instance's egress whitelist. Default keeps the historical single-instance
# name; a second instance passes its own (for example PI_SETUP_TABLE=agy_pi_p2).
TABLE=${PI_SETUP_TABLE:-agy_pi_review}

die() {
    printf 'setup-pi-local-root: %s\n' "$1" >&2
    exit 1
}

[ "$(id -u)" = 0 ] || die "run as root (sudo)"
command -v nft >/dev/null || die "nft not found"
command -v mountpoint >/dev/null || die "mountpoint not found"
id "$RUN_USER" >/dev/null || die "user $RUN_USER does not exist"

# --- cgroup subtree with limits -------------------------------------------
mountpoint -q /sys/fs/cgroup || die "/sys/fs/cgroup is not a mountpoint"
if ! mount -o remount,rw /sys/fs/cgroup 2>/dev/null; then
    die "cannot remount /sys/fs/cgroup rw; the runtime forbids mount, so resource caps and the cgroup-scoped egress rules cannot work (see README.md residuals)"
fi
for c in memory cpu pids; do
    grep -qw "$c" /sys/fs/cgroup/cgroup.controllers \
        || die "$c controller not available at the container's cgroup root"
done
# Enable the controllers for the subtree we are about to create. The
# no-internal-process constraint does not apply to the hierarchy root, which
# in the container is this deployment's own service cgroup.
for c in memory cpu pids; do
    grep -qw "$c" /sys/fs/cgroup/cgroup.subtree_control || echo "+$c" > /sys/fs/cgroup/cgroup.subtree_control
done
mkdir -p "$CG"
echo "$MEM_MAX" > "$CG/memory.max"
echo "$CPU_MAX" > "$CG/cpu.max"
echo "$PIDS_MAX" > "$CG/pids.max"
chown -R "$RUN_USER" "$CG"
chmod 700 "$CG"

# --- nftables egress whitelist scoped to the instance cgroup ---------------
# The whole instance tree (server, supervisor, worker, hooks) lives in the
# subtree above, so this one rule is the network boundary for everything the
# instance spawns: outbound TCP is allowed only to the model proxy port;
# any other destination (other loopback services, direct model endpoints,
# unrelated ports) is dropped by the kernel. Inbound traffic and other
# users' traffic are untouched.
nft list table inet "$TABLE" >/dev/null 2>&1 && nft delete table inet "$TABLE"
CG_NAME=$(basename "$CG")
case "$ALLOW_TCP" in
    *,*) PORT_MATCH="{ $ALLOW_TCP }" ;;
    *)   PORT_MATCH="$ALLOW_TCP" ;;
esac
nft -f - <<EOF
table inet $TABLE {
	chain egress {
		type filter hook output priority filter; policy accept;
		socket cgroupv2 level 1 "$CG_NAME" tcp dport != $PORT_MATCH counter drop
	}
}
EOF

printf 'ok: cgroup %s (memory=%s cpu=%s pids=%s) owned by %s\n' "$CG" "$MEM_MAX" "$CPU_MAX" "$PIDS_MAX" "$RUN_USER"
printf 'ok: nft egress whitelist active for table "%s" (cgroup "%s"): outbound tcp limited to port(s) %s\n' "$TABLE" "$CG_NAME" "$ALLOW_TCP"
printf 'verify (as %s, after the instance starts): a probe from inside the\n' "$RUN_USER"
printf 'instance to an unrelated port must hang/deny while the proxy path works;\n'
printf 'a probe that SUCCEEDS means the boundary is absent and the endpoint must\n'
printf 'not be exposed.\n'
