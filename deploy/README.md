# Protected pi-instance deployment (Phase 1)

This directory holds the controlled launcher and deployment manifest for one
protected single-project agy-mcp instance: the Phase 1 shape from
docs/pi-sandbox-hardening.md (single project, single turn, read-only
snapshot). One instance serves one project; a second project is a second
instance with its own identity, state dir, token and endpoint, never a wider
`AllowedRoots`.

## Files

| File | Role |
|---|---|
| `launch-pi.sh` | the controlled launcher: checks preconditions, generates the instance id and bearer token once, writes the deployment record (project, instance, snapshot fingerprint) into the state dir, stages the pinned binaries, assembles the outer (control plane) and inner (worker) bubblewrap namespaces, runs the cold-start worker check, then execs the server |
| `pi.env.example` | the launcher's configuration, commented; copy, review every line, source it |
| `agy-mcp-pi@.service` | systemd template unit hosting one instance per project: dedicated service account, resource limits, and the kernel-enforced egress allowlist |

## What the launcher enforces

- **Two mount boundaries plus a PID boundary.** The control plane (server
  plus supervisor) sees the read-only snapshot, its own state dir, the staged
  binaries and nothing else of the host: personal directories (`~/.gemini`,
  `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.config`, `~/.pi`) are not bound
  anywhere. The worker (agy and everything it spawns, hooks included) sees
  less: the snapshot, minimal system files, a private HOME and /tmp, and no
  control-plane mounts. Its agy sign-in state arrives as a FRESH COPY of the
  read-only staged identity on a size-limited tmpfs (per job), so the worker
  holds no writable host mount at all and a stuck job cannot fill the disk
  through its config. The worker's namespace is also a PID namespace: from
  inside it the control plane's processes do not exist, so no `/proc/<pid>/root`
  handle reaches the token or the job store, no signal can address the
  control plane, and when the worker's bwrap exits (cancel, timeout, or the
  supervisor dying) the kernel SIGKILLs everything left inside, including
  setsid descendants a process-group kill would never reach.
- **Token and environment hygiene.** The bearer token is generated once
  (0600, control dir), read by the server from a file inside the namespace,
  and never appears in an argv. The control plane starts under bwrap
  `--clearenv` and rebuilds exactly the variables it needs; the cold-start
  worker probe runs before any `AGY_MCP_*` variable exists in that
  environment, so the probe proves the worker path works without ever
  holding the token. agy-mcp itself strips `AGY_MCP_*` from every child
  environment, protected jobs reduce the worker environment further to a
  strict allowlist (HOME, PATH, locale, TLS trust, proxy), and the worker
  wrapper bakes only whitelisted values into agy's environment.
- **Deployment identity and snapshot binding.** The launcher writes an
  `instance.json` record (contract version, project, instance, snapshot
  fingerprint) into the state dir, and fingerprints the snapshot tree (paths,
  sizes, mtimes; one pass at launch). The server refuses to start without a
  matching record, so a bare start of the profile fails closed, two instances
  cannot share one state dir, and every job's ownership record carries the
  fingerprint: after a snapshot redeploy, old jobs and idempotency keys are
  refused instead of replayed.
- **Fail closed.** Missing bwrap, missing or non-executable pinned binaries,
  a missing snapshot, an unfingerprintable snapshot, a state dir holding a
  record for another deployment, a non-loopback listen address, a project id
  or proxy URL with characters the generated scripts cannot carry, or a
  failed nested-namespace smoke test aborts the launch. The server only opens
  its port after the worker path has answered a cold-start `--version`.
- **Pinned binaries.** agy and agy-mcp are copied into the control-plane
  stage at launch time, so a host-side upgrade cannot swap binaries under a
  running instance. An agy upgrade is a re-verification event, not a restart.

## What the unit enforces

- **Dedicated service account.** The unit runs as `agy-mcp` (provision it:
  `useradd --system --home /var/lib/agy-mcp --shell /usr/sbin/nologin agy-mcp`,
  then `chown -R agy-mcp:agy-mcp /var/lib/agy-mcp` and give the account read
  access to the snapshot). The control plane is deliberately not root: a
  worker that escaped its namespaces would otherwise read the token and the
  job store straight off the disk.
- **Kernel-enforced egress.** `IPAddressDeny=any` plus the per-instance
  drop-in's `IPAddressAllow` lines are the network boundary for the whole
  instance cgroup, worker included; proxy environment variables are agy
  configuration, not enforcement (a hook can drop them). The drop-in allows
  the instance's own dedicated loopback address (the one `PI_LISTEN_ADDR`
  names, e.g. `127.0.0.8/32`; each instance gets its own so a worker cannot
  reach another instance's endpoint), plus the egress proxy and any direct
  model endpoints. Every OTHER host loopback service is denied to the
  worker. The template allows nothing: an instance without its drop-in
  cannot even accept the bridge's connection, which is the fail-closed
  shape. Requires a systemd with cgroup BPF support; on a host where that is
  missing the settings can be silently ineffective (the unit still starts),
  which is exactly what the egress negative controls below detect: if a
  probe to an unrelated destination SUCCEEDS, the filter is not effective
  and the endpoint must not be exposed. DNS is not covered by default: use
  IP literals for the proxy.
- **Resource limits.** Memory, task, process and CPU caps apply to the whole
  instance tree. Three disk and load bounds live in the server itself: the
  supervisor caps each protected job's captured output (out and err) at
  64 MiB per stream, the instance's job store carries a disk budget
  (`AGY_MCP_STATE_BUDGET`, default 2 GiB under the profile) whose GC pass
  evicts the oldest removable terminal jobs when the store outgrows it, and
  the HTTP endpoint is bounded by an idle-session timeout, a session count,
  an in-flight cap and a request rate (profile defaults; no operator
  opt-in). The worker's only persistent writable host path is gone: its agy
  config lives on the per-job size-limited tmpfs.

## What this deployment does not prove

The mount and PID-namespace set has been smoke-tested (nested bwrap starts,
masked directories stay masked, Phase 0 T5), not deployment-verified on your
host. The checklist below is the verification. Until it passes, this
directory is a template, not a proven boundary.

## Deploy one instance

1. Create the service account and the directory tree:

       useradd --system --home /var/lib/agy-mcp --shell /usr/sbin/nologin agy-mcp
       install -d -m 700 -o agy-mcp -g agy-mcp /var/lib/agy-mcp/pi-review/{control,state,agy-home}

   Serve the snapshot from a directory the account can read (for example
   `chgrp -R agy-mcp /srv/workspaces/pi && chmod -R g+rX /srv/workspaces/pi`).

2. Provision the service identity (its own agy sign-in, never your personal
   one):

       HOME=/var/lib/agy-mcp/pi-review/agy-home /home/piagent/.local/bin/agy
       # complete the sign-in as the service user, then:

   Record the resulting config dir as `PI_AGY_CONFIG_DIR` (the `.gemini`
   inside that home). The service credential is readable by the worker by
   design: agy needs it to call the model. That residual risk is the one the
   plan calls out; record what the credential can reach, how to revoke it,
   and whether the residual risk is accepted before exposing the endpoint.

3. Copy `pi.env.example`, review every line, source it, then run the launcher
   once in the foreground to watch it pass its checks. Foreground runs are
   for verification only: production serving is the systemd unit, because the
   egress allowlist and the resource limits are unit-level and do not exist
   without it.

       . ./pi.env && ./launch-pi.sh

4. Under systemd (the usual shape):

       systemctl enable --now agy-mcp-pi@pi-review

5. Write the egress drop-in for THIS instance (the unit denies everything
   until it exists):

       /etc/systemd/system/agy-mcp-pi@pi-review.service.d/egress.conf
       [Service]
       IPAddressAllow=127.0.0.8/32
       IPAddressAllow=192.168.5.60/32      # the egress proxy, IP literal
       # plus any direct model endpoints agy talks to

   The first line MUST equal the address in `PI_LISTEN_ADDR` (dedicated per
   instance, never the shared 127.0.0.1). Then restart the unit.

6. Read the token for the client config:

       cat /var/lib/agy-mcp/pi-review/control/token

## Upgrading and redeploying

- **Snapshot content changed:** re-run the launcher against a FRESH state
  dir (move the old one aside). The launcher refuses to re-point a state dir
  whose deployment record names another snapshot, so new content is a new
  deployment: new fingerprint, new instance record, and jobs and
  idempotency keys from the previous version are not carried over (a caller
  retrying an old key gets a fresh run). Old completed results stay
  queryable in the retired state dir only by hand, never through the new
  instance.
- **State dir from an earlier build:** a state dir without `instance.json`,
  or with jobs whose ownership records predate fingerprints, is refused at
  startup by design. Move it aside and start the instance on a fresh state
  dir; do not hand-craft records.
- **agy upgrade:** pin the new `PI_AGY_BIN`, re-run the launcher, and redo
  the security checks the pinned version's behavior assumes (the Phase 0
  measurements were taken against agy 1.5.17).

## Phase 1 acceptance checklist (docs/pi-sandbox-hardening.md section 5.D)

- [ ] **Boundary**: with synthetic credentials and a test snapshot, neither
      the sandboxed client nor the worker can read host personal data, the
      control plane's private storage, or the token file; the worker's
      built-in tools, its terminal and a workspace hook all come up empty
      against canary files outside the snapshot, and a process inside the
      worker PID namespace finds no handle into the control plane through
      /proc. The agy service credential is tested separately: list what it
      can reach, how it is revoked, and whether the residual risk is
      accepted.
- [ ] **Egress**: with the unit's allowlist applied, the worker reaches the
      allowed proxy/model destinations (positive control) and a probe to an
      unrelated destination fails by direct connection, through the proxy,
      and on both IPv4 and IPv6 (negative controls). The negative-control
      list MUST include host loopback destinations other than this
      instance's own endpoint (for example 127.0.0.1:6379 and [::1]:22):
      this is what proves the dedicated-address isolation, and it doubles as
      the cgroup-BPF check. If ANY negative control succeeds, the filter is
      not effective on this host: do not expose the endpoint. Also verify a
      hook that unsets the proxy variables gets no new reach.
- [ ] **Normal calls**: the sandboxed client discovers the endpoint and gets a
      read-only analysis from `agy_run_sync`; a follow-up request restates the
      needed context and succeeds; an explicit `conversation_id` or
      `continue_latest` is refused.
- [ ] **Long task**: `agy_run_sync` returns `running` and a `job_id`; the same
      endpoint's `agy_wait` and `agy_status` deliver the final result. Record
      the client's real per-call timeout (Pi defaults to 60s; the inline wait
      cap here is 50s) and budget for cold start and the bridge; do not rely
      on progress notifications for extra time.
- [ ] **Resources and recovery**: the concurrency cap holds; timeout and
      cancel reclaim the worker tree including a setsid descendant (the PID
      namespace makes this structural; verify it anyway); the output cap
      holds against a flooding fake worker; a flood WRITE into the worker's
      agy config path fails once the tmpfs size bound is hit and the host
      disk does not grow; the state disk budget evicts the oldest terminal
      jobs when padded past it and never a running one; the HTTP guards
      reject excess sessions, in-flight requests and over-rate requests
      (429/503) while normal calls pass; restarting the service reaps
      unfinished workers and never reports an unfinished job as done
      (interrupted jobs report failed/interrupted, with the partial text
      kept); a snapshot content change under the same state dir refuses
      replays of the previous version's jobs.
- [ ] **Service identity across jobs**: run two consecutive jobs and confirm
      the second still authenticates (the per-job seeded tmpfs discards
      token refreshes; if your provider rotates refresh tokens between jobs,
      re-provision the service identity and record that in the runbook).

## Publishing the endpoint to a sandboxed client

The server binds the instance's dedicated loopback address inside the
namespace (PI_LISTEN_ADDR, for example 127.0.0.8:8765). When the client runs
in its own network namespace (a sandboxed Pi session), bridge exactly this
endpoint and nothing else, for example with socat on a host that can reach
the server:

    socat TCP-LISTEN:8765,bind=<client-facing-ip>,fork,reuseaddr \
      TCP:127.0.0.8:8765

(If the bridge host reaches the server only through the egress proxy, front
that hop in the network policy rather than widening the instance allowlist.)
Rules: the bridge must not bypass bearer auth (it cannot: it forwards the
stream, and the server rejects unauthenticated calls), must not log the
`Authorization` header, and the client-side allowlist gets exactly this
address and port, not the host's whole loopback.
