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
  control-plane mounts. The worker's namespace is also a PID namespace: from
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
- **Kernel-enforced egress.** `IPAddressDeny=any` plus `IPAddressAllow`
  lines are the network boundary for the whole instance cgroup, worker
  included; proxy environment variables are agy configuration, not
  enforcement (a hook can drop them). Allow loopback (the host-side bridge
  needs it to reach the endpoint) plus your egress proxy and any direct
  model endpoints; out of the box the instance has no external egress at
  all, and a job that needs the model fails fast until you allow its route.
  Requires a systemd with cgroup BPF support; without it the unit fails to
  start rather than serving unfiltered. DNS is not covered by default: use
  IP literals for the proxy.
- **Resource limits.** Memory, task, process and CPU caps apply to the whole
  instance tree. The supervisor additionally caps each protected job's
  captured output (out and err) at 64 MiB per stream, so a stuck or flooding
  worker cannot fill the control plane's disk.

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

5. Read the token for the client config:

       cat /var/lib/agy-mcp/pi-review/control/token

## Upgrading and redeploying

- **Snapshot content changed:** re-run the launcher. The new fingerprint
  becomes the deployment's snapshot version; jobs and idempotency keys from
  the previous version are refused (a caller retries with the same key and
  gets a fresh run), which is the contract: new content is a new deployment.
  If you intend the old jobs to stay queryable, give the new deployment a
  fresh state dir instead of re-pointing the old one.
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
      and on both IPv4 and IPv6 (negative controls). Also verify a hook that
      unsets the proxy variables gets no new reach.
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
      holds against a flooding fake worker; restarting the service reaps
      unfinished workers and never reports an unfinished job as done
      (interrupted jobs report failed/interrupted, with the partial text
      kept); a snapshot content change under the same state dir refuses
      replays of the previous version's jobs.

## Publishing the endpoint to a sandboxed client

The server binds loopback inside the namespace. When the client runs in its
own network namespace (a sandboxed Pi session), bridge exactly this endpoint
and nothing else, for example with socat on the host:

    socat TCP-LISTEN:8765,bind=<client-facing-ip>,fork,reuseaddr \
      PROXY:<control-plane-host>,proxyport=3128,proxyauth=...

Rules: the bridge must not bypass bearer auth (it cannot: it forwards the
stream, and the server rejects unauthenticated calls), must not log the
`Authorization` header, and the client-side allowlist gets exactly this
address and port, not the host's whole loopback.
