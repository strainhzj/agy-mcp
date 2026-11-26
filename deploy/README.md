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
| `launch-pi.sh` | the controlled launcher: checks preconditions, generates the instance id and bearer token once, stages the pinned binaries, assembles the outer (control plane) and inner (worker) bubblewrap namespaces, runs the cold-start worker check, then execs the server |
| `pi.env.example` | the launcher's configuration, commented; copy, review every line, source it |
| `agy-mcp-pi@.service` | systemd template unit hosting one instance per project |

## What the launcher enforces

- **Two mount boundaries.** The control plane (server plus supervisor) sees
  the read-only snapshot, its own state dir, the staged binaries and nothing
  else of the host: personal directories (`~/.gemini`, `~/.ssh`, `~/.gnupg`,
  `~/.aws`, `~/.config`, `~/.pi`) are not bound anywhere. The worker (agy and
  everything it spawns, hooks included) sees less: the snapshot, minimal
  system files, a private HOME and /tmp, and no control-plane mounts.
- **Token hygiene.** The bearer token is generated once (0600, control dir),
  read by the server from a file inside the namespace, and never appears in
  an argv. agy-mcp itself strips `AGY_MCP_*` from every child environment,
  and the worker wrapper rebuilds agy's environment from a whitelist before
  the inner namespace starts, so a workspace hook (MEASURED to run outside
  agy's sandbox, agy 1.5.17) cannot read the token.
- **Fail closed.** Missing bwrap, missing or non-executable pinned binaries,
  a missing snapshot, a non-loopback listen address, or a failed nested-namespace
  smoke test aborts the launch. The server only opens its port after the
  worker path has answered a cold-start `--version`.
- **Pinned binaries.** agy and agy-mcp are copied into the control-plane
  stage at launch time, so a host-side upgrade cannot swap binaries under a
  running instance. An agy upgrade is a re-verification event, not a restart.

## What the launcher does not prove

The mount set has been smoke-tested (nested bwrap starts, one masked
directory stays masked, Phase 0 T5), not deployment-verified. The checklist
below is the verification. Until it passes on your host, this directory is a
template, not a proven boundary.

## Deploy one instance

1. Create the snapshot and the state and control dirs:

       install -d -m 700 /var/lib/agy-mcp/pi-review/{control,state,agy-home}
       PI_SNAPSHOT_DIR=/srv/workspaces/pi   # your read-only snapshot

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
   once in the foreground to watch it pass its checks:

       . ./pi.env && ./launch-pi.sh

4. Under systemd (the usual shape):

       systemctl enable --now agy-mcp-pi@pi-review

5. Read the token for the client config:

       cat /var/lib/agy-mcp/pi-review/control/token

## Phase 1 acceptance checklist (docs/pi-sandbox-hardening.md section 5.D)

- [ ] **Boundary**: with synthetic credentials and a test snapshot, neither
      the sandboxed client nor the worker can read host personal data, the
      control plane's private storage, or the token file; the worker's built-in
      tools, its terminal and a workspace hook all come up empty against
      canary files outside the snapshot. The agy service credential is tested
      separately: list what it can reach, how it is revoked, and whether the
      residual risk is accepted.
- [ ] **Egress**: the worker reaches only the model endpoints (through
      `PI_PROXY_URL` when set); a probe to an unrelated destination fails.
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
      cancel reclaim the worker tree; restarting the service reaps unfinished
      workers and never reports an unfinished job as done.

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
