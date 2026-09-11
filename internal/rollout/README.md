# Rollout execution

The journaled engine uses the private Komizo gateway. Caddy below remains a
separately controlled shared-edge primitive, not the drain authority. The
normal per-app broker and rootd recovery path are described in
[`docs/seamless-rollouts.md`](../../docs/seamless-rollouts.md).

## Operator path

```text
komizo rollout --app APP --network APP_PRIVATE_NETWORK \
  --model /private/release.normalized.json --key-file /private/identity.key \
  --state-dir /private/rollout-state --gateway-socket /private/admin/gateway.sock \
  --compose-bin /absolute/path/docker-compose --compose-version EXACT_VERSION \
  --timeout DURATION --ready-timeout DURATION --operation-timeout DURATION \
  --stabilize DURATION --retire-timeout DURATION --poll DURATION
```

Budgets are explicit; retirement must exceed stabilization. These are operator
inputs, not approved user-visible latency defaults. `komizo-box rollout` exposes
the same engine to root only. Neither signed operations nor deploy-user grants
are expanded.

Current execution supports request/static candidates, standby workers and
overlap-compatible one-shots on one existing local bridge labeled
`io.komizo.app=APP`, canonical Compose JSON, immutable images and explicit
`x-komizo.services.SERVICE.hosts`. Persistent changes, removals, shared writable
state, implicit legacy adoption and unsupported Compose features fail closed.

The app bridge retains ordinary Docker NAT egress, as the existing Compose
control does, while candidates publish no ports and only the gateway joins the
shared edge. Docker `internal: true` is also accepted for genuinely offline
applications/tests; it is not imposed on services with outbound dependencies.
Macvlan, swarm and directly routed/unprotected bridge modes are refused. Network
ownership labels are required in both cases; "private" is not an egress-denial
claim or authority for cross-application attachments.

The engine validates candidate definitions, persists intent, creates unique
instances, verifies readiness, atomically switches admission, quiesces application
work, observes health, establishes gateway drain, seals application admission,
obtains application drain proof, verifies graceful stop, removes owned old
instances, and commits. The required generic adapter contract is documented in
[APPLICATION-LIFECYCLE.md](APPLICATION-LIFECYCLE.md). Image-declared
volumes require explicit mounts/tmpfs. Read-only data volumes must be explicitly
external. Removal cleans anonymous volumes, never named volumes.

## Journal and recovery

- Current-operator-owned private directory, regular 0600 journal/lock files.
- Cross-process OS exclusion; bounded lock acquisition, no best-effort fallback.
- Atomic same-directory replacement with file and directory fsync.
- Source/config in the private journal, never in CLI status output.
- Persisted transition checkpoints and deterministic instance names on resume.
- Key/app scope must match. Re-run the same command/model/budgets to resume;
  another release cannot displace an unfinished transaction.
- Lost switch responses are reconciled against routes, parent, generation and epoch.
- Retirement budget starts at persisted switch intent; retry does not renew it.
- **Correction (retirement follow-up):** an expired budget now retains the pending
  transaction and refuses further cleanup, rather than eventually committing with
  a violation. Over-budget work is not killed. Non-resumable indefinitely
  open sessions still require application work, not a forced-kill shortcut.

`--abort` cancels pre-switch transactions only. Supply scope, state, key, gateway,
overall timeout, operation timeout and poll; model/Compose flags are unnecessary.
Post-switch abort is refused: resume or investigate, never rewind application data.

Read sanitized status rather than printing the private journal:

```text
komizo rollout status --app APP --state-dir /private/rollout-state \
  --timeout DURATION --poll DURATION
```

Controller interruption is resumable by rootd from private profiles. Recovery
after gateway process restart and production conversion remain explicit
operations. Capacity is bounded by inbox/profile counts and per-app lock; host
resource preflight remains conservative application adoption work. Time elapsed
or unknown accounting never authorizes killing work.

## Real local control

```sh
GOTOOLCHAIN=go1.26.8 KOMIZO_TEST_ROLLOUT=1 go test -race -count=1 -timeout 5m ./internal/rollout -run TestDockerRollout -v
```

Uses the real CLI implementation, pinned standalone Compose, a compiled gateway
container, isolated networks and a compiled compliant application/adapter fixture.
The fixture accounts for real HTTP, background work and resumable streams.
Tests initial deploy,
no-op, UI-only replacement, API identity preservation, failed readiness and owned
old-container removal under concurrent requests, application refusal, TERM timeout,
restart invalidation and lost stop/removal replies. Test resources are uniquely scoped.

Before converting an app, disable/serialize legacy CD and lifecycle paths. The
legacy deploy template now refuses journaled instance labels, but that guard is
not an atomic first-conversion protocol or a replacement CI integration.

## Shared-edge Caddy primitive

`Caddy.Apply` is the first concrete routing primitive, exercised against a pinned
Caddy 2.10.2 container as well as an HTTP test double.

- Requires a caller deadline and explicit polling interval.
- Reads current config first and skips equal desired state (avoids needless reloads).
- Serializes calls on this client and respects cancellation while waiting.
- Rejects changes to the admin configuration before sending a load. A real control
  showed that an invalid app config which omits `admin` can still move the admin
  listener before rejection; assuming the old management endpoint survives was wrong.
- Treats a lost load response as ambiguous and verifies `/config/` before success.
- Uses no environment proxy or reused admin connections by default; redirects are
  not followed. An injected transport can dial an operator-private Unix socket.
- Does not expose configuration, admin response bodies or credentials in errors.

The caller must generate trusted complete configuration, authorize the action,
serialize *all* writers to a router, and persist deployment state. This local client
lock is not cross-process/host-wide serialization. Failure does not prove that the
old route is still active and never authorizes destructive container cleanup.

Application session handoff, backup/migration drivers and normal rootd/Actions
workflow integration remain separate work. Administrative listener changes need
a separate controlled operation, not an ordinary app rollout.

```sh
go test -race -count=1 -timeout 5m ./internal/rollout
```
