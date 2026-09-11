# Application retirement protocol v1

This is a generic application capability, not a guarantee for arbitrary images.
No language SDK is required. Each image supplies an adapter that communicates
with its real application process. A script that merely prints acknowledgements
is **not compliant**, even if it makes the executor return success.

## Declaration and invocation

Add to the existing `x-komizo.services.SERVICE` HTTP policy:

```json
"lifecycle": {"version": 1, "command": ["/app", "lifecycle"]}
```

The command is ordered argv, with an absolute executable path inside the image.
No shell expansion is performed. The declaration is included in the service's
keyed immutable runtime identity and persisted with each instance. The engine
requires it for candidates and old instances before preparing a replacement.
Legacy instances lacking it require explicit operator conversion; adding a new
declaration does not retroactively prove an old image implements it.

The local root-only Docker executor invokes, as the container's configured user:

```text
docker exec CONTAINER_ID /app lifecycle ACTION NONCE GENERATION IDENTITY DEADLINE_UNIX_MS
```

`ACTION` is `quiesce`, `seal`, or `drain`. `NONCE` is a fresh opaque token per
attempt, not a secret. Generation and identity are the instance's journaled
values, not the replacement's. The deadline is an absolute Unix timestamp in
milliseconds, bounded by the caller, operation budget and (after switch) original
retirement deadline. The adapter must enforce this deadline itself: terminating
the Docker CLI does not guarantee termination of the in-container exec process.

Only after the requested application state is positively established, exit 0
and write exactly this single UTF-8/ASCII line to stdout, including its newline:

```text
komizo-lifecycle-v1 ACTION NONCE
```

No banners, other stdout, alternative versions or inferred success are accepted.
Nonzero exit, missing/mismatched acknowledgement, daemon error or timeout is
incomplete retirement. Executor errors omit application output. Adapter diagnostics
may use stderr, but must not publish credentials or private configuration.

## Required semantics

All actions are monotonic, idempotent and safe to repeat after a lost response.
The nonce correlates a response; it is not an idempotency key and must not cause
repeated actions to re-open admission. Multiple outstanding attempts must be safe.

1. **Quiesce**, immediately after confirmed gateway admission flip and before
   stabilization/drain: stop admitting new scheduled/background work and initiate
   ending resumable streams with valid application-specific resumption state.
   Already accepted jobs may finish. **Continue admitting HTTP requests that the
   gateway already admitted but has not yet delivered.** Do not close the request
   listener or globally seal it at this stage. Reply once quiescing is established;
   do not wait for all HTTP requests/streams to drain before initiating their end.
2. After positive gateway drain, **seal**: atomically refuse all new application
   work, including HTTP, background jobs and other independent ingress. Synchronize
   admission and work accounting so nothing can start between zero observation and
   admission closure. Acknowledgement means the seal is established, not drained.
3. **Drain**: wait until all accepted work is complete or safely resumable, all
   streams are ended, all detached tasks and background jobs are accounted for,
   and required writes/transactions are finished. Only acknowledge this positive,
   application-owned proof. Zero gateway requests is not this proof.
4. The executor sends **SIGTERM**, never a timed `docker stop` with a SIGKILL
   fallback. The application's PID 1 must handle/forward TERM, finish shutdown and
   exit **0**. Inspect must confirm the same container ID/start time, exited state,
   zero exit code and no OOM/dead/restarting state. Only then is non-forced
   `docker rm --volumes CONTAINER_ID` permitted. Named volumes are not removed.

The application owns durable stream cursors, transaction completion and background
work correctness. An adapter may use a private Unix socket, pipe or equivalent
local mechanism; it must communicate with the actual serving process. Do not
expose unauthenticated lifecycle commands on the public HTTP listener or give
containers Docker sockets/new host privileges. The test fixture uses a local Unix
socket and actual HTTP/background/stream accounting.

## Recovery and supported boundaries

- Per-instance journal stages: quiesce, seal, drain, stop, remove. Acknowledgements
  bind to Docker ID and `State.StartedAt`; restart/replacement invalidates proof.
  Completed stages are not repeated; an unrecorded reply is retried. Lost stop and
  removal replies are reconciled by inspection without reopening application work.
- Pre-switch candidate abort uses the same lifecycle because candidates can run
  background work. Confirmed absent, never-prepared candidates need no application
  proof. Unexpected disappearance after a positive acknowledgement fails closed.
  A created-but-never-started candidate has a distinct journal proof, rechecked at
  each step: no application process has run, so it needs no application handshake
  or TERM. It is never started just to clean it up. Appearance/start after either
  absent/never-started proof refuses cleanup.
- Retirement deadline starts at durable gateway switch intent, includes all phases
  and never renews on resume. Expiration records `retirement_exceeded`, retains the
  pending transaction and remaining instances, and refuses further retirement.
  Already completed removals are not undone. There is no automatic budget reset,
  forced cleanup or late policy-compliant success. An interrupted operation can
  resume with the same model/policy **only while its original budget remains**.
- An operation deadline can interrupt work before the total retirement deadline;
  proof/checkpoints remain available for retry. Abort is separately bounded by its
  explicit caller/operation deadlines and does not switch routes.
- Automatic container restart policies are rejected (`restart: no`, or omitted).
  Independent Docker/legacy deploy writers must be disabled/serialized for owned
  instances. Docker has no atomic compare-start-time-and-signal API: inspection
  and immutable-ID addressing detect observed races but cannot prevent a privileged
  external writer restarting that same ID between inspection and TERM. The journal
  lock is not a daemon-wide lock against root. No such guarantee is claimed.
- Gateway epoch/route changes refuse retirement, including resumed destructive
  stages. Gateway restart reconciliation, production adoption, operational budget
  recovery, application session protocols and normal CD remain separate integrations.

These constraints are not deployment authority or cross-application readiness.
Each consumer must test real transactions, background jobs, delayed admitted
requests, resumable streams, aborts and shutdown under its own workload and approved
timing policy before adoption.
