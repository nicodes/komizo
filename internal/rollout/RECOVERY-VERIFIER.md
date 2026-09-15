# Pinned failed-incarnation recovery verifier v1

This protocol is an exceptional, explicitly authorized recovery capability. It
does not weaken or replace the normal lifecycle protocol. In particular, a
container exit is never application quiesce, drain, graceful stop, or exit-zero
proof.

Use it only for one retained post-switch transaction where one old worker
incarnation exited nonzero before switch, the replacement is still the exact
healthy standby incarnation, and the application can durably fence every
producer while proving that no accepted work or uncertain paid outcome exists.

## Root authorization

The runtime reads exactly
`/etc/komizo/rollout-recoveries/APP.json`. The file must be an owned regular file
with mode `0600`; the remote broker cannot choose its path or any field. Unknown
fields and trailing documents are refused. Example shape (opaque values are
shortened here and must be complete in the private file):

```json
{
  "version": 1,
  "app": "example",
  "transaction": "pending-generation",
  "service": "worker",
  "old": {
    "id": "FULL_64_LOWERCASE_HEX_CONTAINER_ID",
    "started_at": "2026-01-01T00:00:00Z",
    "finished_at": "2026-01-01T01:00:00Z",
    "exit_code": 1,
    "generation": "old-generation",
    "identity": "FULL_64_LOWERCASE_HEX_IDENTITY"
  },
  "candidate": {
    "id": "FULL_64_LOWERCASE_HEX_CONTAINER_ID",
    "started_at": "2026-01-02T00:00:00Z",
    "generation": "pending-generation",
    "identity": "FULL_64_LOWERCASE_HEX_IDENTITY"
  },
  "verifier_path": "/usr/local/libexec/example/recovery-verifier",
  "verifier_sha256": "FULL_64_LOWERCASE_HEX_SHA256",
  "verifier_args": ["fixed", "arguments"],
  "uid": 1234,
  "gid": 1234,
  "overall": "8m",
  "retire": "5m"
}
```

The verifier must be a nonempty owned regular executable, no larger than 64
MiB, have no owner/group/other write bit, and be executable by the fixed
unprivileged identity. UID and GID must be nonzero. Komizo
opens it once, compares the already-open file's SHA-256, rewinds it, and executes
`/proc/self/fd/3` under the fixed UID/GID. It performs no second pathname
resolution, shell expansion, supplemental-group inheritance, or root environment
inheritance. Environment is exactly `HOME=/nonexistent`, `LANG=C`, and
`PATH=/usr/bin:/bin`; stderr is discarded and stdout is protocol-only. The
fixed arguments are part of the mode-0600 authorization, never caller input.

Authorization `overall` must match the installed profile and cannot exceed 8
minutes. `retire` must match the profile, exceed stabilization, and cannot exceed
5 minutes. All other profile and pending-transaction limits remain unchanged.

## Session protocol

Komizo writes one JSON line, at most 4096 bytes:

```json
{
  "version": 1,
  "nonce": "fresh-opaque-nonce",
  "app": "example",
  "transaction": "pending-generation",
  "service": "worker",
  "old": {"...": "the exact authorization pin"},
  "candidate": {"...": "the exact authorization pin"},
  "deadline_unix_ms": 0,
  "overall_deadline_unix_ms": 0,
  "already_activated": false
}
```

Before replying when `already_activated` is false, the verifier must:

1. Validate every challenge field against its own fixed application scope.
2. Establish a **durable producer fence** that every API/background producer
   must obey. A connection-scoped lock alone is insufficient because process or
   pipe failure must leave admissions blocked.
3. Under the application's queue/database/filesystem locks, prove there are zero
   accepted jobs, live or expired leases, attempts, provider request IDs,
   uncertain paid outcomes, compensation/reconciliation items, checkpoints,
   result files, and malformed job entries.
4. Keep the durable fence active and write exactly:

```text
komizo-recovery-verifier-v1 fenced-empty NONCE
```

No other stdout is allowed. The process remains alive. Komizo then repeats
container, route, epoch, and old-generation request checks, durably records a
distinct recovery proof, positively activates the exact standby candidate, and
durably records activation.

Only then Komizo writes:

```text
release NONCE
```

The verifier atomically transitions the durable fence to the positively
activated generation and writes exactly:

```text
komizo-recovery-verifier-v1 released NONCE
```

It must then close stdout and exit zero without further output. Release is
idempotent. If a release acknowledgement was received but its journal write was
interrupted, the next challenge has `already_activated: true`; the verifier may
report an already-completed durable transition with exactly:

```text
komizo-recovery-verifier-v1 activated NONCE
```

It must still accept `release NONCE` idempotently and return the exact `released`
line. This state is legal only after Komizo has already persisted activation.

EOF, crash, timeout, malformed/extra output, nonzero exit, nonempty state, or a
lost application lock must preserve the durable admission fence. It must never
queue, retry, reconcile, compensate, restore, or submit provider work. Komizo
kills only this verifier helper after an incomplete protocol; that must not
remove its durable fence.

## Platform checks and journal semantics

Before and after `fenced-empty`, Komizo independently requires:

- exact old and candidate IDs, start timestamps, generations, identities, and
  ownership labels;
- old status exited/nonzero, restart policy `no`, restart count zero, and no
  running/restarting/dead/OOM state;
- old finish strictly before durable switch start;
- candidate running, restart policy `no`, restart count zero, exactly one
  `KOMIZO_CANDIDATE=standby` environment entry, and a positive application
  standby acknowledgement repeated before and after the producer fence;
- live gateway config exactly `pending.after` at the persisted epoch;
- old generation inactive with zero requests.

The first invocation persists absolute overall and retirement deadlines before
preflight or verifier execution. Retry uses those timestamps and the exact
authorization digest; it never renews either budget. Expiry is durable and
terminal. Ordinary resume refuses a transaction in verified-recovery phase.

After release, stabilization starts at the recorded recovered activation time.
Other changed services retain their normal positive lifecycle proofs and finish
normal retirement under the fresh bounded recovery deadline. The failed old
worker is removed non-forcibly by exact ID only after reinspection and the
distinct proof; absence after an interrupted authorized removal is idempotent.
Its record never claims normal quiesce, seal, drain, stop, or exit zero.

The only remote caller operation is:

```sh
ssh DEPLOY_USER@HOST doas /usr/local/bin/rollout-APP --recover </dev/null
```

It accepts no additional argument or stdin. The broker must positively acquire
the existing application deployment lock within its fixed 20-second recovery
wait; the runtime also holds the private
rollout journal lock. Installing an authorization/verifier, taking a fresh
application backup, and executing this command are separate owner operations.
