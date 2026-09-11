# Uninterrupted operations: Komizo core plan

Status: draft implementation checkpoint, not merge-ready or production-verified.

## Product boundary

Komizo operates containerized applications on owned servers. It is opinionated
about safe lifecycle execution, not application languages, frameworks or databases.
Keep Compose definitions with small `x-komizo` lifecycle extensions. Coordinate
declared capabilities rather than guessing application behavior or requiring an SDK.

Separate responsibilities:

- Komizo: service identity, guarded rollout, routing, state, recovery and evidence.
- Applications: readiness meaning, safe retries, durable jobs, session resumption,
  schema compatibility and meaningful post-restore validation.
- Database integrations: consistent backups, supported migration/upgrade methods
  and explicit recovery semantics. No mandatory database engine for hosted apps.

The goal is no user-visible disruption during supported routine operations, with
bounded retirement of superseded instances. Physical reconnection is acceptable
only if user work is preserved without intervention. Host-failure availability is
outside this work's scope. No arbitrary-container zero-interruption guarantee.

## Implemented locally

### Approved retirement contract follow-up

The owner approved requiring both gateway and application proof, with two phases:

1. After gateway admission switches, ask the old application to stop new background
   work and end resumable streams, while continuing to accept requests already
   admitted by the gateway.
2. After positive gateway drain, seal application admission and obtain positive
   application drain evidence before graceful stop and removal.

Timeout preserves the old instance and reports incomplete retirement. It must not
force-remove the instance or report policy-compliant success. Keep the existing
root-only permission boundary. This is design approval, not deployment authority.

**Correction (application retirement implementation):** the prior checkpoint's
old-instance-cleanup failure is now addressed by a declared application adapter,
durable per-incarnation lifecycle checkpoints and TERM-only graceful stop before
non-forced removal. The parent-owned refusal of unsafe container states is retained.
The real Docker control now uses an application fixture with actual work accounting,
not a Caddy response as application proof. Exact contract and integration limits:
`internal/rollout/APPLICATION-LIFECYCLE.md`. Local synthetic verification does not
establish consumer or production readiness. PR #113 remains draft; no merge or
deployment is authorized by this follow-up.

- `internal/release`: deterministic comparison of complete service identities;
  canonical Compose JSON resolution; immutable image identities; private keyed
  configuration identities; per-service secret versions and dependency invalidation.
- `komizo plan`: local, read-only analysis without exposing configuration values.
- `internal/gateway`: app-private HTTP/upgrade routing with atomic generation
  admission, parent-generation CAS, retained request accounting and a private Unix
  administration socket. Shared TLS Caddy remains outside ordinary app switches.
- `internal/rollout`: private fsynced journal, OS locking, deterministic candidate
  identities, readiness, switch/readback, stabilization, positive drain evidence,
  scoped retirement, resume, pre-switch abort and sanitized status.
- Operator-only `komizo rollout` and root-only `komizo-box rollout`; no expansion
  of signed-command allowlists or deploy-account privilege grants.
- Explicit readiness Host and concurrent external-volume declarations. Declarations
  are not proof of application concurrency or recovery behavior.
- Legacy deploy refusal when journaled instances exist. This is a guard, not an
  atomic migration from legacy deployment ownership.

See `internal/release/README.md`, `internal/gateway/README.md` and
`internal/rollout/README.md` for supported input shapes and limitations.

## Source and test qualification

2026-09-09 integration update: the merge of `eefb5ea` was verified before commit with
`make check` with Go 1.26.8 and ShellCheck 0.11.0, including the current-main
cross-build/cross-vet matrix (Plan 9 included). The gateway's connection-refused
check now lives behind its existing platform boundary; a focused test requires
positive refusal evidence and rejects permission, missing-file and timeout errors.
The uncached full race suite passed with `KOMIZO_TEST_ROLLOUT=1`,
`KOMIZO_TEST_COMPOSE=1`, `KOMIZO_TEST_CADDY=1` and
`KOMIZO_REQUIRE_SHELLCHECK=1`. The added test subsequently passed the race check
and full gate. The gate emitted a `/dev/stderr` warning in its formatting pipeline;
an independent repository-wide `test -z "$(gofmt -l .)"` passed.
These results describe the local merged working tree, not a published merge
commit, installed host, or production acceptance.

The initial implementation was built on local commit `e40136e`. PR preparation
found current main at `eefb5ea`, 29 commits ahead. That snapshot is now integrated;
the remaining completion gates below still apply. Earlier local tests do
not establish compatibility with current main or installed host versions.

Controls executed against the checkpoint included Go 1.26.8, ShellCheck 0.11.0,
Compose 2.39.2 and Caddy 2.10.2. These are test versions, not automatically selected
production deployment pins. Commands included:

```sh
GOTOOLCHAIN=go1.26.8 KOMIZO_TEST_ROLLOUT=1 KOMIZO_TEST_COMPOSE=1 KOMIZO_TEST_CADDY=1 make check
GOTOOLCHAIN=go1.26.8 KOMIZO_TEST_ROLLOUT=1 KOMIZO_TEST_COMPOSE=1 KOMIZO_TEST_CADDY=1 KOMIZO_REQUIRE_SHELLCHECK=1 go test -race -count=1 -timeout 5m ./...
GOTOOLCHAIN=go1.26.8 go vet ./...
GOTOOLCHAIN=go1.26.8 GOOS=darwin go build ./...
gofmt -l .
git diff --check
```

Real synthetic Docker controls cover initial HTTP rollout, no-op, selective service
replacement, failed readiness, old-instance cleanup and pre-switch abort. Unit
controls cover interrupted preparation, ambiguous switch responses, unknown drain,
retirement failures, exceeded budgets, ownership and private status output.

All controls are local and synthetic. No production workload, data conversion,
provider billing or universal application continuity claim follows from them.
The existing make formatting pipeline emitted a `/dev/stderr` environment warning;
direct formatting verification was run separately.

## Remaining core work and acceptance gates

- [ ] Integrate current main, preserving existing lifecycle/security/CI behavior.
- [ ] Complete trusted artifact generation and host-side secret version/materialization.
- [ ] Complete normal deploy-account/Actions integration without widening privileges.
- [ ] Complete automatic rootd reconciliation and sanitized management status.
- [ ] Implement a deliberate legacy-to-journaled ownership transition and lifecycle
      controls; prevent concurrent legacy and new executors during conversion.
- [ ] Establish capacity policy, request/session budgets and supported operation classes.
- [ ] Complete backup, migration and upgrade integrations with application-specific
      contracts rather than universal filesystem copies or automatic DB restore.
- [ ] Run consumer integration against representative app/database workloads.
- [ ] Approve measured latency, drain/retirement and recovery thresholds.
- [ ] Write and verify cutover/runbook steps; actual deployment remains separately gated.

Applications' implementation details and migration decisions are tracked in private
companion work, not copied into this public plan.

## Safety invariants

1. Validate complete desired state before starting candidates; unresolved input is
   not a proven no-op. Replace only changed, eligible services.
2. Do not start overlapping state writers without an explicitly supported integration.
3. Prepare and check candidates before switching admission. Preserve old work until
   positive drain evidence or application-supported resumption exists.
4. Persist switch intent and do not renew retirement budgets on retries.
5. An unknown generation, gateway epoch change or elapsed deadline is not proof
   of drain. Record violations and refuse unsafe cleanup rather than killing work.
6. Never restore old data automatically because an application health check failed.
7. Keep journals/keys private and out of gateway mounts and public logs.
8. Coordinate all writers to a routing/deployment scope; local locks alone are not
   authority over unrelated operators or legacy tools.

Code and tests do not yet complete this plan. Draft PRs must remain explicit about
untested scope, integration conflicts and unmet application-level requirements.
