# Release change analysis

Local CLI and internal foundation of `UNINTERRUPTED-OPERATIONS-PLAN.md`.

`Compare` accepts two complete, already-resolved service inventories. It returns
all services in sorted order, with `added`, `removed`, `changed` or `unchanged`
membership/equality results. Changed results identify image/runtime/secret-version/
dependency categories, never their values. It validates both inventories before
returning anything; unresolved input is an error, not a proven no-op.

`Resolve` now consumes canonical Compose JSON with `x-komizo` version 1. It checks
immutable `@sha256:` references or local `sha256:` image IDs, hashes only content identity (not tags
or registry mirror names), and derives keyed runtime/resource/secret-version and
explicit dependency identities. `komizo plan` invokes this resolver and comparator.

Local image-config IDs are distinguished from registry manifest digests; identical
hex strings in different image namespaces are not assumed equivalent.
It does not execute Docker, write state, or perform a rollout. `changed` is not
permission to give a database a second writer.

`Compare` can also accept internal equality tokens directly. A nonempty token alone
cannot prove completeness. The resolver and secret-version authority must establish
it; the comparator never invents it. Explicit known-empty tokens differ from
unresolved fields. Key rotation and cross-key persisted inventories require care:
both sides must be resolved with the same private key.

## Input and privacy boundary

Use a private random 32-byte key file (permissions 0600) and protect normalized
model files: effective environment/configuration can be sensitive. The key is never
printed. Runtime equality uses HMAC-SHA256 so output identities are not public
dictionary-testable hashes of guessable secrets. This is not encryption of the
source configuration and not a secure-memory-erasure guarantee.

The CLI accepts JSON already rendered by Compose, not YAML. An isolated control
uses Compose 2.39.2, `config --format json --no-interpolate --no-env-resolution`.
Those flags are not secret redaction. Current local `docker compose` reports `dev`;
do not treat it as the pinned compatibility control.

`x-komizo` has these fields:

- `version: 1`.
- `services`: exactly the active service names, each with `mode` (`http`,
  `persistent`, or `job`). HTTP requires `port`, a local `ready_path` without a
  query, and `candidate_safe: true`. The declaration is not behavioral proof.
- HTTP execution additionally requires explicit `hosts` for private gateway
  routing. Analysis alone does not require a public route for every service.
  Candidate generation uses unique service/container names and only that service's
  resource grants; it does not reuse its original DNS alias beside an old instance.
- Optional per-service `restart_on`: explicit dependency invalidations, acyclic.
  Ordinary dependency image changes do not implicitly restart all consumers.
- Optional `secret_versions`: opaque operator-supplied versions for exactly the
  service-granted Compose secrets. No secret bytes or public secret hashes.

HTTP overlap constraints reject fixed container/network identities, published
ports, privileged mode and unsupported writable mounts. Persistent/job services
are classified, not automatically executed. Referenced network/volume/config
definitions affect identity; unused definitions do not. Named volume content is
mutable application state, not an automatically versioned deployment artifact.

Unresolved tags, interpolation (including dollar-bearing expressions), environment
files/inherited null environment values, build instructions, profiles, external
config contents and bind mounts fail closed. Inline resolved config contents are
supported. Secret file contents are not read: trusted operator version metadata
must agree with the files actually materialized by a future executor. Unknown
lifecycle fields and duplicate JSON keys are rejected rather than silently ignored.

This subset does not yet accept every existing app manifest. A resolver extension
needs focused tests before relaxing any unsupported-input guard. Compose's empty
network attachment `null` is normalized to an empty object, specifically; null
environment values remain unresolved and are rejected.

Run focused checks with the module's Go 1.26 toolchain:

```sh
go test -race -count=1 -timeout 5m ./internal/release
go vet ./internal/release
```

Ordinary comparison/resolver tests are synthetic. Optional real controls:

```sh
KOMIZO_TEST_COMPOSE=1 go test -race -count=1 -timeout 5m ./internal/release -run TestPinnedComposeNormalization -v
KOMIZO_TEST_CADDY=1 go test -race -count=3 -timeout 5m ./internal/release -run TestPinnedCaddySwitchAndHTTPDrain -v
```

These require the local Unix Docker socket, approved image access and available
resources. They use pinned image digests in the test source. Compose normalization
has no network/socket inside its container and no host mounts. The Caddy control
creates uniquely labeled test networks/containers, publishes proxy ports only on
host loopback, mounts only synthetic config, and removes its own resources afterward.
It builds a temporary synthetic HTTP service image, never an application image.

The Caddy control tests a failed config load, successful traffic switch, completion
of an old in-flight HTTP stream, and old-container retirement. Its concurrent
baseline/load timings are observations, not approved product thresholds. It does
not exercise DB writes, backups, WebSocket resumption or a production rollout engine.
