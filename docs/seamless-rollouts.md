# Portable journaled rollouts

Komizo deploys OCI/Compose applications without an application SDK. A release
publishes canonical Compose JSON containing immutable image digests and a small
`x-komizo` declaration. The normal deploy action packages that model in an
immutable config artifact. On the host, the dedicated per-app `doas
rollout-APP` command is the only CI authority: it extracts the digest-pinned
artifact and invokes the journaled engine using a private root-owned profile.
Rootd resumes an interrupted transaction from the same journal; it does not
accept a new generic remote command.

## Lifecycle categories

- `request`: replaceable HTTP/API service. Requires private readiness, explicit
  host routes, candidate overlap safety and the retirement adapter.
- `static`: a replaceable HTTP static/frontend server. It has the same positive
  readiness and retirement obligations as any request process; “static” is not
  permission to kill an in-flight download.
- `worker`: starts with `KOMIZO_CANDIDATE=standby`. Its adapter must positively
  acknowledge `ready` while admitting no work. After gateway switch and old
  worker quiesce it acknowledges monotonic `activate`. Retirement then uses the
  same `seal`, `drain`, TERM, exit-zero and non-forced removal proof.
- `one-shot`: an overlap-compatible migration/task. `candidate_safe: true` is
  explicit. The engine journals its unique container, requires exited/zero
  proof, removes it non-forcibly, and never reruns it after commit. Failed or
  unknown completion stalls for operator reconciliation.
- `persistent`: stable state service. It remains in inventory, but bootstrap,
  replacement and removal are refused in seamless mode and require explicit
  maintenance. Application databases are not a Komizo requirement.

Every replaceable long-running image supplies lifecycle argv, for example:

```json
{"version": 1, "command": ["/app", "lifecycle"]}
```

The full nonce/incarnation-bound protocol is in
[`internal/rollout/APPLICATION-LIFECYCLE.md`](../internal/rollout/APPLICATION-LIFECYCLE.md).

## Host profile and boundaries

Profiles live as private, root-owned regular JSON files in
`/etc/komizo/rollouts`. CI cannot choose any profile value. The initial defaults
below were approved from an isolated constrained-host control where 3-second
operations safely stalled and resumed. These are safety budgets/capacity floors,
not a user-visible latency SLO; tune them from app-specific evidence when
required.

```json
{
  "version": 1,
  "app": "example",
  "network": "example_private",
  "key_file": "/etc/komizo/rollout-keys/example.key",
  "state_dir": "/var/lib/komizo/rollouts/example",
  "gateway_socket": "/run/komizo/gateways/example/admin.sock",
  "gateway_config": "/var/lib/komizo/rollouts/example/gateway/config.json",
  "compose_binary": "/usr/libexec/docker/cli-plugins/docker-compose",
  "compose_version": "EXACT_INSTALLED_VERSION",
  "secret_file": "/srv/example/secrets.env",
  "overall": "120s",
  "min_free_memory_bytes": 134217728,
  "min_free_disk_bytes": 1073741824,
  "limits": {
    "Ready": "15s",
    "Stabilize": "2s",
    "Retire": "60s",
    "Operation": "15s",
    "Poll": "100ms"
  }
}
```

Both capacity values are required. Deployment refuses if Linux `MemAvailable`
or filesystem available bytes are below them, or if either measurement is
unknown. They are conservative initial floors, not a guarantee that every image
or application can safely overlap within the remaining capacity.

The identity key is 32 random bytes, mode `0600`. The profile directory must
not be group/other writable. The app-private local bridge is explicitly labeled
`io.komizo.app=APP`; directly routed/unprotected networks are refused. The
stable gateway runs separately from candidates, loads its desired routes from
durable storage, and exposes administration only through its private Unix
socket. Its container needs only the mounted static `komizo-box` binary/state,
the app bridge, and `CAP_NET_BIND_SERVICE` when retaining the conventional
`APP-gate:80` endpoint; it needs no Docker socket or app secrets.

The model may use only exact, same-name environment indirection such as
`TOKEN: ${TOKEN}` for host secrets. Model-selected secret file paths and partial
interpolation are refused. `set-secret-APP` atomically writes each value together
with a fresh opaque version marker to the profile-fixed environment file while
holding the deployment/journal locks. The broker replaces artifact version
claims with exactly those host markers and passes the fixed file to Compose via
`--env-file`. Secret bytes never enter the model, journal, status output or log.

## Workflow

```yaml
- uses: nicodes/komizo-actions/deploy@EXACT_SHA
  with:
    version: ${{ github.sha }}
    app: example
    config-compose: deploy/compose.yml
    rollout-model: deploy/model.json
    config-image: ghcr.io/example/example-config
```

`publish-config` returns the registry manifest digest. `activate` passes that
digest to the fixed broker, which refuses a model delivered only by mutable tag.
Legacy config remains supported for applications not converted, but once native
instances exist an artifact without `model.json` is refused rather than allowing
Compose `--remove-orphans` to become a second writer.

## Recovery and refusal

- Per-app OS lock and private fsynced journal serialize Actions, rootd resume and
  operators. Lock timeout is a refusal, never best-effort execution.
- Rootd scans at a bounded flat depth/count and resumes only pending intent from
  a valid private profile. A new release cannot displace it.
- Unknown gateway state/epoch, readiness, one-shot completion, application
  acknowledgement, incarnation or exit status is not proof and preserves the
  transaction/resources.
- Request/static retirement requires gateway drain, then application seal and
  drain. Worker retirement additionally requires standby/activation handoff.
- Only SIGTERM is sent. No timeout authorizes SIGKILL or forced removal.
- Persistent changes, service removal and legacy adoption require a separate
  explicit operation; seamless mode does not improvise maintenance.

Shared releases are immutable and opt-in. `komizo` release publication and
`komizo-actions` release publication are manual workflow dispatches; neither
updates hosts or consumer pins. `komizo update` is also operator-invoked. A
public release therefore does not authorize installation on any host.
