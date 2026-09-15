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
`/etc/komizo/rollouts`. CI cannot choose any profile value. The values below are
an experimental fixture profile, not approved application defaults or a
user-visible latency SLO. A constrained-host control showed that 3-second
operations could safely stall and resume; it did not establish production
limits. Operators must select every value from application- and host-specific
evidence.

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

Both capacity values are required. Deployment measures Linux `MemAvailable`
and filesystem available bytes before staging, journals and pulls/unpacks every
declared immutable candidate image without creating a candidate, then measures
both floors again. A failed/unknown post-pull measurement retains the transaction
before candidate creation; resume repeats staging idempotently and rechecks.
Candidate creation uses Compose `--pull never`, so it cannot consume an
unstaged image after the gate. This is a postfactum refusal, not continuously
reserved headroom: pull/unpack may transiently cross a floor, and no filesystem
quota or memory reservation is implied. The displayed 128 MiB/1 GiB values were
used only by the fixture; they are neither approved floors nor a guarantee that
an image or application can safely overlap within the remaining capacity.

The identity key is 32 random bytes, mode `0600`. The profile directory must
not be group/other writable. The app-private local bridge is explicitly labeled
`io.komizo.app=APP`; directly routed/unprotected networks are refused. The
stable gateway runs separately from candidates, loads its desired routes from
durable storage, and exposes administration only through its private Unix
socket. Its container needs only the mounted static `komizo-box` binary/state,
the app bridge, and `CAP_NET_BIND_SERVICE` when retaining the conventional
`APP-gate:80` endpoint; it needs no Docker socket or app secrets.

### Scoped operator provisioning

Run a current checksum/provenance-verified immutable Komizo CLI release. It
carries the matching `komizo-box` and installs that runtime only under
`/usr/local/libexec/komizo/rollouts/APP`; it does not replace the host-wide
agent, restart shared services or require a global `komizo update`. Then it
prepares only the existing app's broker, without selecting policy or changing application
containers, routes, Compose files, environment contents, ownership or traffic:

```sh
komizo rollout provision --host root@HOST --app APP
```

The command reads the app's existing Komizo record, refuses unless its directory
is already root-owned mode `0750` and `compose.yml`, `.env`, and `secrets.env`
are already root-owned mode `0600`, snapshots file ownership/content and Compose
container identities, authenticates and atomically installs the app-scoped
runtime, refreshes only that app's generated broker/rules, and
requires an identical post-refresh snapshot. Omitting `--profile` is deliberate:
it installs no timing/capacity policy, key, state or gateway.

After target-host and application measurements, the application owner supplies a
private mode-`0600` profile with every field in the schema above and separately
authorizes its numeric values. The operator may then run:

```sh
komizo rollout provision --host root@HOST --app APP --profile ./APP-rollout.json
```

This creates only fixed app-scoped authority paths: the profile under
`/etc/komizo/rollouts`, a random 32-byte identity key under
`/etc/komizo/rollout-keys`, private journal/gateway configuration under
`/var/lib/komizo/rollouts/APP`, and a private socket directory under
`/run/komizo/gateways/APP`. It refuses to replace a differing installed profile;
changing policy requires a separate explicit owner decision. It does not start a
gateway or cut traffic. The app owner must configure/supervise the gateway,
verify the broker's full readiness check, serialize legacy CD, and authorize the
first cutover.

The Actions capability probe validates the complete profile, key, configured
capacity floor, exact Compose version, app-labeled private network and live
gateway socket before artifact publication or secret rotation. A broker filename
alone is not readiness.

If a journaled transaction is pending, the existing app deploy identity may
request only its authoritative continuation:

```sh
ssh DEPLOY_USER@HOST doas /usr/local/bin/rollout-APP --resume
```

The existing workflow writes exactly two newline-terminated fields to that
remote command's stdin: its registry username and existing registry token. The
remote argv remains exactly the command above. The scoped runtime bounds and
validates both fields, derives one registry host from the signed pending
candidate set, authenticates through an operation-private Docker configuration,
and removes it before returning. No registry host, image, model, policy, path or
permission is accepted from CI.

The generated broker accepts exactly that one argument, verifies its own fixed
`rollout-APP` filename, takes the normal app deployment lock, and invokes the
app-scoped runtime with only its baked-in root-owned profile and app name. It
accepts no release, digest, model, path, profile, budget or alternate app from
CI. The runtime then takes the private journal lock and reads the pending source;
an absent/mismatched journal or scope fails closed. This is continuation of
recorded intent, not submission of an old artifact as a new goal.

Image-pull failures expose only one bounded, fixed diagnostic category:
configured operation deadline, registry authentication/access, registry
network, digest/platform availability, or unrecognized safe diagnostic. Raw
Docker output is never printed because it may contain private image paths or
credential-bearing URLs. The category does not mutate the journal, add a
pre-stage operation, or relax the exact app-scoped resume interface.

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

Long-lived browser compatibility is application-owned. For the currently
required 24-hour supersession window, the application release must make all
needed content-hashed assets available from the active static service and keep
its active API backward compatible for at least 24 hours. The platform does not
guess unlimited retention or treat request drain as proof that an old tab is
gone; the app must measure the retained artifact set and refuse deployment when
the owner-authorized capacity floor cannot hold it.

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

An explicitly authorized failed-incarnation recovery uses a separate
transaction-pinned verifier and journal proof. It is not ordinary resume and
does not infer drain or graceful exit from a stopped container. The verifier
must durably fence application producers and prove empty queue/provider/file
state while the platform rechecks exact incarnations and gateway drain. Its
complete root authorization and bounded session contract is versioned in
[`internal/rollout/RECOVERY-VERIFIER.md`](../internal/rollout/RECOVERY-VERIFIER.md).
The app broker exposes only `rollout-APP --recover`, with no arguments or stdin,
and only when root has separately installed the exact one-time authorization.

Shared releases are immutable and opt-in. `komizo` release publication and
`komizo-actions` release publication are manual workflow dispatches; neither
updates hosts or consumer pins. `komizo update` is also operator-invoked. A
public release therefore does not authorize installation on any host.
