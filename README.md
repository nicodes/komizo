<!-- Generated from private documentation source. Do not edit directly. Source SHA256: a7327463d637eaf76176ce0b69a0f66f053156d592d6ddc7dd9777f6f8790cf1 -->

# komizo

Komizo installs immutable application releases on a Debian 13 host using rootful Podman, systemd and cgroup v2. Applications declare services, one-shot jobs, static assets, private networks, retained volumes, routes and readiness. Protected host policy grants artifact, resource, hostname and secret authority.

A host Caddy service serves installed static files and routes to private application addresses. Static applications require no application containers. Container services publish no host ports. Workload processes use the numeric identities and capabilities declared by their application.

## Install the owner client

Linux and macOS, x86_64 and arm64:

```sh
curl -fsSL https://komizo.dev/install | sh
```

The installer requires an authenticated GitHub CLI session for release attestation verification. It verifies the selected archive checksum and signing workflow, then atomically installs `komizo` to `~/.local/bin`. It starts no services.

The four owner archives contain the workstation-native client and its embedded local Rust API/UI. Linux host executors and audited Caddy executables with build receipts are separate release assets. Host installation uses verified executable artifacts; it requires no source compiler on the server.

## Operate a host

Pin the host's SSH key in the owner's known-hosts file before connecting. The client uses the owner's root SSH identity with strict host-key verification. `--identity` selects an optional absolute private-key path.

```sh
komizo capabilities
komizo status --host server.example
komizo inspect --host server.example --application mailroom
komizo stop --host server.example --application mailroom
komizo start --host server.example --application mailroom
komizo restart --host server.example --application mailroom
komizo backup --host server.example --application mailroom
komizo logs --host server.example --application mailroom --service migrate
komizo ui --host server.example
```

`--instance` selects `production` or an admitted `pr-N` preview. The UI listens on loopback and supervises its local API. It displays observed source, resources, operation history and bounded service or job logs. Actions bind the displayed release and a proposed operation identity. A failed or lost acknowledgment requires inspection before retrying.

Commands return typed JSON. Failed mutation receipts remain on stdout with a nonzero exit status; diagnostics use stderr. `inspect` accepts `--operation` with an exact operation ID and `--release` with its release digest. The owner client exposes a finite command set and a typed request-file transport:

```sh
komizo request --host server.example --file request.json
```

Request files can contain credentials. Keep them private. Requests travel over SSH stdin; secrets and bearer proofs are never command arguments.

## Prepare the host

The supported host baseline is Debian 13, distro Podman 5.4.2 or newer, systemd and a unified cgroup v2 hierarchy. The executor requires enforced memory, CPU and PID controllers. Capacity policy accounts for measured RAM, CPU, storage, operating-system reserve, application pools, shared helpers and ingress.

Install the verified `komizo-box` and native Caddy artifacts at their protected paths, including the matching Caddy build receipt. Prepare root-owned capacity, proxy and application policies under `/etc/komizo`. Then the owner installs the restricted submission boundary:

```sh
komizo-box install --authorized-keys /absolute/path/submission-public-keys
```

Bootstrap verifies the Caddy executable and provenance receipt, manages systemd units and creates the restricted `komizo-submit` account and independent unprivileged `komizo-proxy` account. Individual applications do not receive host SSH accounts. GitHub application/action authorization is checked independently inside the protected controller; possession of a submission key grants no application authority.

Policy types and finite constraints are defined in [the deployment model](src/deployment/model.rs) and [validation](src/deployment/validation.rs). Protected policy, state and secret files remain private. Installed public assets use a separate readable, immutable serving cache.

## Author and deliver an application

`deploy/application.toml` contains the versioned `komizo.application` definition and its complete workload. Services and jobs reference immutable image artifacts. Static assets reference bounded immutable archives. Dependencies explicitly select started, healthy or completed conditions. Environment files and mounted secrets select named operator grants; application source contains no secret values or host paths.

A canonical `komizo.release` descriptor binds the source repository and revision, immutable artifact inventory, workload and optional stateful compatibility contract. Its SHA256 is the release identity. Source revision, release digest, application instance and operation ID are separate facts.

```sh
komizo-box application validate deploy/application.toml
komizo-box release validate release.json
```

Applications build and test with their own tools. [Cookbook](https://github.com/nicodes/cookbook) can generate contributor workflows and immutable release packets. [komizo-actions](https://github.com/nicodes/komizo-actions) submits bounded requests and fresh audience-bound GitHub proofs. The host independently checks the approved repository, workflow, source, action and artifact family before accepting effects. Owner-authorized applications use the separately authenticated local owner authority.

The release packet contains its exact descriptor and inventory, explicitly inventoried metadata, image archives where required and static archives where required. There is no configuration image. Podman imports the accepted image configuration IDs without retagging unrelated images or pulling a mutable execution target.

## State, secrets and recovery

Services run through protected Quadlet definitions. The controller journals effects before executing them and survives submitter disconnects. One-shot job receipts bind code, secrets, retained objects and native exit evidence. Failed or uncertain migrations never replay automatically. Native boot uses only installed artifacts and retains deliberate stop intent.

Deploying to a stopped instance stages an accepted prepared release without starting databases, jobs or public routes. Start selects that exact prepared release. Restart, Stop and ordinary Backup select the installed release.

Volume-bearing production applications require explicit owner enrollment. Owner-only `data-prepare` creates stopped owned data resources from the reviewed descriptor. Owner-only `data-accept` binds their actual volume fingerprints to explicit empty initialization or an exact hashed transfer-verification report. Empty initialization refuses existing data. Transfer acceptance records database, authorization and file verification evidence. Data preparation alone cannot activate application source; the admitted delivery must stage that source first.

Protected backup bundles capture the actual installed descriptor and data, encrypt snapshots to the owner's public recovery certificate and export exact ciphertext/receipt pairs. The private recovery key stays with the owner. Retained data can be captured when an API never started. Migration or credential recovery requires independently verified owner evidence.

Secret values live in private immutable versions. Owner `secret-set` requests contain a finite `secret_updates` batch with expected generations. Komizo validates the complete batch and changes policy references in one atomic commit. Installed secret snapshots remain immutable until a later activation.

Owner `recover` requests select an exact uncertain operation. Recovery verifies protected creation/removal intents, actual native IDs, complete retained mount bindings, unit hashes and task quiescence. It repairs only proven metadata and finishes only accepted cleanup; it never starts an application or replays a migration. Capture helper cleanup uses the exact original protected bundle and removes only its recorded helper containers and owned plaintext staging.

Previews use the same full workload graph, private database, volumes, resource admission and lifecycle as production. They receive isolated secret grants and a bounded lifetime. Expiry removes only their owned resources. The initial preview policy supports disposable data; a host may refuse a complete preview allocation when capacity is insufficient.

## Contributor verification

`mise.toml` pins contributor SDKs. `cookbook.toml` declares native components, acceptance suites and package assets. Generated task and CI callers use the same immutable Cookbook source.

```sh
mise run help
mise run setup
mise run build
mise run test
```

Setup prepares declared SDKs and fixtures. Build produces the UI, local API, owner clients, separate host executors and audited Caddy companions. Test verifies current-source outputs; it does not install tools or build missing shipping artifacts. Verification evidence stays in `.artifacts/verification`.

The matrix covers Linux and macOS owner clients on both architectures. Disposable Debian hosts verify actual boot, Podman lifecycle, data capture/restore, deliberately stopped state, network isolation and kernel limits. Release acceptance separately measures the reviewed one-CPU/one-GiB host profile and cold owner operations. Source, package, installed and application acceptance remain separate evidence.
