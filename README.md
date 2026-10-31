<!-- Generated from private documentation source. Do not edit directly. Source SHA256: 4663da29c03645fbddf22107ba127bc3a4bde5d65291a711c34470e8c1bb7413 -->

# komizo

Deploy immutable Compose workloads and operate Alpine/OpenRC hosts over SSH. Applications own their images, topology, health assertions and data compatibility; protected host policy authorizes artifacts and finite resources. The CLI needs no hosted Komizo account, SDK manager, application identity provider or private documentation checkout.

Build and test applications with their own tools. Komizo consumes published images and never executes development recipes.

## Deployment targets

Explicit host selection needs no checkout or configuration:

```sh
komizo deploy --host root@your-server --app mailroom --version EXACT_REVISION --approval approval.json
komizo status --host root@your-server --app mailroom
```

For GitHub-authorized applications, setup records a private repository-to-host binding in the workstation's OS configuration directory. An optional root komizo.json contains only deployment selection:

```json
{"version":1,"repository":"your-account/mailroom","images":["registry.example/mailroom-gate:{revision}"]}
```

Then komizo deploy selects the checkout's clean committed revision, komizo status reads installed health, and preview uses declared published images. Explicit host/app values take precedence; conflicting app or port identities fail before remote effects. SDK pins and build receipts do not affect target resolution or host admission.

## Artifact authority

Choose one authority in the root-reviewed application policy. GitHub Actions provenance uses source_repository and repository_id, with optional protected delivery authorization. The GitHub adapter authenticates exact workflow/source/test evidence and image configuration IDs.

For independent use, replace those GitHub fields with "owner_approval": true. Submit the exact images selected by the root SSH operator in a bounded approval document:

```json
{
  "version": 1,
  "revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "images": {
    "registry.example/mailroom-config:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": "sha256:REPLACE_WITH_CONFIGURATION_SHA256",
    "registry.example/mailroom-gate:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": "sha256:REPLACE_WITH_CONFIGURATION_SHA256"
  }
}
```

Pass this file with --approval and an explicit root SSH host. Root SSH authenticates the approving operator; the document fixes byte identities. It makes no CI or publisher claim. The host stores a protected approval receipt and compares every pulled configuration ID before starting services. Revision tags identify the release, while immutable registry digests select execution bytes. A digest alone grants no authority.

Owner approval and GitHub source/delivery authority are mutually exclusive. Generated CI wrappers cannot select owner approval, and an application PR cannot change protected host policy. Existing GitHub-authorized installations keep their provenance requirements. Supply --proof for their audience-bound release proof instead of --approval.

## Install

Linux and macOS (x86_64 or arm64), using prebuilt binaries:

With curl:

```sh
curl -fsSL https://komizo.dev/install | sh
```

Or with mise:

```sh
mise use --global github:nicodes/komizo@latest
```

The shell installer requires the GitHub CLI and an authenticated GitHub.com session (`gh auth login --hostname github.com`, or an existing `GH_TOKEN`) for release provenance verification. Authentication is checked before any release download. It verifies the archive checksum and GitHub attestation, then atomically installs to `~/.local/bin` without starting services. Mise manages its own installation directory and PATH through its shell activation.

Release archives embed both host architectures and the workstation-native Rust API. The local UI, signed Unix-socket monitor and preview certificate listener run in Rust/Axum under `api/`. The Go CLI and privileged host executor retain their own finite command and deployment authority. No Go HTTP API is launched. The workstation needs SSH; platform maintenance also uses Python 3. The application server uses Alpine Linux with OpenRC, amd64 or arm64, and root SSH access. Use only hosts you own or administer.

## Agent journey

```sh
komizo --json capabilities
komizo --json doctor --host root@your-server
komizo --json setup --host root@your-server --definition ./app.json
komizo --json deploy --host root@your-server --app mailroom --version COMMIT
komizo --json operation inspect --host root@your-server --app mailroom
komizo --json report --host root@your-server
```

Pin the server SSH key before setup. First-use trust is explicit with `--accept-host-key`; changed keys continue to refuse. `doctor` reads prerequisites without installing packages or invoking Docker. `setup` checks first, prepares an uninitialized host and optionally registers the declared app. At least 256 MiB measured system memory, 1 GiB ordinary free space on `/var/lib` and 4096 free inodes are required for setup; these are installation prerequisites, not an app-capacity guarantee.

Existing ready hosts are observed without an incidental upgrade. Existing application keys and established workload authority are preserved. A changed definition requires the separate reviewed authority migration. An older executor without setup capabilities must be explicitly upgraded before registration. Setup returns the private key's filename; it never prints its contents. `--key PATH` selects a destination. The default is a private komizo directory under the workstation's OS configuration directory. A registration interrupted after writing its key can resume with the intact key bound to the same app and host.

Use `setup --host root@your-server` without a definition to prepare just the host. All commands support `--help`. `komizo --json list` returns registered applications; `komizo --json report` returns the typed host report.

## Application definition

This is operator-reviewed configuration, with no secret values. Adapt the artifact authority, resource envelope, images and readiness to the app. The repository ID is the immutable numeric GitHub repository ID. Configuration images must end in `-config`, contain the app's Compose/hostname artifacts and use the matching image family. Applications use the existing app-scoped gate/ingress convention.

```json
{
  "version": 1,
  "app": "mailroom",
  "config": "ghcr.io/your-account/mailroom-config",
  "policy": {
    "version": 1,
    "app": "mailroom",
    "app_dir": "/srv/mailroom",
    "image_prefix": "ghcr.io/your-account/mailroom-",
    "shared_network": "edge",
    "source_repository": "your-account/mailroom",
    "repository_id": "123456",
    "resources": {
      "default": {"memory_bytes": 134217728, "memory_swap_bytes": 134217728, "milli_cpus": 250},
      "max_memory_bytes": 268435456,
      "max_memory_swap_bytes": 268435456,
      "max_milli_cpus": 500
    },
    "readiness": {"probes": [{"url": "https://mail.example/readyz", "revision_field": "revision"}]}
  }
}
```

The definition authorizes initial deployment policy only for its registered app. Setup cannot overwrite an established policy, replace an operation fence or accept another app's directories or image family. App-specific privileged adapters and preview profiles remain explicit operator-owned inputs through `add --scoped-env-spec` and `preview configure`; CI cannot install them.

## Deploy and recover

`deploy` submits the exact 40-character source commit through installed host deployment authority. The host verifies its selected approval authority, immutable artifacts, finite resources, readiness, stateful compatibility and any required delivery authorization. The CLI does not build or publish untrusted images, invent CI proof or bypass those requirements. GitHub Actions remains an optional delivery client of the same host executor.

Use `--proof FILE` when supplying an existing authenticated release proof. Private GHCR pulls accept `--registry-user USER --registry-token-file PRIVATE_FILE`; the token travels over SSH stdin into the existing operation-private credential slot. Tokens and proof bodies are never placed in SSH arguments. Use the app's exact existing `--generation` for scoped credentials. `--wait=false` returns after submission; the default waits for the durable result and verifies its operation identity. A stopped app remains stopped.

On refusal, timeout or lost acknowledgement, inspect the operation before resubmitting. Inspection returns its decision, policy/operation identities and reviewable recovery argv for interrupted states. Select the intended serving revision and outcome explicitly. `operation recover` requires those exact reviewed identities, and the host independently rechecks them and its serving postconditions. It does not restore database data, replay provider work, restart the application or discard the fence.

Platform configuration recovery uses the root operator and its exact protected server stage and reviewed digest:

```sh
komizo --json platform inspect --host root@your-server \
  --stage /var/lib/komizo/upgrades/STAGE --expected-manifest REVIEWED_SHA256
komizo --json platform recover --host root@your-server \
  --stage /var/lib/komizo/upgrades/STAGE --expected-manifest REVIEWED_SHA256
```

Inspect the journal before choosing recovery. Recovery restores the recorded prior platform configuration; database recovery is a separate operation. Host identity, foreign-writer and fence checks remain mandatory.

## Machine contract

Prefix any supported finite command with `--json`. Stdout is one version-1 envelope containing `version`, `command`, `ok`, `exit_code`, `data` and `error`, plus a safe `next_action` argv when applicable. Progress goes to stderr. `capabilities` publishes the envelope schema, command effects and result formats. Management commands return structured objects or arrays. A receipt acknowledges successful command completion; readiness remains a separate observation. `capabilities` publishes a common management receipt schema. Application logs, complete command help and printable installer source are explicitly wrapped in `data.text`.

Errors include a stable code, diagnostic message, `retryable: false` and `reconciliation_required`. Local validation uses `invalid_input` without uncertain remote effects; inventory differences use `state_mismatch` with typed findings. Missing or malformed structured results fail as `invalid_response`. Flag values spelled `--help` cannot clear mutation uncertainty. A failed mutating command is conservatively uncertain; inspect before retrying. Failed doctor checks and acknowledged operation IDs remain in `data` when available. `komizo --json --timeout 5m COMMAND ...` selects a deadline from one second to one hour; the default is 30 minutes. Structured results and retained log/help output are bounded at 4 MiB. Results are emitted directly by command handlers; komizo does not relaunch itself or parse its printed output. Timeouts do not cancel durable host work. The optional UI command use the foreground terminal. Hosted-account commands are unavailable. Help succeeds; invalid flags still fail.

For lifecycle and advanced operations use `start`, `stop`, `restart`, `logs`, `set-secret`, `preview`, `platform`, `artifact` and their command help. Authority changes, upgrades and package maintenance retain their explicit reviewed plan/apply interfaces.

## Static serving

Static workloads select an absolute image_directory, bounded limits, and explicit serving options under policy.static. Serving options include fallbacks, deny_paths, headers, header_rules, precompressed formats and encode selectors. Headers and selectors are bounded and validated; they cannot choose an upstream, root directory, plugin or revision identity. Denied paths are checked before fallback. The host retains immutable extraction, resource admission, current/previous images and stop intent.

## Development

Tool versions and native contributor tasks live in mise.toml. Install mise, check out nicodes/tools at the reviewed helper revision 87da2fe9d430c67d15f62f603b07ba1ed40b5603 into .ci-tools, then run:

```sh
mise install
mise run check
```

The gate retains Go race tests, shell and workflow checks, committed UI verification, embedded host builds, archive checks and vulnerability scanning, and adds Rust formatting, Clippy, tests and dependency scanning. `mise run ui` updates the committed web export; `api/build.rs` embeds that export into the native API.

Four native Actions builders produce Rust payloads for Linux and macOS on x86_64 and arm64. Linux payloads use static musl linking and run on Alpine. Each payload carries its source revision and SHA256 receipt; `mise run agents` and the release builder verify both before embedding it. A complete archive build needs all four payloads under `.artifacts/native-api/`; `bash tools/engineering/build-api.sh` produces the current platform's payload. CI downloads all four before running the complete product gate.

For a quick source UI build, run `cargo build --locked --manifest-path api/Cargo.toml`, then select the absolute built executable with `KOMIZO_API_BINARY` when running the Go CLI. Release users need no Rust or Go toolchain. A Go source install that needs to construct an unembedded host agent compiles both the agent and Rust API from the same checksum-verified module version, using its committed Cargo.lock. That path requires Rust 1.94.0 through rustup and a musl C compiler for the host architecture (`musl-gcc` for native Linux, or `CC_x86_64_unknown_linux_musl` / `CC_aarch64_unknown_linux_musl` for a cross compiler). It works in a private source copy and never modifies the module cache. CI also compiles and launches this source-built agent. The pinned tools setup action supplies contributor tools.
