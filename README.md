<!-- Generated from private documentation source. Do not edit directly. Source SHA256: 0bfe125cd88afc492198ef755bed1f6ff43b30d7d0073050c67eacedd4f81b3f -->

# Komizo

CLI for developing, verifying and operating projects and Compose hosts over SSH. The application host remains one box. No hosted Komizo account is required. Applications own their images, Compose files, topology and readiness; operators explicitly authorize their source and resource limits.

## Project commands

Install a published archive as described below, then work from your project checkout:

```sh
komizo dev
komizo check
komizo status
```

`komizo.json` declares the recipe, project commands and development credential selection. Recipes supply exact tool versions; `tools` overrides only the versions or tools a project needs to change. `komizo.lock` binds those inputs to the installed Komizo release and its bundled runtime. Komizo installs the declared tools automatically. `komizo check` runs applicable verification and records source and artifact receipts; unchanged outputs are reused only while their recorded inputs and bytes still match.

To adopt an existing project:

```sh
komizo init --recipe static-site   # also: go-service, go-cli, go-library, godot-app, godot-addon, configuration
komizo lock                      # after changing declared inputs
komizo describe                  # inspect capabilities without running project code
komizo run unit                  # run a selected stage
komizo exec -- go version         # run a command with the locked tools
```

Static sites use Bun install/build/dev and `scripts/test-site.sh` for their output assertions. Go services default to a root main package, Go formatting/vet, race-enabled tests, an executable build and vulnerability scanning. Go CLI projects use the same executable checks. Go libraries compile their packages and explicitly declare that they publish source rather than an application executable. Godot applications and addons supply their test/package/export scripts. Configuration projects supply `scripts/lint.sh` and `scripts/unit.sh`; missing checks fail. Override a recipe stage with argument arrays in `stages`; an inapplicable stage requires a reason. `tasks` adds named project commands accessible through `komizo run NAME`. Initialization creates configuration for existing application source.

Development runs in the foreground until Ctrl-C. The declared default selects Preview credentials where supported; `komizo dev --mode local` selects offline fixtures. `--mode preview` requests Preview explicitly. Selected credentials are injected into the child process environment and are never written to a `.env` file. Development credential retrieval requires the repository's trusted `ghenv.yml` workflow and GitHub CLI authentication. Production credentials are excluded from that handoff.

Host setup records a private repository-to-host binding in the workstation's Komizo configuration directory. Once an operator has configured that binding, `komizo deploy` selects the checkout's clean committed revision, `komizo preview --pr NUMBER` uses its declared published images, and `komizo status` reads its installed health. Explicit `--host` and `--app` remain available. Project manifests cannot grant host authority. Deployments and previews require their published images and the host's existing authorization checks.

Use `komizo run --tools python TASK` or `komizo exec --tools python -- COMMAND` for a named maintenance task that only needs selected declared tools. Verification stages always use the complete recipe toolchain. `komizo describe` reports the resolved tools.

`komizo check --explain` describes the complete gate without executing project code. With `--base EXACT_COMMIT`, it explains or runs the affected stages declared under `verification` in `komizo.json`. Shared configuration, unknown paths, unavailable/non-ancestor bases and production events require the complete gate. The complete policy must cover every applicable recipe stage. Patterns use `*` and `?` over checkout-relative path text. Selection metadata is separate from successful test or publication evidence.

All project commands accept `--directory DIR`. Finite commands accept `--timeout DURATION`; development has no deadline unless one is selected. Verification failures include a focused rerun command.

## GitHub Actions

Pin the setup action to the exact full source commit recorded in `komizo.lock.platform_revision`. It installs the locked platform release, checks its checksum and source attestation, then validates the project lock. Use the same command as locally:

```yaml
steps:
  - uses: actions/checkout@FULL_40_CHARACTER_CHECKOUT_COMMIT
    with:
      persist-credentials: false
  - uses: nicodes/komizo/setup@FULL_40_CHARACTER_KOMIZO_SOURCE_COMMIT
    env:
      GH_TOKEN: ${{ github.token }}
  - run: komizo check
```

For compiler or image caches and retained verification receipts, run `nicodes/komizo/run` at the same pinned source after setup. Its `target` input selects stages, with `check` as the default; optional `go-cache`, `web-cache` and `build-cache` inputs enable the corresponding caches.

The job needs read access to repository contents and attestations. Project source verification does not require deployment credentials. Publication and deployment remain separate authorized steps.

## Install

Download a matching Darwin/Linux, arm64/x86_64 archive from [releases](https://github.com/nicodes/komizo/releases). These examples pin v0.2.0, including structured management results and exact-stage platform recovery. Verify its checksum and GitHub attestation before executing it. The workstation needs SSH; platform maintenance also uses Python 3. The application server uses Alpine Linux with OpenRC, amd64 or arm64, and root SSH access.

```sh
# Linux x86_64; choose the matching archive for your workstation.
gh release download v0.2.0 --repo nicodes/komizo \
  -p komizo_Linux_x86_64.tar.gz -p checksums.txt
sha256sum -c checksums.txt --ignore-missing
gh attestation verify komizo_Linux_x86_64.tar.gz --repo nicodes/komizo \
  --signer-workflow nicodes/komizo/.github/workflows/release.yml \
  --source-ref refs/heads/main --deny-self-hosted-runners
tar xzf komizo_Linux_x86_64.tar.gz
./komizo capabilities
```

Release archives embed both host architectures and need no Go compiler. Published releases include attested acceptance and performance receipts for the declared disposable Alpine test profile. With the matching Go toolchain, the source alternative is `go run github.com/nicodes/komizo@v0.2.0 --json setup --host root@your-server`; it builds the matching host executable when needed. Use only hosts you own or administer.

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

Existing ready hosts are observed without an incidental upgrade. Existing application keys and established workload authority are preserved. A changed definition requires the separate reviewed authority migration. An older executor without setup capabilities must be explicitly upgraded before registration. Setup returns the private key's filename; it never prints its contents. `--key PATH` selects a destination. The default is a private Komizo directory under the workstation's OS configuration directory. A registration interrupted after writing its key can resume with the intact key bound to the same app and host.

Use `setup --host root@your-server` without a definition to prepare just the host. All commands support `--help`. `komizo --json list` returns registered applications; `komizo --json report` returns the typed host report.

## Application definition

This is operator-reviewed configuration, with no secret values. Adapt the source identity, resource envelope, images and readiness to the app. The repository ID is the immutable numeric GitHub repository ID. Configuration images must end in `-config`, contain the app's Compose/hostname artifacts and use the matching image family. Applications use the existing app-scoped gate/ingress convention.

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

`deploy` submits the exact 40-character source commit through installed host deployment authority. The host still verifies authenticated Build/source evidence, immutable artifacts, finite resources, readiness, stateful compatibility and any required delivery authorization. The CLI does not build or publish untrusted images, invent CI proof or bypass those requirements. GitHub Actions remains an optional delivery client of the same host executor.

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

Errors include a stable code, diagnostic message, `retryable: false` and `reconciliation_required`. Local validation uses `invalid_input` without uncertain remote effects; inventory differences use `state_mismatch` with typed findings. Missing or malformed structured results fail as `invalid_response`. Flag values spelled `--help` cannot clear mutation uncertainty. A failed mutating command is conservatively uncertain; inspect before retrying. Failed doctor checks and acknowledged operation IDs remain in `data` when available. `komizo --json --timeout 5m COMMAND ...` selects a deadline from one second to one hour; the default is 30 minutes. Structured results and retained log/help output are bounded at 4 MiB. Results are emitted directly by command handlers; Komizo does not relaunch itself or parse its printed output. Timeouts do not cancel durable host work. Interactive development and UI commands use the foreground terminal. Hosted-account commands are unavailable. Help succeeds; invalid flags still fail.

For lifecycle and advanced operations use `start`, `stop`, `restart`, `logs`, `set-secret`, `preview`, `platform`, `operator`, `workspace`, `artifact` and their command help. The protected operator/broker is optional; it is not another application-host requirement. Authority changes, upgrades and package maintenance retain their explicit reviewed plan/apply interfaces.

## Dependency automation

`komizo dependencies inspect [--pr NUMBER]` returns decisions based on signed bot metadata, current head/base revisions and CI evidence. `komizo dependencies apply` permits a merge only after those checks; it never runs pull-request code or project tool hooks. GitHub automation supplies its repository/event identity and authenticated GitHub CLI context. `--output NEW_FILE` retains a report. Review-required updates remain open.

`komizo --json metadata` parses a dependency metadata block from stdin. Parsing does not authorize a merge; signatures, authorship and source/CI checks remain mandatory in the dependency client.
