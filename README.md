<!-- Generated from private documentation source. Do not edit directly. Source SHA256: e406f1c788026a7baa99b061cfec33587fc108b5ea0a7df4383e2b9938e69a0f -->

# Komizo

Agent-first, application-agnostic CLI for operating your own Compose hosts over SSH. The application host remains one box. No hosted Komizo account is required. Applications own their images, Compose files, topology and readiness; operators explicitly authorize their source and resource limits.

## Install

Download a matching Darwin/Linux, arm64/x86_64 archive from [releases](https://github.com/nicodes/komizo/releases). The agent interface below is available in v0.0.122 and later; these examples pin v0.0.122. Verify its checksum and GitHub attestation before executing it. The workstation needs SSH; platform maintenance also uses Python 3. The application server uses Alpine Linux with OpenRC, amd64 or arm64, and root SSH access.

```sh
# Linux x86_64; choose the matching archive for your workstation.
gh release download v0.0.122 --repo nicodes/komizo \
  -p komizo_Linux_x86_64.tar.gz -p checksums.txt
sha256sum -c checksums.txt --ignore-missing
gh attestation verify komizo_Linux_x86_64.tar.gz --repo nicodes/komizo
tar xzf komizo_Linux_x86_64.tar.gz
./komizo capabilities
```

Release archives embed both host architectures and need no Go compiler. With the matching Go toolchain, the source alternative is `go run github.com/nicodes/komizo@v0.0.122 --json setup --host root@your-server`; it builds the matching host executable when needed. Use only hosts you own or administer.

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

Use `setup --host root@your-server` without a definition to prepare just the host. All commands support `--help`. `list --json` returns raw registered apps; the historical `report --json` continues to return its raw versioned report.

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

## Machine contract

Prefix any supported finite command with `--json`. Stdout is one version-1 envelope containing `version`, `command`, `ok`, `exit_code`, `data` and `error`, plus a safe `next_action` argv when applicable. Progress goes to stderr. `capabilities` publishes the envelope schema, command effects and result formats. Core journey commands return typed data; legacy text and untrusted application logs are explicitly wrapped in `data.text`.

Errors include a stable code, diagnostic message, `retryable: false` and `reconciliation_required`. A failed mutating command is conservatively uncertain; inspect before retrying. Failed doctor checks and acknowledged operation IDs remain in `data` when available. `komizo --json --timeout 5m COMMAND ...` selects a deadline from one second to one hour; the default is 30 minutes. Captured stdout is bounded at 4 MiB. Timeouts do not cancel durable host work. Interactive UI and retired hosted-account commands are outside the machine interface. Help succeeds; invalid flags still fail.

For lifecycle and advanced operations use `start`, `stop`, `restart`, `logs`, `set-secret`, `preview`, `platform`, `operator`, `workspace`, `artifact` and their command help. The protected operator/broker is optional; it is not another application-host requirement. Authority changes, upgrades and package maintenance retain their explicit reviewed plan/apply interfaces.
