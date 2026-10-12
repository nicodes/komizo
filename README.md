<!-- Generated from private documentation source. Do not edit directly. Source SHA256: b057d9182cb1ff2a53564c796d069a67171360eeb73d6f07b1fe21353379bdb9 -->

# komizo

CLI for preparing and operating your own Compose hosts over SSH. No hosted account is required. Run it only against hosts you own or administer.

## Install and use

Use a verified release archive or the Go toolchain matching `go.mod` and `.mise.toml`.

```sh
go run github.com/nicodes/komizo@v0.0.85 init --host root@your-server
```

`init` prepares the host and requires privileged access. Review its changes before using it on an existing host. `komizo list`, `komizo report` and `komizo logs` inspect applications; see command help for current flags. The local UI is available through the CLI’s `ui` command.

The supported deployment operation is app-scoped Compose deployment. Historical journaled rollout releases v0.0.30–v0.0.39 are superseded by v0.0.40 and later. Deployment actions are in [komizo-actions](https://github.com/nicodes/komizo-actions). Verify release checksums and attestations before running a downloaded binary.

## Release archive without Go

Example for Linux x86_64, using the reviewed release v0.0.85:

```sh
gh release download v0.0.85 --repo nicodes/komizo \
  -p 'komizo_Linux_x86_64.tar.gz' -p checksums.txt
sha256sum -c checksums.txt --ignore-missing
gh attestation verify komizo_Linux_x86_64.tar.gz --repo nicodes/komizo
tar xzf komizo_Linux_x86_64.tar.gz
./komizo --help
```

Select the matching Darwin/Linux and arm64/x86_64 archive for another platform. Verify it before provisioning a host.

## Protected operator lifecycle

Komizo owns the privileged operator and broker; the agent configuration repository owns agent behavior. On the Linux systemd machine that runs the operator, use a verified release to inspect and apply a concrete installation plan:

```sh
sudo ./komizo operator plan
sudo ./komizo operator apply --expected-plan <plan-sha256>
sudo ./komizo operator status
sudo ./komizo operator recover
```

The existing `fleet-editor` group, protected `/etc/fleet-operator.json` policy and `/etc/fleet-operator-broker` environment file define the caller's scope. The lifecycle refuses missing or changed authority, journals prior code before replacing it and retains consumed grants across upgrades. `recover` restores a prepared installation after interruption; it does not replay operations. The systemd activation socket remains owned by the service manager across broker process restarts.

The application host remains one box. App-scoped deployment, workload budgets, ingress and release admission are enforced by the host executor. Explicit static profiles and delivery-authorization requirements require an operator-reviewed migration; upgrading a binary alone does not enable them.

## Plan an application-host upgrade

Use the verified CLI, an exact release source commit and protected absolute local directories:

```sh
./komizo platform plan --host your-server --release v0.0.85 \
  --source 2eeffef9a67bc1d5e6f4d85db52d86a26664d769 \
  --release-dir /root/komizo/releases/v0.0.85 --stage /root/komizo/plans/upgrade
./komizo platform apply --host your-server --release v0.0.85 \
  --source 2eeffef9a67bc1d5e6f4d85db52d86a26664d769 \
  --release-dir /root/komizo/releases/v0.0.85 --stage /root/komizo/plans/upgrade \
  --resume --expected-manifest <reviewed-manifest-sha256>
```

Create the parent directories as Root first. Planning authenticates the release and records installed identities; applying the exact digest journals prior files and service state. Applications are not restarted by this upgrade. Inspect interrupted operations with `komizo-box platform inspect <remote-stage> <manifest-sha256>` on the host, then use `recover` with the same arguments. An operation with a journal must be inspected or recovered before another attempt.

`komizo platform proxy plan|apply` accepts an attested immutable `--reference`, exact publisher `--source`, protected `--stage` and operator-reviewed `--probes` JSON. Every running hostname needs its own HTTPS or WebSocket probe and exact serving revision. API routes use their readiness path; intentional redirects require their exact status and destination. The proxy publisher currently supports Linux amd64. Certificate volumes and retained previous images remain available for recovery.

New cold proxies have finite memory, swap, CPU and PID limits. To move an existing proxy into a declared host resource group, explicitly add `--bind-resources` to both proxy planning and application. The manifest binds the protected allocation and policy hash; application recreates the proxy and verifies its actual Docker group and limits. Measure resource policy before migrating serving workloads.

Protected container publication uses the Komizo-owned operator bundle with a separate Root policy and package credential. The publisher verifies finite final-source authorization, authenticated CI, immutable artifact/image/layer identities and package destinations before credentials. It durably refuses replay; ambiguous uploads require read-only inspection/reconciliation. Installing the bundle alone does not configure registry permissions or enable delivery authorization.

## Review workload authority changes

For a release that supports `--authority-review`, install that same authenticated release on the application host first. Keep the review and candidate files in a protected Root directory. The private JSON review has `version: 1` and a `files` list; each entry names an allowed registered-app destination `path`, a candidate filename `source` beside the review, and its exact `mode`. Workload policies use 0600, private task programs 0700, fixed command adapters 0755 and `/etc/doas.conf` 0600. Existing parent directories must already be protected; secret stores and arbitrary filesystem paths are outside this interface.

Add `--authority-review /root/komizo/review/review.json` to `platform plan`, then apply the resulting stage with its exact reviewed manifest digest. Planning reads only installed identity and permissions. Applying validates policy/shell/doas inputs before replacing files, retains previous bytes, modes and absence, and never activates application containers or routes. If interrupted, inspect and recover the same remote stage; pending recovery blocks workload and preview effects. A foreign file or permission change retains the fence for operator inspection. Root remains the trusted reviewer.

## Prepare image publication

For a release that supports `publication prepare`, run it after the complete main-workflow engineering gate with the unchanged tested checkout and exact source-tagged Linux amd64 images:

```sh
komizo publication prepare \
  --image ghcr.io/OWNER/PRODUCT-core:EXACT_SOURCE_COMMIT \
  --image ghcr.io/OWNER/PRODUCT-gate:EXACT_SOURCE_COMMIT \
  --output .artifacts/publication
```

The new output directory contains exactly `release.json` and `images.tar`. Upload them as `fleet-publication-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}` using the reviewed artifact action. Preparation records the actual Git tree, workflow run and attempt; it refuses changed tracked source, foreign tags, platforms, labels or layer hashes. It normalizes selected containerd/classic Docker save payloads into the protected publisher format within finite byte and time bounds. The Docker image ID is not assumed to equal the exported configuration digest.

This command saves local image bytes. It requires no registry credential and does not push images. Root publication remains a separate authenticated operation requiring its protected policy, final-source grant, exact producer evidence and package permissions.

`platform proxy plan|apply --bind-static` explicitly adds the existing protected `/srv/_public` tree at `/srv/public` read-only. Create its Root-owned parent beforehand. The plan retains all other mounts, certificates, networks and security settings; apply verifies the actual Docker mount and recovery restores its prior presence or absence. Existing writable or foreign mounts require separate review. This mount alone does not enable any application's static policy.

## Authorize routine ciphertext export

Install a signed release containing `workload routine-backup` before reviewing
this capability. The protected app policy's optional `routine_backup` object
binds `workflow_repository`, exact `workflow_revision`, `program_sha256` and
`timeout_seconds` (1–900). The reusable workflow path is fixed to
`.github/workflows/backup.yml`. The only export program is the protected
`/usr/local/bin/export-APP-backup`; CI cannot select a program or supply arguments.
Root reviews its ciphertext-only behavior and finite database cleanup separately.

A fixed app adapter invokes `komizo-box workload routine-backup --policy PATH`
and accepts one `komizo-operation/v1:` proof frame on stdin. The fresh GitHub
identity binds the complete routine-backup manifest, repository ID, run/attempt,
scheduled/dispatched main caller and immutable reusable workflow. Its revision
must match the host's accepted ready serving operation. Pending activation,
changed authority, stale proof and replay refuse before export. This capability
does not renew a delivery grant or authorize restoration, arbitrary tasks or
secret updates. The current contract requires a GitHub-hosted runner.

The host durably claims each run/attempt before invoking the fixed exporter.
Use `komizo-box workload backup-inspect --policy PATH --run ID --attempt N`
to inspect completed, claimed or ambiguous outcomes. An interrupted export is
never replayed automatically. Proof tokens are not stored in the operation journal.
`workload policy-check --policy PATH` validates a protected policy candidate
without Compose inputs, output files or activation.
