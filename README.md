<!-- Generated from private documentation source. Do not edit directly. Source SHA256: a686a8729d76e8452e05dfab1b639fb80843ebbfcbcce0cefe41cc2642bd5e64 -->

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
