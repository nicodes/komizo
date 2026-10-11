<!-- Generated from private documentation source. Do not edit directly. Source SHA256: 240bdb459477eeb30dcd75f26d19b44c0c3d7b513a446b2b977b5d9872a48a26 -->

# komizo

CLI for preparing and operating your own Compose hosts over SSH. No hosted account is required. Run it only against hosts you own or administer.

## Install and use

Use a verified release archive or the Go toolchain matching `go.mod` and `.mise.toml`.

```sh
go run github.com/nicodes/komizo@v0.0.80 init --host root@your-server
```

`init` prepares the host and requires privileged access. Review its changes before using it on an existing host. `komizo list`, `komizo report` and `komizo logs` inspect applications; see command help for current flags. The local UI is available through the CLI’s `ui` command.

The supported deployment operation is app-scoped Compose deployment. Historical journaled rollout releases v0.0.30–v0.0.39 are superseded by v0.0.40 and later. Deployment actions are in [komizo-actions](https://github.com/nicodes/komizo-actions). Verify release checksums and attestations before running a downloaded binary.

## Release archive without Go

Example for Linux x86_64, using the reviewed release v0.0.80:

```sh
gh release download v0.0.80 --repo nicodes/komizo \
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
