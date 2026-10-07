<!-- Generated from private documentation source. Do not edit directly. Source SHA256: de88ea7a601145159b88f155279609b5d362abeeb4a911485d671acc36b7136b -->

# komizo

CLI for preparing and operating your own Compose hosts over SSH. No hosted account is required. Run it only against hosts you own or administer.

## Install and use

Use a verified release archive or the Go toolchain matching `go.mod` and `.mise.toml`.

```sh
go run github.com/nicodes/komizo@v0.0.45 init --host root@your-server
```

`init` prepares the host and requires privileged access. Review its changes before using it on an existing host. `komizo list`, `komizo report` and `komizo logs` inspect applications; see command help for current flags. The local UI is available through the CLI’s `ui` command.

The supported deployment operation is app-scoped Compose deployment. Historical journaled rollout releases v0.0.30–v0.0.39 are superseded by v0.0.40 and later. Deployment actions are in [komizo-actions](https://github.com/nicodes/komizo-actions). Verify release checksums and attestations before running a downloaded binary.

## Release archive without Go

Example for Linux x86_64, using the reviewed release v0.0.45:

```sh
gh release download v0.0.45 --repo nicodes/komizo \
  -p 'komizo_Linux_x86_64.tar.gz' -p checksums.txt
sha256sum -c checksums.txt --ignore-missing
gh attestation verify komizo_Linux_x86_64.tar.gz --repo nicodes/komizo
tar xzf komizo_Linux_x86_64.tar.gz
./komizo --help
```

Select the matching Darwin/Linux and arm64/x86_64 archive for another platform. Verify it before provisioning a host.

### Image retention

After updating an app with `komizo add --keep-key`, successful deployments record the current and previous revisions for image retention. The app's deploy account can run `doas /usr/local/bin/prune-<app> --dry-run` to review candidates, then the same command without `--dry-run` to remove superseded images. The command keeps current and rollback tags, their aliases, all container-referenced images and images outside the app's family. Missing or stale deployment records prevent cleanup. A same-version deployment preserves the earlier rollback record.

Re-running `komizo init` installs nightly maintenance that invokes these same app commands after preview garbage collection. It does not run a global image prune. Deploy accounts require no Docker socket access.
