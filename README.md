<!-- Generated from private documentation source. Do not edit directly. Source SHA256: 232a23ee78f3d6604799d1a08cf6d9d6ab15d7b053f0046d0f4e733c0bf2acd8 -->

# komizo

Reusable, application-agnostic CLI for preparing and operating your own Compose hosts over SSH. Application names, accounts, domains, service layouts and credential mapping come from explicit configuration. No hosted account is required. Run it only against hosts you own or administer.

## Install and use

Use a verified release archive or the Go toolchain matching `go.mod` and `.mise.toml`.

```sh
go run github.com/nicodes/komizo@v0.0.120 init --host root@your-server
```

`init` prepares the host and requires privileged access. Review its changes before using it on an existing host. `komizo list`, `komizo report` and `komizo logs` inspect applications; see command help for current flags. The local UI is available through the CLI’s `ui` command.

The supported deployment operation is app-scoped Compose deployment. Historical journaled rollout releases v0.0.30–v0.0.39 are superseded by v0.0.40 and later. Deployment actions are in [komizo-actions](https://github.com/nicodes/komizo-actions). Verify release checksums and attestations before running a downloaded binary.

## Release archive without Go

Example for Linux x86_64, using the reviewed release v0.0.120:

```sh
gh release download v0.0.120 --repo nicodes/komizo \
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
./komizo platform plan --host your-server --release v0.0.120 \
  --source 6443881535214dd4f9fadee92ae3eceb57ee02f3 \
  --release-dir /root/komizo/releases/v0.0.120 --stage /root/komizo/plans/upgrade
./komizo platform apply --host your-server --release v0.0.120 \
  --source 6443881535214dd4f9fadee92ae3eceb57ee02f3 \
  --release-dir /root/komizo/releases/v0.0.120 --stage /root/komizo/plans/upgrade \
  --resume --expected-manifest <reviewed-manifest-sha256>
```

Create the parent directories as Root first. Planning authenticates the release and records installed identities; applying the exact digest journals prior files and service state. Applications are not restarted by this upgrade. Inspect interrupted operations with `komizo-box platform inspect <remote-stage> <manifest-sha256>` on the host, then use `recover` with the same arguments. An operation with a journal must be inspected or recovered before another attempt.

`komizo platform proxy plan|apply` accepts an attested immutable `--reference`, exact publisher `--source`, protected `--stage` and operator-reviewed `--probes` JSON. Every running hostname needs its own HTTPS or WebSocket probe and exact serving revision. API routes use their readiness path; intentional redirects require their exact status and destination. The proxy publisher currently supports Linux amd64. Certificate volumes and retained previous images remain available for recovery.

New cold proxies have finite memory, swap, CPU and PID limits. To move an existing proxy into a declared host resource group, explicitly add `--bind-resources` to both proxy planning and application. The manifest binds the protected allocation and policy hash; application recreates the proxy and verifies its actual Docker group and limits. Measure resource policy before migrating serving workloads.

Protected container publication uses the Komizo-owned operator bundle with a separate Root policy and package credential. The publisher verifies finite final-source authorization, authenticated CI, immutable artifact/image/layer identities and package destinations before credentials. It durably refuses replay; ambiguous uploads require read-only inspection/reconciliation. Installing the bundle alone does not configure registry permissions or enable delivery authorization.

## Review workload authority changes

For a release that supports `--authority-review`, install that same authenticated release on the application host first. Keep the review and candidate files in a protected Root directory. The private JSON review has `version: 1` and a `files` list; each entry names an allowed registered-app destination `path`, a candidate filename `source` beside the review, and its exact `mode`. Workload policies use 0600, private task programs 0700, fixed command adapters 0755 and `/etc/doas.conf` 0600. Existing parent directories must already be protected; secret stores and arbitrary filesystem paths are outside this interface.

Add `--authority-review /root/komizo/review/review.json` to `platform plan`, then apply the resulting stage with its exact reviewed manifest digest. Planning reads only installed identity and permissions. Applying validates policy/shell/doas inputs before replacing files, retains previous bytes, modes and absence, and never activates application containers or routes. If interrupted, inspect and recover the same remote stage; pending recovery blocks workload and preview effects. A foreign file or permission change retains the fence for operator inspection. Root remains the trusted reviewer.

For a release supporting resource-policy migration, the review may also replace the existing `/etc/komizo/resources.json` at mode 0600. The executor validates measured capacity, controller availability and current usage before creating its journal, then applies the installed policy after replacing the reviewed files. Recovery restores both prior policy bytes and its controller settings; a failed controller recovery retains the fence for a measured drain. Empty unused app leaves may remain for inspection. Releases supporting rate-only I/O policies accept `io_weight: 0` only with nonempty finite `io_max` device limits. This keeps the installed disk scheduler and applies explicit read/write caps without assuming a proportional-weight backend. Positive weights require the `io.weight` interface and refuse during read-only preflight when it is unavailable; configured weights are scheduling hints whose effective share needs measurement. Container membership changes only through later ordinary app deployment. Use `komizo-box workload host-resources --check --policy /root/komizo/review/resources.json --check-usage` for a read-only preflight; a caller-selected file cannot select the apply authority.

Releases supporting `aggregate_mode: "cgroup"` can let services share the installed application's finite runtime budget. Individual services keep finite admission limits; the protected application group enforces the smaller total. The app reserve must match the installed allocation, and its startup allowance must fit between its reserve and pressure threshold. The default summed mode still requires the declared aggregate to fit the app allocation. Measure application startup and expensive work before opting in; the mode does not make all individual maxima available simultaneously.

The optional native kernel fixture is available from a reviewed source checkout:

```sh
python3 tools/engineering/native-cgroup-acceptance.py \
  --image alpine@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 \
  --output /absolute/path/native-cgroup-evidence.json
```

Run it on a development machine with local Docker and Linux cgroup v2 support. It creates and removes its own privileged container with a private cgroup namespace, no host mounts or Docker socket, and finite outer limits. The synthetic hard-boundary test intentionally kills an over-budget worker while checking the neighboring responder. It verifies kernel behavior; product, installer and OS-boot acceptance are separate.

A reviewed source checkout containing the public lifecycle fixture can run the installer, activation, self/proxy upgrade, executor interruption/recovery, cached deployment and stop-intent checks:

```sh
python3 tools/engineering/cold-lifecycle-acceptance.py \
  --release vX.Y.Z --source EXACT_RELEASE_COMMIT \
  --release-dir /absolute/path/verified-release \
  --output /absolute/path/fresh-protected-evidence
```

It requires Root, local Docker, Linux cgroup v2 and at least 4.5 GiB free on the Docker filesystem. It downloads public packages/images and verifies release provenance. Its privileged guest has finite CPU/RAM limits, private PID/cgroup namespaces and an owned 4 GiB filesystem; it removes its guest and disk without pruning shared images. It uses synthetic local images through operator bootstrap and verifies TLS with its own public CA. Root remains trusted. This tests public commands and real process recovery; it does not authenticate a new product CI source or test OS boot or real backup restoration.

For a release supporting current-image reconfiguration, Root can submit `komizo-box workload deployment-submit --policy /etc/komizo/workloads/APP.json --version CURRENT_SOURCE --local-only </dev/null`, then wait with `workload activation-wait --id OPERATION_ID`. This reuses only the retained current accepted source and local immutable images through the ordinary journalled worker. It accepts no registry credential or CI proof, performs no pull, preserves private environment and retained prior images, and refuses unresolved current operations or missing cached images. A scoped app still needs its existing protected `--generation`. This lets an operator apply reviewed resource/serving policy without rebuilding or authorizing another source. Root remains trusted; the flag is not exposed through product CI adapters.

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

## Engineering storage and workload acceptance

`komizo workspace check --path OUTPUT --reserve-bytes BYTES` checks ordinary
available bytes and inodes before an install or build. It does not count Root's
reserved filesystem blocks. `workspace plan --root WORKTREE --path OUTPUT`
reviews owned generated directories; the response contains `plan` and its
`sha256`. Save the inner `plan` object as a local JSON file, then use
`workspace clean --manifest PLAN_JSON --expected-plan SHA256`. Cleanup refuses
tracked files, mounted paths, active use, changed contents and evidence paths.
Linux cleanup requires visibility of the relevant processes. Shared caches are
never pruned by this command.

Use `komizo workload acceptance --profile PROFILE_JSON --host root@HOST
--output NEW_FILE` for an operator-reviewed synthetic pressure profile. The
profile binds installed binary/allocation hashes, app revisions, exact TLS/WSS
read probes and finite cases/repetitions. Each case fully touches hot memory,
runs 200m CPU work for forty seconds, writes eight 1MiB fsync blocks and checks
startup refusal before effects. Core reads retain a two-second maximum; the
chosen complete fresh report or light operation inspection retains five seconds.
Failed cases and cleanup failures remain in the aggregate while independent
cases continue. This is a declared engineering workload, not a universal SLO or
a provider, authenticated-product or real-backup test.

### Reviewed host package maintenance

The Root operator can plan Alpine package updates without changing installed packages. Plans retain firewall dependencies, verify signed package bytes, bind the current serving configuration and expire after two hours. Supply the installed `komizo-box` SHA256 from the authenticated release artifact receipt. Each output filename must be new.

```sh
komizo platform maintenance plan --host root@HOST --stage /var/lib/komizo/maintenance/update-001 --binary-sha256 BOX_SHA256 --output maintenance-plan.json
komizo platform maintenance apply --host root@HOST --stage /var/lib/komizo/maintenance/update-001 --binary-sha256 BOX_SHA256 --manifest-sha256 PLAN_SHA256 --output maintenance-applied.json
komizo platform maintenance inspect --host root@HOST --stage /var/lib/komizo/maintenance/update-001 --binary-sha256 BOX_SHA256 --manifest-sha256 PLAN_SHA256 --output maintenance-status-001.json
```

Review the returned manifest identity before applying. Applying blocks application deployment until acceptance. Arrange the one-box maintenance window and verify the bootloader and recovery-console route before restarting the machine. If the plan requires a kernel reboot, reboot through your existing Root SSH/provider route, then run:

```sh
komizo platform maintenance finish --host root@HOST --stage /var/lib/komizo/maintenance/update-001 --binary-sha256 BOX_SHA256 --manifest-sha256 PLAN_SHA256 --output maintenance-accepted.json
```

`finish` checks exact installed versions and, when a kernel update was planned, a fresh boot ID and the expected running kernel, unchanged serving configuration and stop intent, required services, complete host observation and firewall access before clearing the deployment block. After a connection failure, inspect the durable host operation. A partially completed package transaction remains blocked; repeating `apply` is refused. `finish` can reconcile a transaction only when its exact installed and serving postconditions hold. Preserve the stage and its original failure evidence.

An optional `controls` field in the Root host resource policy gives the fixed OpenRC Docker, controller and API groups finite memory/swap/PID limits and CPU weights. Their protected working sets fit inside the OS reservation, with an additional 64 MiB base OS allowance. Each controller's ceiling must leave the other declared serving floors. These are per-group limits and declared burst admission, not a promise that every group can reach its ceiling concurrently. Reductions refuse before writes when current usage exceeds the reviewed limits.

For a userspace-only transaction, add `--hold-kernel` to `maintenance plan`. The solver and offline transaction keep the exact installed kernel; acceptance also verifies that the running kernel did not change. The temporary transaction pin is removed after installation, preserving the reviewed original world constraints and explicit firewall intent. A held-kernel plan reports `kernel_held: true` and `reboot_required: false`. It still needs normal package and serving acceptance. Updated files do not establish that an already running daemon uses the new version; verify running services separately.

If finite controller limits refuse because usage is above a proposed cap, inspect the charge and inactive file cache first. An authenticated host executor supports this explicit Root admission step, bound to the protected candidate policy hash:

```sh
sudo komizo-box workload host-resources --reclaim-controls --policy /root/review/resources.json --policy-sha256 POLICY_SHA256
sudo komizo-box workload host-resources --check --policy /root/review/resources.json --check-usage
```

It preflights all three fixed control groups, requests at most 64 MiB per daemon with anonymous-memory swapping disabled, and records before/requested/after counters. Insufficient inactive cache, unsupported kernels and larger excesses refuse. Kernel reclaim can be incomplete; inspect the retained result and current usage. This step applies no limits, deletes no files/images and touches no application group. Only a subsequent reviewed authority plan/apply installs the policy. Never repeat a refused limit change blindly or use a cache drain to hide an underestimated working set.

Version-two acceptance profiles require `version: 2` and an integer `probe_interval_seconds` between 1 and 10. Choose a round cadence that fits each endpoint's existing request budget; every round still probes the declared routes and measures the chosen fresh operator read. Cadence does not raise the two/five-second latency limits or reduce the forty-second memory/CPU/fsync workload. Version-one profiles retain their historical pacing. The signed operator client can test a compatible older host executor: bind that host's actual authenticated binary hash in the profile.

Acceptance snapshots include available fixed OpenRC controller groups, actual throttle/hard limits and separate anonymous/file/kernel/inactive-cache charges. Failure evidence remains part of the aggregate. A rate-limit response is a failed read contract; it is not skipped or silently retried.

Persist a declared finite control policy through OpenRC service restarts with the public operator. Install the same authenticated host release first, then use protected local staging paths:

```sh
./komizo platform controls plan --host your-server --release v0.0.120 --source 6443881535214dd4f9fadee92ae3eceb57ee02f3 --release-dir /root/komizo/releases/v0.0.120 --stage /root/komizo/plans/controls
./komizo platform controls apply --host your-server --release v0.0.120 --source 6443881535214dd4f9fadee92ae3eceb57ee02f3 --release-dir /root/komizo/releases/v0.0.120 --stage /root/komizo/plans/controls --expected-manifest REVIEWED_SHA256
```

The plan binds the installed resource policy and derives native settings for the fixed Docker, controller and API services. It preserves caller options, journals prior modes and absence, and writes the reviewed configuration at 0600. Foreign control assignments and edits outside the managed block refuse. Applying this plan activates no application or service. Verify actual limits after an ordinary service restart. Self-upgrade and recovery also reapply installed resource authority before accepting restarted services. The workload fixture rejects declared control drift before applying pressure and retains transport timeout route/phase/elapsed diagnostics without retries.

## Application-owned operations

Komizo's runtime is reusable across unrelated applications and GitHub accounts. Applications own Compose files, service topology, migrations and environment mapping. Operators explicitly install host authority; application CI can request only its registered operations. Fleet inventory and deployment measurements belong outside the tool.

Releases supporting `--scoped-env-spec` accept an operator-reviewed local JSON definition:

```json
{"version":1,"profile":"mail-credentials-v1","schema":27,"files":["mailer.env","tls.pem"],"provision_script":"provision.sh","status_script":"status.sh"}
```

Pass this file to `komizo add --host root@your-server --app mailroom --config ghcr.io/your-account/mailroom-config --scoped-env-spec ./scoped-env.json`. The two bounded shell scripts must be regular sibling files. The operator reviews their root authority; Komizo substitutes only the app, state-file and deployment-lock bindings. Provisioning remains root-only. The deploy account can request argument-free status. Omitted configuration preserves the installed definition; an explicit empty scoped profile revokes adapters and grants while preserving credential data. Existing scoped installations need an explicit definition migration that preserves their generation, provenance and file permissions before using the generic runtime.

Releases supporting `preview configure` accept a version-1 operator profile containing `services`, matching immutable `image_prefixes`, `credential_namespace`, `credentials`, optional `environment_rules` and `compose_template`. Install it with `komizo preview configure --host root@your-server --app mailroom --profile-file ./preview-profile.json`. This root-only operation requires a registered app with drained previews. App CI cannot install or replace it. Templates receive only the preview record, assigned ingress, explicit resource limits and derived private credentials. Generic checks enforce finite admission limits, project-owned volumes/networks, the preview's private `stack.env` and assigned loopback port. Preview records bind the exact profile hash and retain private seeds across rebuilds; changing topology requires draining that app's previews.

Configure preview domains explicitly through the host knob. Komizo supplies no fleet domain or default certificate authorization.
