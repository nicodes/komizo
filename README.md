# komizo

The `komizo` command: set up a server, add apps to it, and watch what they are
doing.

One command, nothing to install first:

```sh
go run github.com/nicodes/komizo@latest init --host root@your-server
```

komizo carries the server agent inside itself, so that setting up a box needs
nothing from the box but sshd. Those agents are build artifacts and are not in
the module the Go proxy serves — so a `go run` build compiles one on demand,
from the same module at the same version it is itself. Nothing new is fetched
that was not already fetched to get here, and a warm module cache reaches the
network not at all.

**Or take a release binary.** It carries the agents already, so it needs no Go
toolchain. It connects to your server as root, so verify it before you run it:

```sh
gh release download v0.0.17 --repo nicodes/komizo \
  -p 'komizo_Linux_x86_64.tar.gz' -p checksums.txt
sha256sum -c checksums.txt --ignore-missing
gh attestation verify komizo_Linux_x86_64.tar.gz --repo nicodes/komizo
tar xzf komizo_Linux_x86_64.tar.gz && sudo install komizo /usr/local/bin/

komizo init --host root@your-server
```

From a checkout, `make build` compiles the agents first.

Every operation is a command that takes the server as a flag; `komizo` on its
own prints the list. Watching a box — its apps, its charts, its logs — is what
the app is for, and everything the app can do is a command here as well.

## What it is

komizo deploys to your own server from GitHub Actions. This repository is both
halves of the tool: the CLI that runs on **your machine**, and `komizo-box`, the
small agent it installs on **the server**.

- [**komizo-be**](https://github.com/nicodes/komizo-be) — the docs, and how the
  whole thing fits together
- [**komizo-actions**](https://github.com/nicodes/komizo-actions) — the GitHub
  Actions a deploying repository uses

## What it does to a server

Three commands, each safe to re-run:

```sh
komizo init   --host root@box      # Docker, the shared network, the agent
komizo update --host root@box      # re-run all of it, every app included
komizo proxy  --host root@box      # one Caddy, terminating TLS for every app
komizo add    --host root@box ...  # a deploy account and its two privileged commands
```

**Provisioning** is shell, piped down the connection that is already open, run
once and thrown away. It is the half that CHANGES a machine, and it runs as root
exactly as long as it takes.

**Reading** is not. The inventory, the request counts and the cgroup reads come
from `komizo-box` — a 2.6MB Go binary that `init` installs and runs on a timer
as root, writing `/run/komizo/report.json` and nothing else.

That split is the whole design. Root writes a file; something with no privileges
at all reads it. Everything komizo grows next — a dashboard, a phone, alerts —
reads that same file, and none of it needs a way in. See
[design/architecture.md](https://github.com/nicodes/komizo-be/blob/main/design/architecture.md).

The trade is real and worth stating: the old shell arrived fresh on every poll,
so a newer `komizo` read new things off an untouched box. An agent has to be
updated to learn anything new, and `komizo report` says when one is behind.

## Rebuilding a box

A fresh machine is brought back in a fixed order, and every step is safe to
re-run:

```sh
komizo init      --host root@box                          # Docker, network, agent
komizo proxy     --host root@box                          # the shared Caddy
komizo add       --host root@box --app NAME --config REF  # once per app
komizo reconcile --host root@box --inventory expected-apps.json
```

The order matters: `add` needs the network and agent that `init` installs, and
a deploy needs the proxy route. `reconcile` is last and is the proof the
rebuild worked — it reads the box ONCE, compares every registered app and
route against the inventory, and exits nonzero on any missing, unexpected or
mismatched entry. It only ever reads: it provisions nothing, deploys nothing
and rotates no key, so run it as often as you like, as the operator (root)
login. The inventory holds only app names, pinned config-image references and
public hostnames; the schema refuses anything secret- or key-looking, so the
file is safe to commit beside the runbooks.

### The deploy-key and known-hosts handoff

Two values per app have to reach its repository before CI can deploy, and a
rebuild changes exactly one of them:

- **`KOMIZO_DEPLOY_KEY`** (secret) — the app's deploy key. `komizo add`
  generates a fresh pair; on a rebuild where the old key is still in the repo
  and still intended, `komizo add --keep-key` regenerates everything else and
  leaves the account's authorized key alone. The private half is printed once,
  held in memory and written nowhere unless `--key PATH` says so.
- **`KOMIZO_KNOWN_HOSTS`** (variable) — the box's host keys against the names
  this app's CI dials. A rebuilt box has NEW host keys, so this value always
  changes on a rebuild. `komizo report --host root@box --known-hosts` prints
  each app's value without touching the box — reading it costs no rotation.

Both go to the app's repository under Settings → Secrets and variables →
Actions. Values are never written down here, in the inventory, or in any log
komizo keeps.

Four things live on a server: `komizo-box` and its OpenRC service, the two
per-app scripts, and the shared proxy. `komizo update` renews all of them --
including the per-app scripts, which are regenerated from the record komizo
already holds for each app, so no deploy key is rotated, no setting is changed
and an app somebody deliberately stopped stays stopped.

## Layout

```
main.go            the CLI
cmd/komizo-box/    the agent, which runs on the server
internal/app/      the subcommands, and everything they do to a server
box/               the probes and the report -- shared by both binaries AND the service
internal/agent/    the compiled agents, embedded into the CLI
scripts/           the provisioning shell, embedded with go:embed
```

`box/` is imported by three programs that are **not upgraded together**:
the agent on a server writes a report, a CLI on a laptop reads one, and the
komizo service receives them from every box it knows about — possibly months
apart, each on a different version. It is public rather than `internal/` for
that third reader, which is a different module. The schema rule is in
`report.go`: add fields, never repurpose one.

`scripts/` is the half that runs as **root on somebody else's machine**, so it
is tested by being executed against a fake box rather than by being read. See
`internal/app/deploy_script_test.go`.

## Building

```sh
make            # the agents, then the CLI
make check      # what CI runs
```

`make`, not a bare `go build`: the agents are embedded into the CLI, and
`//go:embed` reads the filesystem at build time rather than invoking a compiler,
so they have to exist first. A CLI built without them works for everything
except installing one, and says so.

MIT licensed.
