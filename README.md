# komizo

The `komizo` command: set up a server, add apps to it, and watch what they are
doing.

Take a binary from [releases](https://github.com/nicodes/komizo/releases). It
connects to your server as root, so verify it before you run it:

```sh
gh release download v0.0.17 --repo nicodes/komizo \
  -p 'komizo_Linux_x86_64.tar.gz' -p checksums.txt
sha256sum -c checksums.txt --ignore-missing
gh attestation verify komizo_Linux_x86_64.tar.gz --repo nicodes/komizo
tar xzf komizo_Linux_x86_64.tar.gz && sudo install komizo /usr/local/bin/

komizo init --host root@your-server
```

**`go install` does not work, and the reason is not a bug.** komizo carries the
server agent inside itself, so that `komizo init` can set up a box that has
nothing on it but sshd — no network fetch, no second supply chain. Those
binaries are build artifacts: `make agents` builds them and the release workflow
runs it, but they are not committed, so the module the Go proxy serves does not
contain them. `go install github.com/nicodes/komizo@latest` compiles happily and
then cannot install an agent, which leaves a box provisioned and unreadable.

From a checkout it works, because the Makefile builds them first:

```sh
git clone https://github.com/nicodes/komizo && cd komizo
make build
```

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
