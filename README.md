# komizo

The `komizo` command: set up a server, add apps to it, and watch what they are
doing.

```sh
go install github.com/nicodes/komizo@latest
komizo root@your-server
```

Or run it without installing anything:

```sh
go run github.com/nicodes/komizo@latest root@your-server
```

That opens the interface. Everything is done from there — the flag-driven
subcommands remain for scripting, but nobody should have to learn them to set a
box up.

No Go? Take a binary from [releases](https://github.com/nicodes/komizo/releases).
It connects to your server as root, so verify it before you run it:

```sh
gh attestation verify komizo_Linux_x86_64.tar.gz --repo nicodes/komizo
```

## What it is

komizo deploys to your own server from GitHub Actions. This repository is the
part that runs on **your machine**: the CLI, and the shell it pipes over SSH.

- [**komizo-be**](https://github.com/nicodes/komizo-be) — the docs, and how the
  whole thing fits together
- [**komizo-actions**](https://github.com/nicodes/komizo-actions) — the GitHub
  Actions a deploying repository uses

## What it does to a server

Three commands, each safe to re-run:

```sh
komizo init  --host root@box      # Docker, the shared network, the agent
komizo proxy --host root@box      # one Caddy, terminating TLS for every app
komizo add   --host root@box ...  # a deploy account and its two privileged commands
```

Very little is installed. Provisioning is still shell piped down the connection
that is already open, run once and thrown away. Reading a box is not: the
inventory, the request counts and the cgroup reads come from `komizo-box`, a
small Go binary that `init` puts on the server and runs on a timer as root.

That is a real trade. The shell arrived fresh on every poll, so a newer `komizo`
read new things off an untouched box; the agent has to be updated to learn
anything new, and `komizo report` will say when one is behind. What it buys is a
box that describes itself once, into a file, so an unprivileged process can read
it — which is what the rest of komizo is built on. See
[design/architecture.md](https://github.com/nicodes/komizo-be/blob/main/design/architecture.md).

Four things live on a server: `komizo-box` and its OpenRC service, the two
per-app scripts, and the shared proxy.

## Layout

```
main.go            the CLI
cmd/komizo-box/    the agent, which runs on the server
internal/app/      the TUI and the subcommands
internal/box/      the probes and the report -- shared by both binaries
internal/agent/    the compiled agents, embedded into the CLI
scripts/           the provisioning shell, embedded with go:embed
```

`internal/box/` is imported by two programs that are **not upgraded together**:
the agent on a server writes a report, and a CLI on a laptop reads one, possibly
months apart. The schema rule is in `report.go` — add fields, never repurpose
one.

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
