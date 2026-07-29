# komizo-cli

The `komizo` command: set up a server, add apps to it, and watch what they are
doing.

```sh
go install github.com/nicodes/komizo-cli/cmd/komizo@latest
komizo root@your-server
```

No Go? Take a binary from [releases](https://github.com/nicodes/komizo-cli/releases).
It connects to your server as root, so verify it before you run it:

```sh
gh attestation verify komizo_Linux_x86_64.tar.gz --repo nicodes/komizo-cli
```

That opens the interface. Everything is done from there — the flag-driven
subcommands remain for scripting, but nobody should have to learn them to set a
box up.

## What it is

komizo deploys to your own server from GitHub Actions. This repository is the
part that runs on **your machine**: the CLI, and the shell it pipes over SSH.

- [**komizo**](https://github.com/nicodes/komizo-be) — the docs, and how the
  whole thing fits together
- [**komizo-actions**](https://github.com/nicodes/komizo-actions) — the GitHub
  Actions a deploying repository uses

## What it does to a server

Three commands, each safe to re-run:

```sh
komizo init  --host root@box      # Docker, the shared network, the sampler
komizo proxy --host root@box      # one Caddy, terminating TLS for every app
komizo add   --host root@box ...  # a deploy account and its two privileged commands
```

Almost nothing is installed. The inventory, the request counts, the cgroup
reads — all of it is shell piped down the connection that is already open, run
once and thrown away, which is why a newer `komizo` reads new things off an old
box without touching it. Only three things actually live on a server: the two
per-app scripts, the resource sampler and its crontab line, and the shared
proxy.

## Layout

```
cmd/komizo/     the binary
internal/app/   everything: the TUI, the subcommands, the parsers
scripts/        the shell that runs on the server, embedded with go:embed
```

`scripts/` is the half that runs as **root on somebody else's machine**, so it
is tested by being executed against a fake box rather than by being read. See
`internal/app/deploy_script_test.go`.

## Building

```sh
go build -o bin/komizo ./cmd/komizo
go test ./...
```

MIT licensed.
