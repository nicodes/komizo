# Application-private Komizo gateway

Owner-approved replacement for app-private Caddy switching. Shared TLS Caddy
stays in place. Caddy's upstream pool can forget an address while its requests
still run, so it is not used as drain evidence.

## Contract

- Separate traffic and operator-private Unix-socket administration handlers.
- Fixed application scope and compare-and-swap generation parent.
- One mutex covers route admission, generation switching and request accounting.
- Requests admitted before a switch retain their generation until proxying ends;
  HTTP and upgraded connections are not forcibly closed on route swap.
- Positive drain evidence is an inactive generation with zero admitted requests.
  Unknown generations and changed process epochs are not proof of drain.
- Exact hostname routes precede one-label wildcards. Host, URI and query survive.
- Forwarding headers are trusted only from explicit `trusted_proxies` IP prefixes.
  Configure actual TLS-edge addresses; the default rejects spoofable forwarding
  headers and reports the immediate peer instead.

Application jobs, acknowledged input/output and session resumption remain app
responsibilities. Proxy completion cannot prove arbitrary detached work ended.

## Process

```text
komizo gateway --app APP --config /private/state/gateway/config.json \
  --admin-socket /private/admin/gateway.sock --listen :8080 \
  --shutdown-timeout EXPLICIT_DURATION

komizo-box gateway [same flags]
```

`--initialize` creates an empty config only if missing. A real TLS deployment
needs a complete initial configuration with explicitly trusted proxy prefixes.
Run inside the app-private Docker network so candidate names resolve. Only this
gateway joins the edge network. Mount only the routing subdirectory read-only
and a separate admin socket directory; never mount the journal, identity key,
Docker socket or app secrets. Directory ownership must suit the selected UID.

An OS lock prevents duplicate processes from replacing each other's socket.
Stale sockets are removed only after connection refusal; active sockets and
non-socket paths are refused. The admin directory/socket are private.

Controller persists `state-dir/gateway/config.json` before applying routes. A
gateway restart loads desired routes but changes epoch; the controller refuses
to guess whether requests from the previous process drained. Application-level
restart recovery is not established by this gateway alone.

```sh
GOTOOLCHAIN=go1.26.8 go test -race -count=1 -timeout 5m ./internal/gateway
```

Tests cover concurrent admission/swap, old HTTP completion, live upgrades across
swap, stale-parent refusal, application scope and forwarding trust.
