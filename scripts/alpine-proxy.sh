#!/bin/sh
# cli/scripts/alpine-proxy.sh - installs the one shared reverse proxy, as root.
#
# komizo embeds this and pipes it over SSH. To read it: `komizo script proxy`.
#
# One Caddy container per server terminates TLS and owns ports 80 and 443.
# It holds NO per-app configuration of its own. Its Caddyfile is three lines
# and never changes:
#
#     import /srv/*/caddy/app.caddy
#
# Each app ships its own fragment inside its own config image, and deploy-<app>
# extracts it to /srv/<app>/caddy/. So adding, changing or removing an app never
# edits anything shared -- which is the property that lets apps stay independent
# on a box they share.
#
# Deliberately NOT label-based discovery (caddy-docker-proxy): that needs the
# docker socket inside the container listening on the public internet, and the
# socket is root. This design gives the proxy no privileges at all -- it reads
# /srv read-only and cannot talk to the daemon.
#
# Safe to re-run: that is how you update Caddy or move it to another network.
#
# Certificates need no configuration at all. Caddy agrees to the CA's terms
# when it runs non-interactively, and there is deliberately no contact address
# to set: Let's Encrypt stopped sending expiry notices in June 2025, so an email
# here would buy nothing but a field to fill in.
#
# Inputs, all environment variables:
#   SHARED_NETWORK docker network apps join                 (default: edge)
#   PROXY_IMAGE    caddy image to run                       (default: caddy:2)

set -eu

SHARED_NETWORK="${SHARED_NETWORK:-edge}"
PROXY_IMAGE="${PROXY_IMAGE:-caddy:2}"

# Under /srv so the same import glob covers the proxy's own catch-all fragment,
# which means there is exactly one rule about where fragments live rather than
# two. (An import glob matching nothing is not an error, so this is for
# consistency, not to keep Caddy happy.)
#
# The leading underscore is reserved: komizo refuses to create an app whose name
# starts with one, so this can never collide with /srv/<app>.
PROXY_DIR=/srv/_proxy
# Compose project names must start with a letter or digit, so the project cannot
# simply be named after the directory. Fixed rather than derived so the deploy
# and remove scripts can address the container without discovering it.
PROXY_PROJECT=komizo-proxy
PROXY_CONTAINER=komizo-caddy

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root"

case "$SHARED_NETWORK" in
	''|*[!A-Za-z0-9._-]*) die "SHARED_NETWORK must be letters, digits, dot, underscore or hyphen" ;;
esac
case "$PROXY_IMAGE" in
	*[!A-Za-z0-9.:/_-]*) die "PROXY_IMAGE contains characters that are not valid in an image reference" ;;
esac
command -v docker >/dev/null 2>&1 || die "this server is not set up yet -- run 'komizo init' first"

# --- 1. the shared network -------------------------------------------------
# Created here rather than by compose so it outlives any single project, and so
# an app can join it as `external: true` before the proxy is ever started.

if docker network inspect "$SHARED_NETWORK" >/dev/null 2>&1; then
	log "Shared network '$SHARED_NETWORK' already exists"
else
	log "Creating shared network '$SHARED_NETWORK'"
	docker network create "$SHARED_NETWORK" >/dev/null
fi

# --- 2. the Caddyfile ------------------------------------------------------

log "Writing $PROXY_DIR/Caddyfile"
mkdir -p "$PROXY_DIR/caddy"
chown root:root "$PROXY_DIR" "$PROXY_DIR/caddy"
chmod 755 "$PROXY_DIR" "$PROXY_DIR/caddy"

{
	printf '# Every app writes its own fragment here. Nothing in this file names\n'
	printf '# an app, so adding or removing one never edits shared config.\n'
	printf '#\n'
	printf '# One wildcard, and the filename is fixed: Caddy rejects an import glob\n'
	printf '# with more than one "*", so /srv/*/caddy/*.caddy is not available.\n'
	printf '# deploy-<app> concatenates whatever the config image ships into this\n'
	printf '# single file, so an app can still author several.\n'
	printf 'import /srv/*/caddy/app.caddy\n'
} > "$PROXY_DIR/Caddyfile"
chown root:root "$PROXY_DIR/Caddyfile"
chmod 644 "$PROXY_DIR/Caddyfile"

# A catch-all for hostnames that resolve here but have no app behind them: they
# get a plain 404 instead of whichever app Caddy happens to list first.
#
# It lives at the same path an app's fragment would, because $PROXY_DIR is
# itself under /srv and so is covered by the same import glob. Caddy matches the
# most specific site address regardless of file order, so a bare ":80" here
# never shadows a real app's hostname.
cat > "$PROXY_DIR/caddy/app.caddy" <<'EOF'
# Written by komizo. Requests for a hostname with no app behind it land here.
:80 {
	respond "no app is configured for this hostname" 404
}
EOF
chown root:root "$PROXY_DIR/caddy/app.caddy"
chmod 644 "$PROXY_DIR/caddy/app.caddy"

# --- 3. the container ------------------------------------------------------

log "Writing $PROXY_DIR/compose.yml"
cat > "$PROXY_DIR/compose.yml" <<EOF
# Written by komizo. Re-run 'komizo proxy' to change it; edits here are lost.
services:
  caddy:
    image: $PROXY_IMAGE
    container_name: $PROXY_CONTAINER
    restart: unless-stopped
    # The only container on this box that publishes a port. Apps are reached
    # over the '$SHARED_NETWORK' network by name, so they publish nothing.
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    volumes:
      - $PROXY_DIR/Caddyfile:/etc/caddy/Caddyfile:ro
      # Read-only, and the whole of /srv rather than each app in turn: the
      # import glob is resolved inside the container, so the paths have to
      # match the host's. Read-only means a compromised proxy cannot write an
      # app's compose.yml, which would be equivalent to root.
      - /srv:/srv:ro
      # ACME account key and issued certificates. Losing this volume means
      # every certificate is re-issued, and Let's Encrypt rate limits are per
      # domain per week -- so it is the one volume on the box worth backing up.
      - caddy_data:/data
      - caddy_config:/config
    networks:
      - shared

volumes:
  caddy_data:
  caddy_config:

networks:
  shared:
    external: true
    name: $SHARED_NETWORK
EOF
chown root:root "$PROXY_DIR/compose.yml"
chmod 644 "$PROXY_DIR/compose.yml"

log "Starting the proxy"
cd "$PROXY_DIR"
docker compose -p "$PROXY_PROJECT" config -q \
	|| die "the generated proxy compose.yml is not valid -- nothing was started"
docker compose -p "$PROXY_PROJECT" up -d

# Report what Caddy made of it. A fragment that fails to parse keeps the proxy
# on its previous config rather than taking the site down, so a silent failure
# here would otherwise look like a working deploy.
if ! docker exec "$PROXY_CONTAINER" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then
	printf '\n'
	printf 'warning: Caddy is running, but the combined config does not validate.\n' >&2
	printf 'One of the app fragments under /srv/*/caddy/app.caddy is malformed:\n' >&2
	docker exec "$PROXY_CONTAINER" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1 | sed 's/^/  /' >&2 || true
fi

log "Done"
cat <<EOF

  proxy:    $PROXY_CONTAINER ($PROXY_IMAGE)
  dir:      $PROXY_DIR (root-owned)
  network:  $SHARED_NETWORK
  certs:    ${PROXY_PROJECT}_caddy_data (docker volume -- back this up)

EOF

cat <<EOF
For an app to be reachable through it, that app's compose.yml must join the
'$SHARED_NETWORK' network with a UNIQUE alias, and publish no ports of its own:

  services:
    web:
      networks:
        shared:
          aliases: [myapp-web]      # unique across every app on this box
        default: {}
  networks:
    shared:
      external: true
      name: $SHARED_NETWORK

The alias must be unique because compose gives every service a network alias
equal to its service name. Two apps that both call a service 'web' would both
answer to 'web' here, and traffic would be split between them at random.

Then ship a fragment at caddy/<anything>.caddy in the app's config image:

  myapp.example.com {
      reverse_proxy myapp-web:3000
  }

It is extracted, validated and loaded on every deploy, and rolls back with the
app because it lives in the same versioned config image.
EOF
