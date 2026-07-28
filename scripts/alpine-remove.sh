#!/bin/sh
# cli/scripts/alpine-remove.sh - tears one app off a server, run as root.
#
# The CLI embeds this and pipes it over SSH. To read it: `komizo script remove`.
#
# It undoes exactly what alpine.sh set up for one app and nothing else.
# Every step targets that app's own name or marker block, so an app sharing the
# box is untouched.
#
# Inputs:
#   APP_NAME   which app to remove                            (required)
#   CI_USER    its deploy account        (default: komizo-<app>)
#   APP_DIR    its directory                 (default: /srv/<app>)
#   KEEP_DATA  1 to leave the directory and its volumes alone (default: 0)

set -eu

APP_NAME="${APP_NAME:-}"
case "$APP_NAME" in
	'') echo "error: APP_NAME is required" >&2; exit 1 ;;
	# Reserved for komizo's own directories, /srv/_proxy among them. Removing one
	# through the app path would take the shared proxy down and leave every other
	# app on the box unreachable.
	_*) echo "error: APP_NAME must not start with '_' -- those names are reserved" >&2; exit 1 ;;
	*[!A-Za-z0-9_-]*) echo "error: APP_NAME must be letters, digits, underscore or hyphen" >&2; exit 1 ;;
esac

CI_USER="${CI_USER:-komizo-$APP_NAME}"
APP_DIR="${APP_DIR:-/srv/$APP_NAME}"
KEEP_DATA="${KEEP_DATA:-0}"
DEPLOY_BIN="/usr/local/bin/deploy-$APP_NAME"
SECRET_BIN="/usr/local/bin/set-secret-$APP_NAME"
PROJECT_MARKERS='(komizo|ncicd|cicd|alpine-server-scripts|boot\.sh)'
PROXY_CONTAINER=komizo-caddy

log() { printf '\n==> %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "error: must run as root" >&2; exit 1; }

# Nothing here fails the run if it is already absent: removal has to be safe to
# repeat, including after a previous attempt died half way.

# --- 1. the running stack --------------------------------------------------

if [ "$KEEP_DATA" = "1" ]; then
	log "Stopping containers (keeping $APP_DIR and its volumes)"
	volflag=""
else
	log "Stopping containers and removing volumes"
	volflag="--volumes"
fi

if [ -f "$APP_DIR/compose.yml" ] && command -v docker >/dev/null 2>&1; then
	# --remove-orphans as well, so a service dropped from compose.yml in an
	# earlier deploy does not survive the teardown.
	docker compose -f "$APP_DIR/compose.yml" --project-directory "$APP_DIR" \
		down --remove-orphans $volflag >/dev/null 2>&1 || true
fi

# --- 1b. the reverse-proxy route -------------------------------------------
# Done here, immediately after the containers stop, and done even with
# KEEP_DATA=1. The shared Caddy imports /srv/*/caddy/app.caddy, so a route left
# behind keeps advertising a hostname whose containers are gone -- the domain
# would answer with a 502 instead of going quiet, and Caddy would keep renewing
# a certificate for it forever.

if [ -d "$APP_DIR/caddy" ]; then
	log "Removing the reverse-proxy route for '$APP_NAME'"
	rm -rf "$APP_DIR/caddy"
	# The hostname list beside it, so nothing on the box still records this app
	# as the owner of those names -- another app claiming one must not be told
	# it collides with an app that is gone.
	rm -f "$APP_DIR/hostnames"
	if command -v docker >/dev/null 2>&1 &&
		docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$PROXY_CONTAINER"; then
		if docker exec "$PROXY_CONTAINER" caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then
			log "Reverse proxy reloaded"
		else
			echo "warning: the proxy would not reload; it may still be serving '$APP_NAME'" >&2
		fi
	fi
fi

# --- 2. the privileged commands and their doas rules -----------------------
# Rules go BEFORE the scripts: if this run dies in between, the account is left
# unable to invoke something that no longer exists, rather than able to invoke
# something unexpected that later takes its path.

log "Removing doas rules for '$CI_USER'"
if [ -f /etc/doas.conf ]; then
	cp /etc/doas.conf /etc/doas.conf.bak.remove
	sed -i -E "/^# $PROJECT_MARKERS: $CI_USER BEGIN\$/,/^# $PROJECT_MARKERS: $CI_USER END\$/d" /etc/doas.conf
	if ! doas -C /etc/doas.conf >/dev/null 2>&1; then
		mv /etc/doas.conf.bak.remove /etc/doas.conf
		echo "error: removing the doas rules left an invalid config -- reverted" >&2
		exit 1
	fi
	rm -f /etc/doas.conf.bak.remove
fi

log "Removing $DEPLOY_BIN and $SECRET_BIN"
rm -f "$DEPLOY_BIN" "$SECRET_BIN"

# --- 3. sshd ---------------------------------------------------------------

log "Removing the sshd restrictions for '$CI_USER'"
conf=/etc/ssh/sshd_config
if [ -f "$conf" ]; then
	cp "$conf" "$conf.bak.remove"
	sed -i -E \
		-e "/^# $PROJECT_MARKERS: sshd $CI_USER BEGIN\$/,/^# $PROJECT_MARKERS: sshd $CI_USER END\$/d" \
		"$conf"
	if sshd -t >/dev/null 2>&1; then
		rm -f "$conf.bak.remove"
		rc-service sshd reload >/dev/null 2>&1 || rc-service sshd restart >/dev/null 2>&1 || true
	else
		mv "$conf.bak.remove" "$conf"
		echo "error: removing the sshd block left an invalid config -- reverted" >&2
		exit 1
	fi
fi

# --- 4. the account --------------------------------------------------------

if id "$CI_USER" >/dev/null 2>&1; then
	log "Removing user '$CI_USER'"
	deluser --remove-home "$CI_USER" >/dev/null 2>&1 || deluser "$CI_USER" >/dev/null 2>&1 || true
fi

# --- 5. the directory ------------------------------------------------------

if [ "$KEEP_DATA" = "1" ]; then
	log "Keeping $APP_DIR"
else
	log "Removing $APP_DIR"
	# Guard against a mis-set APP_DIR taking something else with it.
	case "$APP_DIR" in
		/|/etc|/usr|/var|/home|/root|/srv) echo "error: refusing to remove $APP_DIR" >&2; exit 1 ;;
		# The shared proxy lives under /srv too, and taking it out through the
		# app path would make every other app on the box unreachable.
		/srv/_*) echo "error: refusing to remove $APP_DIR -- it belongs to komizo, not an app" >&2; exit 1 ;;
	esac
	rm -rf "$APP_DIR"
fi

log "Removed '$APP_NAME'"
cat <<EOF

  Its images are still in your registry, and the deploy key on your machine
  still exists. Delete KOMIZO_DEPLOY_KEY from the repo's secrets if the app is
  gone for good.
EOF
