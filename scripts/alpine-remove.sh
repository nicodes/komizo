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

# What komizo recorded when this app was set up. Read FIRST, so an app given a
# custom account or directory is removed by its real values rather than by the
# defaults -- removing by the default left a stray account and a live doas rule
# behind for exactly the apps that had been set up most deliberately.
STATE_DIR=/var/lib/komizo/apps
STATE_FILE="$STATE_DIR/$APP_NAME.env"
# Either name, and this is what keeps a removal safe to REPEAT.
#
# Step 1c below renames the record to "$STATE_FILE.removing" so that a run which
# dies from there on leaves nothing `komizo update` will reprovision (see the
# long note there). Reading only the live name would have paid for that with the
# property the block above this exists for: a second `komizo remove`, after an
# interrupted first, would find no record, fall back to komizo-<app> and
# /srv/<app>, and quietly leave the real account and the real directory of any
# app set up with a custom --user or --app-dir -- which is precisely the apps
# that were set up most deliberately. So the renamed record is still read, by
# the one thing that has any business reading it.
state() {
	for _f in "$STATE_FILE" "$STATE_FILE.removing"; do
		[ -f "$_f" ] || continue
		sed -n "s/^$1=//p" "$_f" | head -n 1
		return 0
	done
	return 0
}

CI_USER="${CI_USER:-$(state CI_USER)}"
CI_USER="${CI_USER:-komizo-$APP_NAME}"
# Used as a sed -E pattern and in `rm`/`deluser`; constrain it (a dot is a regex
# metacharacter, a newline could target another account's block).
case "$CI_USER" in
	''|*[!A-Za-z0-9_-]*) echo "error: CI_USER must be letters, digits, underscore or hyphen" >&2; exit 1 ;;
esac
APP_DIR="${APP_DIR:-$(state APP_DIR)}"
APP_DIR="${APP_DIR:-/srv/$APP_NAME}"

# The one irreversible flag, so it fails safe: anything but an explicit "keep"
# deletes, and a typo (KEEP_DATA=ture) errors rather than silently wiping data.
KEEP_DATA="${KEEP_DATA:-0}"
case "$KEEP_DATA" in
	1|yes|true) KEEP_DATA=1 ;;
	0|no|false|'') KEEP_DATA=0 ;;
	*) echo "error: KEEP_DATA must be 0 or 1" >&2; exit 1 ;;
esac
DEPLOY_BIN="/usr/local/bin/deploy-$APP_NAME"
SECRET_BIN="/usr/local/bin/set-secret-$APP_NAME"
PROJECT_MARKER=komizo
PROXY_CONTAINER=komizo-proxy
ROUTE_FILE="/srv/_proxy/routes/$APP_NAME.caddy"

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
# KEEP_DATA=1. The shared Caddy imports every file in its routes directory, so
# a route left behind keeps advertising a hostname whose containers are gone --
# the domain would answer with a 502 instead of going quiet, and Caddy would
# keep renewing a certificate for it forever.

if [ -f "$ROUTE_FILE" ]; then
	log "Removing the reverse-proxy route for '$APP_NAME'"
	rm -f "$ROUTE_FILE" "$ROUTE_FILE.prev"
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

# --- 1c. stop calling it an app --------------------------------------------
#
# THE RECORD IS MADE INERT HERE, and only deleted at the end.
#
# Everything above reads it, which is why it used to be removed last -- but
# "removed last" also means a removal that dies half way leaves a complete
# record behind for an app that no longer has containers, an account, or a
# directory. That was survivable while nothing acted on a record by itself:
# `komizo remove` is safe to repeat, and the inventory showing a ghost row was
# the whole of the damage.
#
# komizo#58 changed what a leftover record means. `komizo update` now re-runs
# the app setup script for every record in this directory, and that script
# CREATES what is missing: the deploy account, the directory, the two
# privileged scripts, the doas rules and the sshd block. So a removal
# interrupted by a dropped connection or a Ctrl-C, followed at any later date
# by a routine upgrade, would put the removed app's whole deploy path back --
# on its original key, with nothing on the box's report to show for it, until
# that repo's next merge to main deployed an app somebody had decommissioned.
#
# HERE AND NOT AT THE TOP, which is a trade rather than an oversight. A record
# renamed away is invisible to everything: no row on the report, no app_down,
# no per-app command resolves it. Steps 1 and 1b only STOP things -- and they
# are the slow, interruption-prone part, `docker compose down` over a large
# stack plus a proxy reload -- so a record left live across them describes an
# app that still fully exists, and a refresh over one is a no-op reprovision
# rather than a resurrection. Nothing komizo would put back has been deleted
# until step 2. So the app stays visible for exactly as long as it is still
# really there, and goes inert the moment that stops being true.
#
# Renaming rather than deleting keeps this removal safe to repeat: state()
# above reads either name, so a second run still finds an app's real account
# and directory. The suffix goes AFTER .env for the reason alpine.sh's
# STATE_TMP does -- everything that enumerates apps globs *.env, so this name
# is invisible to all of them. A run that dies from here on leaves a stray file
# rather than an app anything will act on.
#
# NOT `|| true`. Everything else in this script tolerates its target being
# absent, because everything else is cleanup. This one is a guard: if the
# rename does not happen and the removal carries on to delete the account and
# the directory, the window above is silently open again. It is very hard to
# fail as root inside a directory root owns, which is the argument for letting
# it say so rather than for swallowing it.
if [ -f "$STATE_FILE" ]; then
	log "Setting $STATE_FILE aside"
	mv -f "$STATE_FILE" "$STATE_FILE.removing" || {
		echo "error: could not set $STATE_FILE aside, so a removal interrupted from here" >&2
		echo "       would leave an app that 'komizo update' puts back -- refusing to go on" >&2
		exit 1
	}
fi

# --- 2. the privileged commands and their doas rules -----------------------
# Rules go BEFORE the scripts: if this run dies in between, the account is left
# unable to invoke something that no longer exists, rather than able to invoke
# something unexpected that later takes its path.

# One backup suffix across every script that edits a file in /etc: ".komizo.bak"
# beside the file. There were three conventions before this -- ".komizo.bak" for
# sshd_config in alpine.sh, ".bak.remove" for both files here -- so a stray
# backup left by a killed run was not obviously komizo's, and no two of them
# could be cleaned by one rule. alpine.sh appends its own PID after that prefix,
# because komizo#58 made two of its runs at once ordinary and a shared name
# means the second one restores the first one's edits; the prefix is still the
# thing to look for. Each is guarded by a trap, so an interrupted run
# puts the file back rather than leaving a half-edit and a copy beside it.
log "Removing doas rules for '$CI_USER'"
if [ -f /etc/doas.conf ]; then
	doas_bak=/etc/doas.conf.komizo.bak
	cp /etc/doas.conf "$doas_bak"
	# EXIT ALONE DOES NOT FIRE ON THE SIGNALS THAT ACTUALLY ARRIVE, and a
	# handler that only tidies does not stop -- komizo#64, and the third place
	# in this codebase with the same defect after alpine.sh's doas and sshd
	# windows.
	#
	# POSIX sh RESUMES at the interruption point when a handler returns, so a
	# trap that restores and returns carries on removing an app the operator
	# just cancelled. And EXIT is not raised at all by HUP or PIPE, which is how
	# a dropped ssh connection arrives -- directly, or at the next write to a
	# stdout with nothing on the other end. Measured under busybox ash on the
	# sibling case: HUP left no cleanup, TERM cleaned up and then ran to the
	# end, PIPE left no cleanup.
	#
	# So the window this guard exists for -- /etc/doas.conf mid-edit, on
	# somebody's server -- was open on exactly the interruptions most likely to
	# happen. The paired form restores AND stops, and `exit` from a signal
	# handler runs the EXIT trap too, so the restore is written once.
	restore_doas() { mv -f "$doas_bak" /etc/doas.conf 2>/dev/null || true; }
	trap restore_doas EXIT
	trap 'restore_doas; exit 129' INT TERM HUP PIPE
	sed -i -E "/^# $PROJECT_MARKER: $CI_USER BEGIN\$/,/^# $PROJECT_MARKER: $CI_USER END\$/d" /etc/doas.conf
	if ! doas -C /etc/doas.conf >/dev/null 2>&1; then
		mv -f "$doas_bak" /etc/doas.conf
		trap - EXIT INT TERM HUP PIPE
		echo "error: removing the doas rules left an invalid config -- reverted" >&2
		exit 1
	fi
	trap - EXIT INT TERM HUP PIPE
	rm -f "$doas_bak"
fi

log "Removing $DEPLOY_BIN and $SECRET_BIN"
rm -f "$DEPLOY_BIN" "$SECRET_BIN"

# --- 3. sshd ---------------------------------------------------------------

log "Removing the sshd restrictions for '$CI_USER'"
conf=/etc/ssh/sshd_config
if [ -f "$conf" ]; then
	conf_bak="$conf.komizo.bak"
	cp "$conf" "$conf_bak"
	# The same pairing as the doas window above, and for the same reason: an
	# sshd_config left mid-edit does not bite now -- sshd has not been reloaded
	# -- it bites at the next reboot, a long way from anything anyone would
	# connect it to.
	restore_sshd() { mv -f "$conf_bak" "$conf" 2>/dev/null || true; }
	trap restore_sshd EXIT
	trap 'restore_sshd; exit 129' INT TERM HUP PIPE
	sed -i -E \
		-e "/^# $PROJECT_MARKER: sshd $CI_USER BEGIN\$/,/^# $PROJECT_MARKER: sshd $CI_USER END\$/d" \
		"$conf"
	if sshd -t >/dev/null 2>&1; then
		trap - EXIT INT TERM HUP PIPE
		rm -f "$conf_bak"
		rc-service sshd reload >/dev/null 2>&1 || rc-service sshd restart >/dev/null 2>&1 || true
	else
		mv -f "$conf_bak" "$conf"
		trap - EXIT INT TERM HUP PIPE
		echo "error: removing the sshd block left an invalid config -- reverted" >&2
		exit 1
	fi
fi

# --- 4. the account --------------------------------------------------------

if id "$CI_USER" >/dev/null 2>&1; then
	log "Removing user '$CI_USER'"
	deluser --remove-home "$CI_USER" >/dev/null 2>&1 || deluser "$CI_USER" >/dev/null 2>&1 || true
fi

# The key list lives outside the home directory -- root's, not the account's --
# so removing the home does not take it with it. A file left here would
# authorise a key for an account that no longer exists, and would silently
# authorise it again the moment a future app reused the name.
rm -f "/etc/ssh/authorized_keys.d/$CI_USER"

# --- 5. the directory ------------------------------------------------------

if [ "$KEEP_DATA" = "1" ]; then
	log "Keeping $APP_DIR"
else
	log "Removing $APP_DIR"
	# Guard against a mis-set APP_DIR taking something else with it. Normalise
	# first, then refuse anything that is not plausibly an app directory.
	case "$APP_DIR" in
		*[!A-Za-z0-9./_-]*) echo "error: refusing to remove APP_DIR with unexpected characters: $APP_DIR" >&2; exit 1 ;;
		*..*) echo "error: refusing to remove APP_DIR containing '..': $APP_DIR" >&2; exit 1 ;;
	esac
	# Strip trailing slashes so "/etc/" cannot dodge the literal-path list below.
	while [ "${APP_DIR%/}" != "$APP_DIR" ] && [ -n "${APP_DIR%/}" ]; do APP_DIR="${APP_DIR%/}"; done
	case "$APP_DIR" in
		# Top-level and known-sensitive directories: never.
		/|/etc|/etc/ssh|/usr|/usr/local|/var|/var/lib|/home|/root|/root/.ssh|/srv|/boot) echo "error: refusing to remove $APP_DIR" >&2; exit 1 ;;
		# Must be at least two components deep -- a bare "/foo" is almost certainly
		# a mistake, and no komizo app lives there.
		/*/*) ;;
		*) echo "error: refusing to remove a top-level directory: $APP_DIR" >&2; exit 1 ;;
	esac
	case "$APP_DIR" in
		# The shared proxy lives under /srv too, and taking it out through the
		# app path would make every other app on the box unreachable.
		/srv/_*) echo "error: refusing to remove $APP_DIR -- it belongs to komizo, not an app" >&2; exit 1 ;;
	esac
	rm -rf "$APP_DIR"
fi

# --- 6. what komizo knew about it ------------------------------------------
# Last, because everything above reads it. Removing this is what makes the app
# gone as far as the inventory is concerned.
#
# BOTH NAMES. The record was renamed out of the way at step 1c so that a run
# which dies part way through leaves nothing `komizo update` will reprovision;
# the original name is removed too, because a run interrupted before 1c's
# rename -- or an older komizo's removal that never renamed at all -- can still
# have left one there.

rm -f "$STATE_FILE" "$STATE_FILE.removing"

log "Removed '$APP_NAME'"
cat <<EOF

  Its images are still in your registry, and the deploy key on your machine
  still exists. Delete KOMIZO_DEPLOY_KEY from the repo's secrets if the app is
  gone for good.
EOF
