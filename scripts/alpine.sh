#!/bin/sh
# cli/scripts/alpine.sh - sets one app up on a server, run as root on the box.
#
# komizo embeds this file and pipes it over SSH; you do not normally run it
# yourself. To read what will run as root on your server:
#
#   komizo script           # prints this file
#
# To run it by hand from the server's own console:
#
#   CI_PUBKEY="ssh-ed25519 AAAA... deploy@myapp" \
#     CONFIG_IMAGE=ghcr.io/you/myapp-config \
#     APP_NAME=myapp \
#     sh alpine.sh
#
# You then have to capture the host key yourself, which is the part the CLI
# exists to get right.
#
# One script per distro lives in cli/scripts/. This one assumes apk, OpenRC
# and doas.
# Everything here is POSIX sh: Alpine's /bin/sh is busybox ash.
#
# Inputs, all environment variables:
#   CI_PUBKEY      deploy PUBLIC key                              (required)
#   CONFIG_IMAGE   registry path, no tag, carrying compose.yml    (required)
#   APP_NAME       which app on this box                          (default: app)
#   CI_USER        deploy account        (default: komizo-<app>)
#   APP_DIR        root-owned app directory                (default: /srv/<app>)
#   TASKS          1 when this app has a task script installed  (recorded)
#   TASKS_SET      1 when TASKS is an explicit edit; otherwise keep recorded
#   TASK_SCRIPT_B64  the app's task script, base64, from --task-script
#                  (optional; absent reinstalls whatever the box stored)
#   SCOPED_ENV     fixed scoped-env profile; fields-postgres-v2 only, and
#                  only for app fieldsofrevik                         (optional)
#   SCOPED_ENV_SET 1 when SCOPED_ENV is an explicit edit; otherwise keep
#                  the recorded profile
#   KNOWN_AS       names CI dials this app by, comma-separated    (kept if unset)
#   CLEAR_KNOWN_AS 1 to record that there are none                (default: 0)
#   HARDEN_SSH     1 to also harden sshd machine-wide             (default: 0)
#
# The server must already be initialised (alpine-init.sh) -- this script does
# not install Docker. Setting a server up and adding an app to it are separate
# things, so that a fresh box has a state you can name rather than becoming
# half-configured as a side effect of the first app.

set -eu

# One box can host several apps. Everything that could collide between them --
# the directory, the two privileged scripts, the deploy account, the doas rules
# -- is named after the app, so bootstrapping a second one cannot disturb the
# first.
APP_NAME="${APP_NAME:-}"
case "$APP_NAME" in
	'') echo "error: APP_NAME is required" >&2; exit 1 ;;
	# A leading underscore is reserved for komizo's own directories under /srv,
	# starting with /srv/_proxy. Refusing it here means an app can never collide
	# with one, and the inventory can tell them apart by name alone.
	_*) echo "error: APP_NAME must not start with '_' -- those names are reserved" >&2; exit 1 ;;
	*[!A-Za-z0-9_-]*) echo "error: APP_NAME must be letters, digits, underscore or hyphen" >&2; exit 1 ;;
esac

# Every app is named, always -- there is no unsuffixed "the app" special case.
# A box set up for one app can host a second later without renaming anything
# that already exists, which is not true if the first one owns the bare paths.
#
# One account per app, so a key that leaks reaches only its own app. That is a
# rule, not a default: an explicit CI_USER naming another app's account is
# REFUSED below, once STATE_DIR is known.
CI_USER="${CI_USER:-komizo-$APP_NAME}"
# Validated here, not only in the CLI: this script is documented as hand-runnable
# with env vars, and CI_USER is written verbatim into doas.conf and an sshd Match
# block, and used as a sed -E pattern below. A newline would inject a doas rule
# (full root); a dot is a regex metacharacter that could match another account's
# marker block. Letters, digits, underscore and hyphen is all a deploy account
# needs. Also refuse root and any UID-0 account: setting it up would point sshd
# at a key list holding only the deploy key, turning that key into a root login.
case "$CI_USER" in
	''|*[!A-Za-z0-9_-]*) echo "error: CI_USER must be letters, digits, underscore or hyphen" >&2; exit 1 ;;
	root) echo "error: CI_USER must not be root -- the deploy account is a separate, unprivileged user" >&2; exit 1 ;;
esac
DEPLOY_BIN="/usr/local/bin/deploy-$APP_NAME"
PRUNE_BIN="/usr/local/bin/prune-$APP_NAME"
SECRET_BIN="/usr/local/bin/set-secret-$APP_NAME"
TASK_BIN="/usr/local/bin/task-$APP_NAME"
PROVISION_BIN="/usr/local/bin/provision-scoped-env-$APP_NAME"
STATUS_BIN="/usr/local/bin/scoped-env-status-$APP_NAME"
# The old setter path. Removed on install and remove so a stale doas grant
# cannot be pointed at a binary that provisions.
SCOPED_BIN="/usr/local/bin/set-scoped-env-$APP_NAME"

APP_DIR="${APP_DIR:-/srv/$APP_NAME}"

# Where komizo records what it knows about an app, as data rather than as code.
#
# Everything that needs an app's directory or its config image -- the inventory,
# the agent, a key rotation, the deploy script -- reads THIS. It used
# to sed the values back out of the generated deploy script, which meant five
# readers were parsing komizo's own output as a database and a change to the
# generator's formatting would break all of them at once.
STATE_DIR=/var/lib/komizo/apps
STATE_FILE="$STATE_DIR/$APP_NAME.env"

# A deploy account belongs to ONE app, and this is where that is enforced.
#
# Sharing was never really possible, it just looked like it. Everything this
# script writes for the account is keyed by the account NAME and replaced whole
# on each run: the doas block (which names one app's two privileged scripts),
# the sshd Match block, and $KEYS_DIR/$CI_USER. So a second app claiming an
# existing account does not join it -- it takes it. The first app's CI keeps a
# key that no longer opens anything and doas rules that are gone, and the second
# app's key now reaches an app it was never issued for. Both halves of "one
# account per app, so a leaked key reaches only its own app" fail at once.
#
# Refuse, and name the app that already holds it. The way out is a different
# account for THIS app, which the rename path below handles.
# What this app's record already says, read the same way every other reader
# reads it. An account this app ALREADY holds is established state, not a new
# claim: refusing it would make `komizo update` fail on every app of a box set
# up before this rule, which is a working box broken by a rule about new ones.
_mine="$(sed -n 's/^CI_USER=//p' "$STATE_FILE" 2>/dev/null | tr -d '\r' | head -n 1)"

for _st in "$STATE_DIR"/*.env; do
	[ -f "$_st" ] || continue                  # no records yet: the glob is literal
	_a="${_st##*/}"; _a="${_a%.env}"
	[ "$_a" = "$APP_NAME" ] && continue         # this app's own record
	# A record that cannot be READ is not a record that says no clash. Refuse
	# rather than provision: the whole value of this check is knowing which
	# accounts are taken, and an unreadable file is the one case where komizo
	# does not know.
	if [ ! -r "$_st" ]; then
		echo "error: cannot read $_st, so komizo cannot tell whether '$CI_USER' is another app's account" >&2
		exit 1
	fi
	[ "$(sed -n 's/^CI_USER=//p' "$_st" | tr -d '\r' | head -n 1)" = "$CI_USER" ] || continue

	# Already shared, from before this refusal existed. Say so on every run --
	# loudly, because it is a real weakness and a silent one -- but do not break
	# a box that is working today.
	if [ "$_mine" = "$CI_USER" ]; then
		echo "warning: apps '$APP_NAME' and '$_a' share the deploy account '$CI_USER'." >&2
		echo "  a key that leaks reaches both. komizo no longer sets this up." >&2
		echo "  to separate them, re-add one of the apps with an account of its own:" >&2
		echo "    komizo add --app $APP_NAME --user komizo-$APP_NAME ..." >&2
		continue
	fi

	echo "error: deploy account '$CI_USER' already belongs to app '$_a'" >&2
	echo "  each app needs its own, so a key that leaks reaches only one app." >&2
	echo "  give this app an account of its own: komizo add --user komizo-$APP_NAME ..." >&2
	exit 1
done

# If this app was previously set up under a DIFFERENT deploy account, that old
# account's key file, doas rule and sshd Match block would otherwise be orphaned
# -- an invisible, still-privileged account that a key rotation never touches.
# Note it now, before the state file is rewritten below, and remove it further
# down. Skipped when another app is still recorded against that old account,
# since removing it would break that app. New sharing is refused above, but a
# box set up before that refusal existed can still be in this state -- and this
# is the path that migrates it: give one of the apps its own account, and the
# one left behind keeps working.
# Every read of a record's CI_USER strips CR, here and above, because these two
# comparisons DECIDE OPPOSITE THINGS from the same bytes: the one above refuses
# a clash, and the one below deletes an account when it finds none. Strip in one
# and not the other and a single stray CR -- a record edited on Windows, a
# hand-written file -- makes this path conclude the old account is unused and
# `deluser` an account another app is deploying under right now.
OLD_CI_USER=""
_old="$_mine"
case "$_old" in
	''|"$CI_USER") ;;                     # nothing recorded, or unchanged
	*[!A-Za-z0-9_-]*) ;;                  # legacy/unreadable value -- leave it be
	*)
		OLD_CI_USER="$_old"
		for _st in "$STATE_DIR"/*.env; do
			[ -f "$_st" ] || continue
			_a="${_st##*/}"; _a="${_a%.env}"
			[ "$_a" = "$APP_NAME" ] && continue
			if [ "$(sed -n 's/^CI_USER=//p' "$_st" | tr -d '\r' | head -n 1)" = "$OLD_CI_USER" ]; then
				OLD_CI_USER=""   # still in use by another app; do not touch it
				break
			fi
		done
		;;
esac

# The deploy account's key list, OUTSIDE its home directory.
#
# This is the difference between a rotation that evicts and one that does not.
# When the file lived in ~/.ssh the account owned it, so anyone holding a leaked
# key could log in and append a second one -- and rotation, which replaces the
# key komizo knows about, would then remove the legitimate key and leave the
# attacker's. Root owns the directory and the file; the account cannot write
# either, and cannot pre-create anything in the path root writes through.
KEYS_DIR=/etc/ssh/authorized_keys.d
KEYS_FILE="$KEYS_DIR/$CI_USER"

# Config we write into /etc is tagged with a marker so a re-run can find and
# replace its own block.
PROJECT_MARKER=komizo
# Must match alpine-proxy.sh. Fixed rather than discovered so the generated
# deploy script can address the proxy without searching for it.
PROXY_CONTAINER=komizo-proxy
# Where the generated reverse-proxy routes live: with the PROXY, not with the
# app. The proxy container mounts this one directory and nothing else, so it
# can no longer read every app's secrets.env through a /srv bind mount.
PROXY_DIR=/srv/_proxy
ROUTES_DIR="$PROXY_DIR/routes"

CI_PUBKEY="${CI_PUBKEY:-${1:-}}"
CONFIG_IMAGE="${CONFIG_IMAGE:-}"
HARDEN_SSH="${HARDEN_SSH:-0}"
TASKS="${TASKS:-}"
TASKS_SET="${TASKS_SET:-0}"
SCOPED_ENV="${SCOPED_ENV:-}"
SCOPED_ENV_SET="${SCOPED_ENV_SET:-0}"
PREVIEW="${PREVIEW:-0}"
PREVIEW_SET="${PREVIEW_SET:-0}"

case "$TASKS_SET" in
	1|yes|true) TASKS_SET=1 ;;
	0|no|false|'') TASKS_SET=0 ;;
	*) echo "error: TASKS_SET must be 0 or 1" >&2; exit 1 ;;
esac
if [ "$TASKS_SET" = "0" ] && [ -f "$STATE_FILE" ]; then
	TASKS="$(sed -n 's/^TASKS=//p' "$STATE_FILE" | tr -d '\r' | head -n 1)"
fi
# TASKS is a recorded yes/no now, not a catalog key: what varies is the
# script, and that is stored on the box rather than named here.
#
# Decided HERE rather than where the script is installed, because the state
# record is written between the two and has to say what is true. The three
# cases are: a script was supplied, the flag was given with nothing (revoke),
# or neither -- in which case whatever the box already stores is what this
# app has, which is what makes `komizo update` keep it.
TASK_STORE=/var/lib/komizo/tasks
TASK_FILE="$TASK_STORE/$APP_NAME.sh"
if [ "$TASKS_SET" = "1" ]; then
	if [ -n "${TASK_SCRIPT_B64:-}" ]; then
		TASKS=1
	else
		TASKS=""
	fi
elif [ -f "$TASK_FILE" ]; then
	TASKS=1
else
	TASKS=""
fi

case "$PREVIEW_SET" in
	1|yes|true) PREVIEW_SET=1 ;;
	0|no|false|'') PREVIEW_SET=0 ;;
	*) echo "error: PREVIEW_SET must be 0 or 1" >&2; exit 1 ;;
esac
if [ "$PREVIEW_SET" = "0" ] && [ -f "$STATE_FILE" ]; then
	PREVIEW="$(sed -n 's/^PREVIEW=//p' "$STATE_FILE" | tr -d '\r' | head -n 1)"
fi
case "$PREVIEW" in
	1|yes|true) PREVIEW=1 ;;
	0|no|false|'') PREVIEW=0 ;;
	*) echo "error: PREVIEW must be 0 or 1" >&2; exit 1 ;;
esac

case "$SCOPED_ENV_SET" in
	1|yes|true) SCOPED_ENV_SET=1 ;;
	0|no|false|'') SCOPED_ENV_SET=0 ;;
	*) echo "error: SCOPED_ENV_SET must be 0 or 1" >&2; exit 1 ;;
esac
if [ "$SCOPED_ENV_SET" = "0" ] && [ -f "$STATE_FILE" ]; then
	SCOPED_ENV="$(sed -n 's/^SCOPED_ENV=//p' "$STATE_FILE" | tr -d '\r' | head -n 1)"
fi
# A catalog, like TASKS. The only profile writes per-service env files for
# fieldsofrevik. Any other app, or any other name, is a mistake rather than a
# path the caller gets to choose.
case "$SCOPED_ENV" in
	'') ;;
	fields-postgres-v2)
		[ "$APP_NAME" = "fieldsofrevik" ] || {
			echo "error: scoped env profile fields-postgres-v2 is only defined for app fieldsofrevik" >&2
			exit 1
		}
		;;
	*) echo "error: SCOPED_ENV names an unknown profile" >&2; exit 1 ;;
esac

# The names CI connects to this app by. Recorded per APP rather than per box:
# known_hosts is matched on the exact string the client dialled, and each repo
# dials one name -- so the value that repo pins should name that one, not every
# name every app on this box answers to.
#
# Empty means keep whatever is already recorded, which is what re-running for a
# config-image change wants: it is not saying the names changed, it is not
# mentioning them.
#
# Which leaves no way to say "there are none", and that is what CLEAR_KNOWN_AS
# is for. Editing the list down to nothing is a real edit -- a box that stopped
# answering to a second name, an entry added by mistake -- and without this it
# was the one change that silently did nothing. A separate variable rather than
# a sentinel value, because every sentinel a hostname could never be is also a
# value someone eventually types.
KNOWN_AS="${KNOWN_AS:-}"
CLEAR_KNOWN_AS="${CLEAR_KNOWN_AS:-0}"
case "$CLEAR_KNOWN_AS" in
	1|yes|true) CLEAR_KNOWN_AS=1 ;;
	0|no|false|'') CLEAR_KNOWN_AS=0 ;;
	*) echo "error: CLEAR_KNOWN_AS must be 0 or 1" >&2; exit 1 ;;
esac
if [ "$CLEAR_KNOWN_AS" = "1" ]; then
	[ -z "$KNOWN_AS" ] || { echo "error: CLEAR_KNOWN_AS=1 with names in KNOWN_AS says two different things" >&2; exit 1; }
elif [ -z "$KNOWN_AS" ] && [ -f "$STATE_FILE" ]; then
	# tr -d '\r' for the reason the STOPPED read below strips it, and this one
	# fails harder. A record that picked up CRLF -- copied through an editor on
	# another machine, restored from a backup taken on one -- reads back as
	# "blog.example.com\r", and the charset check immediately below rejects the
	# CR and dies complaining about a value nobody passed. So the app could
	# not be re-provisioned AT ALL: not to change its config image, and not by
	# `komizo update`, which re-runs this script for every app on the box. That
	# app would keep the deploy script it already had through every upgrade,
	# which is komizo#58 surviving its own fix, and the message names a value
	# nobody passed.
	KNOWN_AS="$(sed -n 's/^KNOWN_AS=//p' "$STATE_FILE" | tr -d '\r' | head -n 1)"
fi
# Substituted into the generated deploy script, so constrain it here rather
# than trusting the caller. Hostnames and the commas between them.
case "$KNOWN_AS" in
	'') ;;
	*[!A-Za-z0-9.,_-]*) echo "error: KNOWN_AS must be hostnames separated by commas" >&2; exit 1 ;;
esac

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root"
# An empty CI_PUBKEY means "leave the deploy key alone", which is what a
# setting change wants: re-running this to re-point an app at a different
# config image must not issue the repo a new key it does not know about. It is
# only valid when the account already has one -- an app with no authorized key
# is an app nothing can deploy to, and failing here is better than creating a
# deploy account that silently accepts nobody.
if [ -n "$CI_PUBKEY" ]; then
	case "$CI_PUBKEY" in
		ssh-*|ecdsa-*) ;;
		*) die "CI_PUBKEY does not look like an SSH public key" ;;
	esac
	# It is written into a file one line at a time, and a newline in it would
	# authorise a second key nobody asked for.
	case "$CI_PUBKEY" in
		*"
"*) die "CI_PUBKEY must be a single line" ;;
	esac
elif [ ! -s "$KEYS_FILE" ]; then
	die "no SSH public key given, and this account has none (pass as \$1 or CI_PUBKEY)"
fi

# Required. It is the trust anchor: root pins WHICH image the host will accept
# config from, so a leaked deploy key cannot redirect the host at an image the
# attacker controls. Everything else about a deploy is CI's to choose; this is
# not.
[ -n "$CONFIG_IMAGE" ] || die "CONFIG_IMAGE is required, e.g. ghcr.io/you/myapp-config"
case "$CONFIG_IMAGE" in
	*@*) die "CONFIG_IMAGE must not include a digest (got '$CONFIG_IMAGE')" ;;
	*[!A-Za-z0-9.:/_-]*) die "CONFIG_IMAGE contains characters that are not valid in an image reference" ;;
esac
# The tag is supplied per deploy, so a tag here is always a mistake -- it would
# silently pin every deploy to one version. A tag is a colon AFTER the last
# slash; testing the whole string would reject a registry with a port, e.g.
# registry.internal:5000/app-config.
case "${CONFIG_IMAGE##*/}" in
	*:*) die "CONFIG_IMAGE must not include a tag (got '$CONFIG_IMAGE'); the deploy tag is appended per run" ;;
esac

# Substituted into the generated scripts below with sed, using '|' as the
# delimiter. Every value above is already constrained to charsets that exclude
# it, but the app directory is the one a caller can point anywhere.
case "$APP_DIR" in
	/*) ;;
	*) die "APP_DIR must be an absolute path (got '$APP_DIR')" ;;
esac
case "$APP_DIR" in
	*[!A-Za-z0-9./_-]*) die "APP_DIR contains characters that are not allowed" ;;
esac

# --- 1. Preconditions ------------------------------------------------------
# The server half of the setup is its own step. Checking rather than installing
# keeps that boundary honest: if this script quietly ran apk, "initialised"
# would stop meaning anything.

command -v docker >/dev/null 2>&1 \
	|| die "this server is not set up yet -- run 'komizo init' first"
command -v doas >/dev/null 2>&1 \
	|| die "doas is missing -- run 'komizo init' first to install it"
docker info >/dev/null 2>&1 \
	|| die "Docker is installed but not running -- try 'rc-service docker start'"

# --- 2. CI user ------------------------------------------------------------

log "Creating user '$CI_USER'"
if id "$CI_USER" >/dev/null 2>&1; then
	# An existing account is fine only if it is not privileged: pointing sshd at a
	# key list of komizo's for a UID-0 account would turn the deploy key into a
	# root login and could lock the operator out.
	[ "$(id -u "$CI_USER")" -ne 0 ] || die "CI_USER '$CI_USER' is a UID-0 (root-equivalent) account -- refusing"
else
	# -D: no password (key-only login), -s: shell needed for SSH commands
	adduser -D -s /bin/sh "$CI_USER"
fi
# The password field must be "*", and this is load-bearing rather than tidy-up.
#
# "adduser -D" writes "!", which sshd reads as ACCOUNT LOCKED and then refuses
# every authentication method -- including publickey. The deploy user could not
# log in at all:
#
#   User komizo-app not allowed because account is locked
#
# "*" is the value we want: it is not a valid password hash, so no password can
# ever match it, but it does not mark the account locked, so key auth works.
# Empty would also let key auth through, but an empty field plus
# PermitEmptyPasswords would accept a blank password, so it is not equivalent.
#
# chpasswd -e takes an already-hashed value and is in busybox; usermod is not
# present on a stock Alpine.
printf '%s:*\n' "$CI_USER" | chpasswd -e >/dev/null 2>&1 \
	|| die "could not clear the password for '$CI_USER' -- it would be unable to log in"
# Deliberately NOT added to the docker group -- that would be root.
deluser "$CI_USER" docker 2>/dev/null || true

# The key list is root's, in root's directory. sshd is pointed at it by the
# Match block below.
mkdir -p "$KEYS_DIR"
chown root:root "$KEYS_DIR"
chmod 755 "$KEYS_DIR"

# Retire the app's previous deploy account, if it was renamed (see OLD_CI_USER
# above). Its doas and sshd marker blocks are removed alongside the current
# account's, further down; here we drop its key file and the account itself.
if [ -n "$OLD_CI_USER" ]; then
	log "Removing this app's previous deploy account '$OLD_CI_USER'"
	rm -f "$KEYS_DIR/$OLD_CI_USER"
	deluser "$OLD_CI_USER" 2>/dev/null || true
fi

if [ -z "$CI_PUBKEY" ]; then
	log "Keeping the deploy key already installed"
else
	log "Installing deploy key"
	# The file is WRITTEN, not appended to and not edited.
	#
	# It holds exactly one key -- this one -- so a rotation is a replacement by
	# construction rather than by matching the old key's comment and hoping
	# nothing else was added beside it. Nothing but komizo has ever been able to
	# write here, so there is nothing else in it to preserve.
	#
	# "restrict" turns everything off and nothing on: no pty, no forwarding of
	# any kind, no user rc file. The sshd Match block says the same thing, which
	# is the point -- neither is load-bearing alone.
	printf 'restrict %s\n' "$CI_PUBKEY" > "$KEYS_FILE"
fi
chown root:root "$KEYS_FILE"
chmod 644 "$KEYS_FILE"

log "Preparing $APP_DIR"
# Root-owned on purpose: if the CI user could edit compose.yml it could mount
# the host filesystem into a container, which is the same as being root.
mkdir -p "$APP_DIR"
chown root:root "$APP_DIR"
# 750, not 755: nothing but root reads under here (the deploy runs as root via
# doas; the proxy mounts only its own routes directory). The deploy account has
# an ordinary shell session, and a world-readable app dir let it read every
# OTHER app's compose.yml -- which the app is told to keep non-secret settings
# in, and which in practice accretes internal URLs and the like.
chmod 750 "$APP_DIR"
if [ ! -f "$APP_DIR/compose.yml" ]; then
	printf 'services: {}\n' > "$APP_DIR/compose.yml"
fi
chown root:root "$APP_DIR/compose.yml"
# 600: compose.yml is root's to write and root's (docker, the deploy script) to
# read; no other account has any business reading it.
chmod 600 "$APP_DIR/compose.yml"
# Two env files, split by who writes them and who may read them:
#
#   .env         APP_VERSION only. Compose reads this for ${APP_VERSION}
#                substitution in compose.yml. Written by the deploy script.
#   secrets.env  Production credentials, written only by set-secret. 600 so the
#                CI user cannot read it back -- it may set values, never read
#                them.
#
# There is deliberately no third file for non-secret settings. It would ship in
# the config image, be readable by anyone who can pull it, and be versioned per
# commit -- all of which is equally true of an `environment:` block in
# compose.yml, which additionally scopes per service. A second mechanism with
# no distinct property is just something else to explain.
for f in .env secrets.env; do
	touch "$APP_DIR/$f"
	chown root:root "$APP_DIR/$f"
done
chmod 600 "$APP_DIR/.env" "$APP_DIR/secrets.env"

# Where this app's generated route will land. Under the PROXY's directory, not
# the app's: the proxy container mounts only this, so an app's secrets are no
# longer inside the one process on the box that faces the internet.
mkdir -p "$ROUTES_DIR"
chown root:root "$PROXY_DIR" "$ROUTES_DIR"
chmod 755 "$PROXY_DIR" "$ROUTES_DIR"

# --- 2b. What komizo knows about this app ----------------------------------
# Data, read by everything that needs to know where the app lives or what it
# deploys from. Written before the scripts below so that a run which dies half
# way still leaves the box describable.

log "Recording $STATE_FILE"
mkdir -p "$STATE_DIR"
chown root:root "$STATE_DIR"
# 750: the records name every app's directory, deploy account and config-image
# path, and root is the only thing that reads them.
chmod 750 "$STATE_DIR"

# The PARENT keeps its group, and this line is why it is separate.
#
# It used to be chowned root:root here, on every `komizo add` -- so adding an app
# to a working box silently took the agent's traversal away and every request for
# that box's history started answering "no readings" with nothing to say why.
# Closed, and traversable by the one account that has to pass through it.
chown root:root /var/lib/komizo
if id komizo_monitor >/dev/null 2>&1; then
	chgrp komizo_monitor /var/lib/komizo
fi
chmod 750 /var/lib/komizo
# A DELIBERATE STOP SURVIVES A RE-RUN.
#
# This file is rewritten wholesale below, and re-running for an existing app is
# the documented way to change the config image or KNOWN_AS. Without this, doing
# that to a stopped app deletes the record of the stop while leaving the app
# down -- so the box starts reporting app_down for something somebody stopped on
# purpose, and nothing anywhere says why it changed its mind. That is komizo#48
# reached from the other direction, and the KNOWN_AS block above already makes
# the same argument: a re-run that is not mentioning a thing is not saying it
# changed.
#
# Read line by line, in the same shape KNOWN_AS is read, rather than copied
# through as a block -- so what lands back in the file is three known keys and
# never whatever else a hand-edited file happened to have on those lines.
#
# ONE WRITER OF THIS FILE AT A TIME, and the lock is the first thing here.
#
# komizo-box rewrites the same file, from Go, whenever an app is stopped or
# started -- it reads the record, changes three keys and writes it back. This
# block is the other half of that pair: it reads three keys and writes the whole
# file. Interleaved, the two lose each other's work, and one interleaving loses
# far more than a stop marker: a rootd-applied `app.stop` that reads the file
# while this one has it open for writing sees whatever is there at that instant,
# and writes back a record with no APP_DIR in it. paths.go's answer to a record
# like that is "names no APP_DIR, so komizo does not know where %q is" -- and
# nothing puts it back. Rare, and the whole app is unreachable to every command
# afterwards.
#
# Per app, matching the lock name box/stopped.go takes, so the two processes are
# actually excluding each other rather than each locking something private.
# Skipped wherever it cannot be taken -- a busybox without the flock applet, a
# /run this cannot write -- exactly as the deploy lock is, and for the same
# reason: refusing to add an app at all would trade a rare race for a certain
# outage. The atomic replacement below means the worst that survives a skipped
# lock is a lost update, not a truncated record.
STATE_LOCK="/run/komizo/state-$APP_NAME.lock"
if command -v flock >/dev/null 2>&1 &&
	mkdir -p /run/komizo 2>/dev/null &&
	: > "$STATE_LOCK" 2>/dev/null
then
	exec 7>"$STATE_LOCK"
	if ! flock -w 30 7; then
		echo "error: another process has been writing $STATE_FILE for over 30s" >&2
		exit 1
	fi
fi

# tr -d '\r' on every read, because a CR is invisible and this is a comparison
# against a literal. A record that picked up CRLF -- copied through an editor on
# another machine, restored from a backup taken on one -- makes "$(...)" return
# "1\r", which is not "1", so this block would decide the app was never stopped
# and silently drop a marker that was there. Dropping it starts app_down paging
# for an app somebody stopped on purpose, which is komizo#48 all over again and
# with no trace of why. Stripped from the carried values too: a CR inside
# STOPPED_BY would be written straight back into the new file, where Go refuses
# to put one.
STOPPED_KEEP=""
if [ -f "$STATE_FILE" ] && [ "$(sed -n 's/^STOPPED=//p' "$STATE_FILE" | tr -d '\r' | head -n 1)" = "1" ]; then
	STOPPED_KEEP="$(printf 'STOPPED=1\nSTOPPED_BY=%s\nSTOPPED_AT=%s' \
		"$(sed -n 's/^STOPPED_BY=//p' "$STATE_FILE" | tr -d '\r' | head -n 1)" \
		"$(sed -n 's/^STOPPED_AT=//p' "$STATE_FILE" | tr -d '\r' | head -n 1)")"
fi
GEN_KEEP=""
if [ -f "$STATE_FILE" ]; then
	GEN_KEEP="$(sed -n 's/^SCOPED_GENERATION=//p' "$STATE_FILE" | tr -d '\r' | head -n 1)"
	case "$GEN_KEEP" in
		*[!0-9a-f]*|'') GEN_KEEP="" ;;
	esac
	if [ -n "$GEN_KEEP" ] && [ "${#GEN_KEEP}" -ne 32 ]; then
		GEN_KEEP=""
	fi
fi

# Built beside the file and MOVED over it, never truncated in place.
#
# `cat > "$STATE_FILE"` empties the record and then fills it line by line, so
# there is a window in which the file exists and says nothing. Anything reading
# it in that window -- rootd's applier, the probe that builds the report, the
# generated deploy script scanning other apps' records -- reads a file with no
# APP_DIR and believes it. A rename is a single step to every reader: they see
# the old record or the new one and never a half.
#
# Same directory, because rename is only atomic within one filesystem. Owner and
# mode are set on the temporary file BEFORE the move, so the record is never
# briefly readable by more than root at its final name.
#
# The suffix goes AFTER .env, not before, so the name is inert to everything
# that enumerates apps: the probe skips a file that does not end in .env, and
# the deploy script's cross-app scan globs *.env. A run that dies between the
# write and the move therefore leaves a stray file and not a phantom app.
STATE_TMP="$STATE_FILE.tmp.$$"
cat > "$STATE_TMP" <<EOF
# Written by komizo. This is what komizo knows about this app; edit with
# 'komizo add' rather than by hand.
APP_NAME=$APP_NAME
APP_DIR=$APP_DIR
CI_USER=$CI_USER
CONFIG_IMAGE=$CONFIG_IMAGE
KNOWN_AS=$KNOWN_AS
TASKS=${TASKS:-}
SCOPED_ENV=${SCOPED_ENV:-}
PREVIEW=${PREVIEW:-0}
EOF
if [ -n "$STOPPED_KEEP" ]; then
	printf '%s\n' "$STOPPED_KEEP" >> "$STATE_TMP"
fi
if [ -n "$GEN_KEEP" ]; then
	printf 'SCOPED_GENERATION=%s\n' "$GEN_KEEP" >> "$STATE_TMP"
fi
VOL_KEEP=""
PROJECT_KEEP=""
if [ -f "$STATE_FILE" ]; then
	VOL_KEEP="$(sed -n 's/^SCOPED_PG_VOLUME=//p' "$STATE_FILE" | tr -d '\r' | head -n 1)"
	PROJECT_KEEP="$(sed -n 's/^SCOPED_COMPOSE_PROJECT=//p' "$STATE_FILE" | tr -d '\r' | head -n 1)"
	case "$VOL_KEEP" in
		*[!A-Za-z0-9_.-]*|'') VOL_KEEP="" ;;
	esac
	case "$PROJECT_KEEP" in
		*[!a-z0-9_-]*|'') PROJECT_KEEP="" ;;
	esac
fi
if [ -n "$VOL_KEEP" ]; then
	printf 'SCOPED_PG_VOLUME=%s\n' "$VOL_KEEP" >> "$STATE_TMP"
fi
if [ -n "$PROJECT_KEEP" ]; then
	printf 'SCOPED_COMPOSE_PROJECT=%s\n' "$PROJECT_KEEP" >> "$STATE_TMP"
fi
chown root:root "$STATE_TMP"
chmod 640 "$STATE_TMP"
mv -f "$STATE_TMP" "$STATE_FILE"

# Released here rather than left to the end of the script. What follows is the
# deploy script, the doas rules and the proxy, none of which touch this file,
# and a lock held across all of that would make a concurrent `komizo stop` wait
# for work it has nothing to do with.
exec 7>&-

# Host-owned authority is separate from repository-supplied configuration.
# Existing policies are retained verbatim; a new config image cannot widen one.
if ! command -v komizo-box >/dev/null 2>&1; then
	die "komizo-box is required; initialize/update the host before adding apps"
fi
komizo-box workload init --policy "/etc/komizo/workloads/$APP_NAME.json" \
	--app "$APP_NAME" --app-dir "$APP_DIR" --config-image "$CONFIG_IMAGE" \
	--network "${SHARED_NETWORK:-edge}"

# --- 3. Deploy path --------------------------------------------------------
# An app-bound privileged command. Secret, image-retention and configured
# optional task/preview commands are installed below.
#
# It takes one argument, the image tag to deploy. doas "cmd" without an "args"
# clause permits ANY arguments, so the script validates the tag itself rather
# than trusting the caller -- it is substituted into .env via sed, and used as
# an image tag and a path component, so a value containing a newline, a slash
# or a shell metacharacter could otherwise do real damage.
#
# compose.yml comes OUT OF THE IMAGE for that tag rather than off the disk.
# That is what lets CI change the shape of the stack without ever writing to
# this box: the file arrives as a registry layer that root extracts, so
# altering it requires registry push, which already implied code execution
# here. The CI user gains nothing.
#
# The template below is a QUOTED heredoc, so what is between the markers is
# written out literally and is ordinary readable shell. It used to be an
# unquoted heredoc with every '$' hand-escaped, where one missed backslash
# silently moved an expansion from deploy time to install time -- the worst
# possible failure mode for the most security-sensitive file on the box.
# The handful of values that ARE fixed at install time are spelled __LIKE_THIS__
# and substituted immediately afterwards.

log "Installing $DEPLOY_BIN"
cat > "$DEPLOY_BIN.tmp" <<'KOMIZO_DEPLOY_EOF'
#!/bin/sh
# Written by komizo. Edits are lost the next time the app is set up.
set -eu
# No pathname expansion. Several loops below iterate $hostnames (whitespace-
# separated, straight from the config image), and a hostname of "*" or "*.prev"
# would otherwise glob into the files in this directory and be published as bogus
# routes -- slipping past the wildcard check, which never sees a literal "*".
# Re-enabled only around the one place a glob is intended (the state-file scan).
set -f

CONFIG_IMAGE="__CONFIG_IMAGE__"
PROXY_CONTAINER="__PROXY_CONTAINER__"
PROXY_DIR="__PROXY_DIR__"

# Baked in rather than derived. The app's name decides the upstream the shared
# proxy is pointed at (<app>-gate), and its directory is where the hostnames
# it has claimed are recorded -- both are read below, so both have to be values
# this script carries rather than things it works out.
APP_NAME="__APP_NAME__"
APP_DIR="__APP_DIR__"
ROUTE_FILE="__ROUTES_DIR__/__APP_NAME__.caddy"
SCOPED_ENV="__SCOPED_ENV__"
WORKLOAD_POLICY="/etc/komizo/workloads/__APP_NAME__.json"

# This app's own record, which is where a DELIBERATE STOP is written down.
#
# The deploy reads it and refuses to start an app somebody stopped -- see the
# start decision near the end of this script for the whole argument. Named here,
# beside the other baked-in values, because the cross-app hostname scan below
# already reaches into __STATE_DIR__ and two spellings of the same directory in
# one script is one of them going stale.
#
# A FILE, deliberately, and not a question asked of komizo. appify.md §2 is
# explicit that a deploy must not depend on anything off the box: a deploy that
# has to consult a service to find out whether it may start the app is a deploy
# that fails when the service is down.
STATE_FILE="__STATE_DIR__/__APP_NAME__.env"

# Metadata, file type, owner, and mode, plus the nonsecret provenance marker
# written only by v2 provision. Env files are not opened, so a deploy log
# cannot carry a credential. A missing or escaping current link fails before
# compose.yml is swapped: the running stack is still the previous one.
komizo_scoped_env_ready() {
	recorded=$(sed -n 's/^APP_DIR=//p' "$STATE_FILE" | tr -d '\r' | head -n 1)
	if [ "$recorded" != "$APP_DIR" ]; then
		echo "deploy: refusing: app record APP_DIR does not match this deploy script" >&2
		return 1
	fi
	secrets="$APP_DIR/secrets"
	if [ -L "$secrets" ] || [ ! -d "$secrets" ]; then
		echo "deploy: refusing: scoped env is not staged (secrets is missing or a symlink)" >&2
		return 1
	fi
	if [ ! -L "$secrets/current" ]; then
		echo "deploy: refusing: scoped env current link is missing" >&2
		return 1
	fi
	target=$(readlink "$secrets/current") || {
		echo "deploy: refusing: cannot read scoped env current link" >&2
		return 1
	}
	case "$target" in
		generations/[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
		*)
			echo "deploy: refusing: scoped env current link is not a confined generation" >&2
			return 1
			;;
	esac
	id=${target#generations/}
	gdir="$secrets/generations/$id"
	if [ -L "$gdir" ] || [ ! -d "$gdir" ]; then
		echo "deploy: refusing: scoped env generation is missing or a symlink" >&2
		return 1
	fi
	for f in postgres.env migrate.env api.env godot-api.env; do
		p="$gdir/$f"
		if [ -L "$p" ] || [ ! -f "$p" ]; then
			echo "deploy: refusing: scoped env file $f is missing or a symlink" >&2
			return 1
		fi
		mode=$(stat -c %a "$p" 2>/dev/null || true)
		owner=$(stat -c %u "$p" 2>/dev/null || true)
		if [ "$mode" != "600" ] || [ "$owner" != "0" ]; then
			echo "deploy: refusing: scoped env file $f is not root-owned mode 600" >&2
			return 1
		fi
	done
	if [ "$id" != "${expected_generation:-}" ]; then
		echo "deploy: refusing: scoped generation mismatch" >&2
		return 1
	fi
	recorded_gen=$(sed -n 's/^SCOPED_GENERATION=//p' "$STATE_FILE" | tr -d '\r' | head -n 1)
	if [ "$recorded_gen" != "$id" ]; then
		echo "deploy: refusing: scoped generation mismatch" >&2
		return 1
	fi
	marker="$gdir/provenance"
	if [ -L "$marker" ] || [ ! -f "$marker" ]; then
		echo "deploy: refusing: scoped env is not a fields-postgres-v2 generation" >&2
		return 1
	fi
	mode=$(stat -c %a "$marker" 2>/dev/null || true)
	owner=$(stat -c %u "$marker" 2>/dev/null || true)
	if [ "$mode" != "400" ] || [ "$owner" != "0" ]; then
		echo "deploy: refusing: scoped env file provenance is not root-owned mode 400" >&2
		return 1
	fi
	size=$(stat -c %s "$marker" 2>/dev/null || true)
	expected_size=$(printf 'profile=fields-postgres-v2\nschema=11\ngeneration=%s\n' "$id" | wc -c | tr -d '[:space:]')
	match=0
	if [ "$size" = "$expected_size" ]; then
		printf 'profile=fields-postgres-v2\nschema=11\ngeneration=%s\n' "$id" | cmp -s - "$marker" || match=$?
	else
		match=1
	fi
	if [ "$match" -ne 0 ]; then
		echo "deploy: refusing: scoped env is not a fields-postgres-v2 generation" >&2
		return 1
	fi
	return 0
}


# Operator-written host-wide floors. Komizo never creates this file. Empty or
# missing keys mean no floor: deploys fail-open with a warning rather than
# inventing a production SLO here. CI only reaches deploy-APP, so the operator
# writes this on the box as root.
FLOORS_FILE="/etc/komizo/deploy-floors"
REPORT_JSON="/run/komizo/report.json"

# Numbers from compact encoding/json output. No jq on the box. Brace-matched so
# a nested swap object inside mem does not clip available. BusyBox awk %d is
# 32-bit, so large byte counts are printed with %.0f (exact to 2^53).
json_mem_available() {
	awk '
	{
		buf = buf $0
	}
	END {
		gsub(/[ \t\n\r]/, "", buf)
		pat = "\"mem\":{"
		i = index(buf, pat)
		if (i == 0) exit
		rest = substr(buf, i + length(pat) - 1)
		depth = 0
		obj = ""
		n = length(rest)
		for (k = 1; k <= n; k++) {
			c = substr(rest, k, 1)
			obj = obj c
			if (c == "{") depth++
			if (c == "}") {
				depth--
				if (depth == 0) break
			}
		}
		i = index(obj, "\"available\":")
		if (i == 0) exit
		rest = substr(obj, i + 12)
		if (match(rest, /^[0-9]+/)) printf "%.0f\n", substr(rest, RSTART, RLENGTH) + 0
	}' "$1" 2>/dev/null || true
}

json_disk_available() {
	awk '
	{
		buf = buf $0
	}
	END {
		gsub(/[ \t\n\r]/, "", buf)
		i = index(buf, "\"disks\":[")
		if (i == 0) exit
		rest = substr(buf, i + 9)
		depth = 0
		arr = ""
		n = length(rest)
		for (k = 1; k <= n; k++) {
			c = substr(rest, k, 1)
			arr = arr c
			if (c == "[") depth++
			if (c == "]") {
				depth--
				if (depth == 0) break
			}
		}
		have = 0
		minv = 0
		s = arr
		while ((j = index(s, "\"available\":")) > 0) {
			s = substr(s, j + 12)
			if (!match(s, /^[0-9]+/)) break
			v = substr(s, RSTART, RLENGTH) + 0
			if (!have || v < minv) minv = v
			have = 1
			s = substr(s, RLENGTH + 1)
		}
		if (have) printf "%.0f\n", minv
	}' "$1" 2>/dev/null || true
}

# True when A < B. BusyBox [ ] is 32-bit signed; disk bytes are not.
below_bytes() {
	awk -v a="$1" -v b="$2" 'BEGIN { exit (a + 0 < b + 0) ? 0 : 1 }'
}

version="${1:-}"
registry="${2:-}"
registry_user="${3:-}"
cd "$APP_DIR"

# Clean up scratch however this exits. Several validation failures below exit
# without reaching an explicit cleanup, and each would otherwise leave a
# root-owned copy of the config image -- or the per-run registry credentials --
# behind in /tmp.
#
# The .env backup is in here for the same reason. It is removed on both the
# success and the failure path below, but a kill between writing it and reaching
# either would leave a copy of this app's environment sitting in its directory
# until something happened to overwrite it.
staging=""
release_dir=""
journal_started=0
journal_finished=0
#
# AND IT STOPS, rather than only tidying. A handler for a non-EXIT signal in
# POSIX sh RESUMES at the interruption point when it returns, so `EXIT INT TERM`
# cleaned up and then carried on deploying a box whose operator had just
# cancelled -- the same defect Review 2 found in the doas and sshd windows
# below, in a third place nobody had looked. HUP and PIPE were absent entirely,
# which are precisely how a dropped SSH connection arrives: the tidy-up did not
# run at all on the two signals most likely to fire, leaving the registry
# credential in /tmp and a copy of the app's environment beside it.
#
# `exit` from a handler runs the EXIT trap too, so the cleanup is written once.
cleanup_staging() {
	if [ "$journal_started" = 1 ] && [ "$journal_finished" = 0 ]; then
		komizo-box workload operation --policy "$WORKLOAD_POLICY" --version "$version" --previous "$previous" --phase failed >/dev/null 2>&1 || true
	fi
	rm -rf "$staging" "$release_dir" "${DOCKER_CONFIG:-}" 2>/dev/null || true
	rm -f "$APP_DIR/.env.komizo.bak" 2>/dev/null || true
}
trap cleanup_staging EXIT
trap 'cleanup_staging; exit 129' INT TERM HUP PIPE

# Tags and SHAs only: letters, digits, dot, underscore, hyphen. Required --
# every deploy names a version, because the config for that version has to be
# fetched before anything can run.
case "$version" in
	*[!A-Za-z0-9._-]*|'')
		echo "deploy: usage: deploy <tag> [<registry> <registry-user>]  (token on stdin)" >&2
		echo "deploy: refusing version '$version'" >&2
		exit 1
		;;
esac

# fields-postgres-v2 always takes four arguments. The generation is not a
# secret and is not read from stdin; stdin remains the registry token, and is
# left unread when the registry arguments are both empty. Any other app stays
# at one or three arguments and rejects a fourth rather than ignoring it.
expected_generation=""
if [ "$SCOPED_ENV" = "fields-postgres-v2" ]; then
	if [ "$#" -ne 4 ]; then
		echo "deploy: refusing: scoped generation missing" >&2
		exit 1
	fi
	expected_generation=$4
	case "$expected_generation" in
		*[!0-9a-f]*|'')
			echo "deploy: refusing: scoped generation malformed" >&2
			exit 1
			;;
	esac
	if [ "${#expected_generation}" -ne 32 ]; then
		echo "deploy: refusing: scoped generation malformed" >&2
		exit 1
	fi
	if [ -z "$registry" ] && [ -n "$registry_user" ]; then
		echo "deploy: refusing: registry user set without registry" >&2
		exit 1
	fi
	if [ -n "$registry" ] && [ -z "$registry_user" ]; then
		echo "deploy: refusing registry user '$registry_user'" >&2
		exit 1
	fi
elif [ "$#" -ne 1 ] && [ "$#" -ne 3 ]; then
	echo "deploy: usage: deploy <tag> [<registry> <registry-user>]  (token on stdin)" >&2
	echo "deploy: refusing: unexpected arguments" >&2
	exit 1
fi

# One deploy of this app at a time.
#
# Two runs of the same app interleave their compose.yml swaps and their .env
# writes, and the loser wins on some files and loses on others -- a stack
# running one commit's containers against another commit's config, from two
# green pipelines. The wait is bounded so a stuck deploy fails the second run
# with a message rather than hanging CI until it times out.
#
# Both locks are mandatory. A host operation serializes pulls, Compose startup
# and pruning across products; the app lock also coordinates scoped secrets.
komizo_lock="/run/komizo/deploy-__APP_NAME__.lock"
command -v flock >/dev/null 2>&1 || { echo "deploy: refusing: locking unavailable" >&2; exit 1; }
mkdir -p /run/komizo || { echo "deploy: refusing: lock directory unavailable" >&2; exit 1; }
exec 9>"$komizo_lock"
flock -w 300 9 || { echo "deploy: refusing: app lock busy" >&2; exit 1; }
exec 6>/run/komizo/operation.lock
flock -w 300 6 || { echo "deploy: refusing: host operation busy" >&2; exit 1; }

# Resource floors, if the operator set any. Until they do, fail-open with a
# loud warning that prints the reported available bytes. No sample sizes are
# encoded as defaults. If floors exist and report.json is missing, unreadable,
# or lacks the available fields those floors need, refuse-closed -- before
# pulling images or composing up.
disk_floor=""
mem_floor=""
if [ -e "$FLOORS_FILE" ]; then
	if [ ! -f "$FLOORS_FILE" ] || [ ! -r "$FLOORS_FILE" ]; then
		echo "deploy: refusing: cannot read $FLOORS_FILE" >&2
		exit 1
	fi
	disk_floor="$(sed -n 's/^DISK_AVAILABLE_FLOOR_BYTES=//p' "$FLOORS_FILE" | tr -d '\r \t' | head -n 1)"
	mem_floor="$(sed -n 's/^MEM_AVAILABLE_FLOOR_BYTES=//p' "$FLOORS_FILE" | tr -d '\r \t' | head -n 1)"
	case "$disk_floor" in
		''|*[!0-9]*)
			if [ -n "$disk_floor" ]; then
				echo "deploy: refusing: $FLOORS_FILE has a non-numeric DISK_AVAILABLE_FLOOR_BYTES" >&2
				exit 1
			fi
			;;
	esac
	case "$mem_floor" in
		''|*[!0-9]*)
			if [ -n "$mem_floor" ]; then
				echo "deploy: refusing: $FLOORS_FILE has a non-numeric MEM_AVAILABLE_FLOOR_BYTES" >&2
				exit 1
			fi
			;;
	esac
fi
mem_avail=""
disk_avail=""
if [ -f "$REPORT_JSON" ] && [ -r "$REPORT_JSON" ]; then
	mem_avail="$(json_mem_available "$REPORT_JSON")"
	disk_avail="$(json_disk_available "$REPORT_JSON")"
fi
if [ -n "$disk_floor" ] || [ -n "$mem_floor" ]; then
	if [ ! -f "$REPORT_JSON" ] || [ ! -r "$REPORT_JSON" ]; then
		echo "deploy: refusing: $FLOORS_FILE sets floors but $REPORT_JSON is missing or unreadable" >&2
		exit 1
	fi
	if [ -n "$mem_floor" ] && [ -z "$mem_avail" ]; then
		echo "deploy: refusing: $FLOORS_FILE sets floors but $REPORT_JSON lacks available fields" >&2
		exit 1
	fi
	if [ -n "$disk_floor" ] && [ -z "$disk_avail" ]; then
		echo "deploy: refusing: $FLOORS_FILE sets floors but $REPORT_JSON lacks available fields" >&2
		exit 1
	fi
	komizo-box workload capacity --report "$REPORT_JSON" || { echo "deploy: refusing: stale capacity report" >&2; exit 1; }
	if [ -n "$mem_floor" ] && below_bytes "$mem_avail" "$mem_floor"; then
		echo "deploy: refusing: mem available ${mem_avail} bytes is below floor ${mem_floor} bytes" >&2
		exit 1
	fi
	if [ -n "$disk_floor" ] && below_bytes "$disk_avail" "$disk_floor"; then
		echo "deploy: refusing: disk available ${disk_avail} bytes is below floor ${disk_floor} bytes" >&2
		exit 1
	fi
	# Past the floor is not the same as comfortable. Between 1x and 2x the
	# floor the deploy proceeds, but loudly: tonight's disk died between one
	# deploy and the next, and a box drifting toward the line should be
	# audible in the log before it is over it. Doubled with awk for the same
	# reason below_bytes exists -- BusyBox [ ] is 32-bit signed; bytes are not.
	if [ -n "$mem_floor" ] && below_bytes "$mem_avail" "$(awk -v f="$mem_floor" 'BEGIN{printf "%.0f", f*2}')"; then
		echo "deploy: WARNING -- mem available ${mem_avail} bytes is below twice the floor ${mem_floor} bytes" >&2
	fi
	if [ -n "$disk_floor" ] && below_bytes "$disk_avail" "$(awk -v f="$disk_floor" 'BEGIN{printf "%.0f", f*2}')"; then
		echo "deploy: WARNING -- disk available ${disk_avail} bytes is below twice the floor ${disk_floor} bytes" >&2
	fi
else
	echo "deploy: WARNING -- no operator resource floors configured ($FLOORS_FILE absent or keys empty); deploying anyway" >&2
	echo "deploy: WARNING -- reported available bytes: mem=${mem_avail:-unknown} disk=${disk_avail:-unknown}" >&2
fi

release_wire=""
# Registry authentication happens HERE, as root, and not over the deploy user's
# SSH session. It has to: this script pulls as root, so a 'docker login' run as
# the deploy user would write to that user's home instead and the pull below
# would still be anonymous -- which fails only on a private registry, and looks
# like a broken image reference.
#
# Into a config directory of this run's own, rather than root's shared
# ~/.docker/config.json. Two apps deploying at once would otherwise log each
# other out through the same file -- and credentials that outlive the deploy
# are credentials sitting on the box.
#
# The token arrives on STDIN, never as an argument: arguments are visible in the
# host's process list to every other user on the box.
if [ -n "$registry" ]; then
	case "$registry" in
		*[!A-Za-z0-9.:_-]*)
			echo "deploy: refusing registry '$registry'" >&2
			exit 1
			;;
	esac
	# GitHub's workflow actor is this literal bot after an automated merge.
	# Other bracketed or shell-special usernames remain invalid.
	case "$registry_user" in
		'github-actions[bot]') ;;
		''|*[!A-Za-z0-9._@-]*)
			echo "deploy: refusing registry user '$registry_user'" >&2
			exit 1
			;;
	esac
	DOCKER_CONFIG="$(mktemp -d)"
	export DOCKER_CONFIG
	# Credentials must not outlive the deploy; the EXIT trap set above drops both
	# this directory and the staging dir however we leave.
	registry_password=""
	IFS= read -r registry_password || true
	release_wire=$(head -c 131073)
	if ! printf '%s' "$registry_password" | docker login "$registry" -u "$registry_user" --password-stdin >/dev/null; then
		echo "deploy: could not authenticate to $registry as $registry_user" >&2
		exit 1
	fi
	echo "deploy: authenticated to $registry as $registry_user"
fi

# Reported because the CI user cannot read .env itself (600 root) and has no
# other way to learn what it is replacing. Printed before anything changes, so
# it is still correct if a later step fails -- which is exactly when a caller
# wants it, to roll back to. Machine-readable on purpose: the activate action
# parses this line.
previous="$(sed -n 's/^APP_VERSION=//p' .env 2>/dev/null | head -n 1)"
echo "deploy: previous-version=${previous:-}"
release_dir=$(mktemp -d)
if ! printf '%s' "$release_wire" | komizo-box workload release-admit --policy "$WORKLOAD_POLICY" --version "$version" --output "$release_dir/accepted.json"; then
	echo "deploy: refusing: host release verification failed" >&2
	exit 1
fi
komizo-box workload operation --policy "$WORKLOAD_POLICY" --version "$version" --previous "$previous" --phase admitted
journal_started=1

ref="$CONFIG_IMAGE:$version"
echo "deploy: fetching config from $ref"
docker pull -q "$ref" >/dev/null

# 'docker create' + 'docker cp' rather than 'docker run': the config image
# is FROM scratch and has no shell to run anything with.
#
# --entrypoint is required, not cosmetic: 'docker create' refuses an image
# with no command at all, which a bare scratch image has. The container is
# only ever created and copied out of, never started, so the value is
# irrelevant -- it just has to be present.
staging="$(mktemp -d)"
cid="$(docker create --entrypoint /nonexistent "$ref")"
docker cp "$cid:/config/." "$staging/" >/dev/null
docker rm -v "$cid" >/dev/null

if [ ! -f "$staging/compose.yml" ]; then
	echo "deploy: $ref has no /config/compose.yml" >&2
	exit 1
fi

# A config image is data, not a way to make root read the host. `docker cp`
# preserves symlinks, and the cat/sed below would follow one out of the staging
# dir into an arbitrary host file. Refuse symlinks for the two files consumed.
if [ -L "$staging/compose.yml" ]; then
	echo "deploy: compose.yml in $ref is a symlink, which is not allowed" >&2
	exit 1
fi
if [ -L "$staging/hostnames" ]; then
	echo "deploy: hostnames in $ref is a symlink, which is not allowed" >&2
	exit 1
fi

# Parse and restrict untrusted YAML before Compose can read an env_file,
# include, provider or external configuration. Only canonical, host-approved
# JSON reaches Compose; validation failure leaves all installed files alone.
if ! komizo-box workload validate --policy "$WORKLOAD_POLICY" \
	--app "$APP_NAME" --app-dir "$APP_DIR" --version "$version" \
	--compose "$staging/compose.yml" --output "$staging/approved.json"; then
	echo "deploy: refusing: host workload policy" >&2
	exit 1
fi
if ! komizo-box workload release-bind --policy "$WORKLOAD_POLICY" --version "$version" --config-image "$ref" \
	--release "$release_dir/accepted.json" --compose "$staging/approved.json" --output "$staging/bound.json"; then
	echo "deploy: refusing: image identity differs from the authenticated release" >&2
	exit 1
fi
mv "$staging/bound.json" "$staging/compose.yml"

# The hostnames this app claims, one per line. This is the whole of what the
# app tells the reverse proxy: komizo writes the routes itself, so an app can
# no longer author server config, and no app's mistake can be another app's
# outage.
#
# Optional. An app with no hostnames publishes nothing and is reachable only
# from inside its own network -- a worker, a cron job, a queue consumer.
#
# A line may name where the hostname goes -- "api.example.com -> api" -- which
# is metadata for the interface and NOTHING ELSE. Routing reads the first field
# and ignores the rest, so the shared proxy is still pointed at <app>-gate
# whatever the arrow says: a wrong annotation mislabels a chart, it cannot
# misroute a request. The app is the only thing that knows which of its
# containers serves a name, and this is the only way it can say so without
# shipping config the server loads.
hostnames=""
hostmap=""
if [ -f "$staging/hostnames" ]; then
	hostmap="$(sed 's/#.*//' "$staging/hostnames" | tr -d '\r' | awk 'NF { print }')"
	hostnames="$(printf '%s\n' "$hostmap" | awk '{ print $1 }' | sed '/^$/d')"
fi

# Swap everything in, then validate. A broken config must not be left behind
# on a box that was working, so keep backups and put them back if a check
# fails -- including the reverse-proxy route, which is why this is a function
# rather than three copies of the same three lines.
#
# It puts FILES back and starts nothing, which is why every failure path below
# says "reverted, nothing restarted" and means it. That is now load-bearing
# rather than incidental: the start decision at the end of this script is the
# ONE place containers come up, and it is the one place that consults the stop
# marker. A failure path that grew a `docker compose up` to put the previous
# version back would become a second way to start an app somebody stopped, and
# the worse one to find -- it runs only when something else has already gone
# wrong, which is not when anybody is reading the log for this. If one is ever
# added, it has to read the marker the same way.
revert() {
	cat compose.yml.prev > compose.yml
	rm -f "$ROUTE_FILE"
	[ -f "$ROUTE_FILE.prev" ] && mv "$ROUTE_FILE.prev" "$ROUTE_FILE"
	rm -f hostnames
	[ -f hostnames.prev ] && mv hostnames.prev hostnames
	rm -f compose.yml.prev
	return 0
}

if [ "$SCOPED_ENV" = "fields-postgres-v2" ]; then
	# Once, under the lock taken above, immediately before the first app-config
	# mutation. The config image is still only in the staging directory.
	if ! /usr/local/bin/provision-scoped-env-$APP_NAME --check-compose "$staging/compose.yml"; then
		echo "deploy: refusing: scoped compose map" >&2
		exit 1
	fi
	komizo_scoped_env_ready || exit 1
	echo "deploy: scoped-generation=$expected_generation"
fi
cp compose.yml compose.yml.prev
rm -f "$ROUTE_FILE.prev"
[ -f "$ROUTE_FILE" ] && cp -a "$ROUTE_FILE" "$ROUTE_FILE.prev"
rm -f hostnames.prev
[ -f hostnames ] && cp -a hostnames hostnames.prev

cat "$staging/compose.yml" > compose.yml

# The reverse-proxy route, WRITTEN BY KOMIZO from the hostnames above.
#
# The app used to ship Caddy config and this script concatenated it into a file
# the shared proxy imported. That made every app on the box an author of one
# config loaded by one process: a syntax error anywhere failed the combined
# validate for everyone, and Caddy accepts exactly one global options block, so
# the second app to want one broke the first.
#
# Now the app declares names and nothing else. Everything a request meets after
# the hostname match is inside the app, in its own gate container.
#
# Replaced wholesale rather than merged: a hostname the app has stopped
# publishing must disappear, and the config image is the whole truth about this
# version.
rm -f "$ROUTE_FILE"
rm -f hostnames

if [ -n "$hostnames" ]; then
	# The SHAPE of each line, before any of it is believed.
	#
	# A line is a hostname, optionally followed by "-> <container>". Nothing
	# else. The routing itself only ever reads the first word, which means a
	# line of prose -- or a name with a stray space in it -- had its first word
	# quietly published as a hostname and the rest dropped. The CI action
	# rejects those; the host, which is the side that has to be right, did not.
	# A line is a name, optionally the container that serves it, optionally how
	# its certificate is obtained:
	#
	#   example.com
	#   api.example.com        -> api
	#   *.preview.example.com  -> api  on-demand
	#   *.preview.example.com         on-demand
	#
	# The mode is last so the arrow reads the way it did before, and so a file
	# written without one is still valid -- which is every file written so far.
	bad_line="$(printf '%s\n' "$hostmap" | awk '
		function mode(m) { return m == "on-demand" || m == "dns" || m == "passthrough" }
		NF == 0 { next }
		NF == 1 { next }
		NF == 2 && mode($2) { next }
		NF == 3 && $2 == "->" && $3 ~ /^[A-Za-z0-9_-]+$/ { next }
		NF == 4 && $2 == "->" && $3 ~ /^[A-Za-z0-9_-]+$/ && mode($4) { next }
		{ print; exit }')"
	if [ -n "$bad_line" ]; then
		revert
		echo "deploy: '$bad_line' is not a hostname, optionally '-> <container>', optionally one of: on-demand dns passthrough" >&2
		exit 1
	fi

	# Modes komizo accepts in a file but cannot yet serve. Refused here rather
	# than ignored: silently falling back to on-demand would hand a name the
	# certificate strategy it asked NOT to have, and the reason to ask is
	# usually that the other one is wrong for it. See docs/tls-design.md.
	unsupported="$(printf '%s\n' "$hostmap" | awk '
		{ for (i = 2; i <= NF; i++) if ($i == "dns" || $i == "passthrough") { print $1 " " $i; exit } }')"
	if [ -n "$unsupported" ]; then
		revert
		echo "deploy: $unsupported is not supported yet -- komizo only obtains certificates on demand. See docs/tls-design.md" >&2
		exit 1
	fi

	# Validated before it is written, because these land in a config the whole
	# box loads. Charset first, then shape: a leading '*.' is the only wildcard
	# Caddy takes, and anything else with a '*' in it would adapt to something
	# nobody meant.
	for h in $hostnames; do
		case "$h" in
			*[!A-Za-z0-9.*-]*)
				revert
				echo "deploy: '$h' is not a valid hostname (letters, digits, dot, hyphen, and a leading '*.')" >&2
				exit 1 ;;
		esac
		case "$h" in
			\*.*)
				case "${h#\*.}" in
					*\**)
						revert
						echo "deploy: '$h' has more than one wildcard; Caddy takes at most a leading '*.'" >&2
						exit 1 ;;
				esac ;;
			*\**)
				revert
				echo "deploy: '$h' puts a wildcard somewhere Caddy will not take one; only a leading '*.' works" >&2
				exit 1 ;;
		esac
	done

	# A hostname claimed twice on one box is two site blocks for one name, which
	# Caddy rejects outright -- so it would take down every app, not just the
	# two arguing. Caught here, against what the other apps have already
	# published, so the deploy that would cause it is the deploy that fails.
	#
	# Compared on the FIRST FIELD of each line, not the whole line: a recorded
	# hostname may carry an annotation ("api.example.com -> api"), and a
	# whole-line match silently misses every one that does -- which let the
	# duplicate through to fail later as an unexplained "routes do not load".
	#
	# The apps are enumerated from komizo's own records rather than by globbing
	# /srv, because an app is not required to live there: --app-dir puts it
	# anywhere, and such an app was neither checked against nor checked.
	# Held across the check AND the claim, box-wide.
	#
	# The deploy lock above is per-app, deliberately, so two different apps still
	# deploy at once -- they share nothing but the daemon. This one is the
	# exception: checking whether a hostname is taken and then taking it is a
	# read-then-write over state every app on the box shares, and two apps
	# claiming the same name at the same moment both passed the check. Neither
	# was told what had happened; they wrote their routes, and whichever ran
	# `caddy validate` second failed with "the routes generated from X do not
	# load" -- or, on the other interleaving, the FIRST app failed for a conflict
	# the second one caused. The good message this check exists to produce is the
	# one that got skipped.
	#
	# A short critical section, not the whole deploy: it is a scan of a few small
	# files and one write, so this costs concurrent deploys nothing measurable
	# while making the claim atomic.
	#
	# Skipped wherever the lock cannot be taken, exactly as the deploy lock is --
	# a busybox without the flock applet, or a /run this cannot write. Refusing
	# to deploy would trade a rare bad error message for a certain outage.
	claim_lock="/run/komizo/hostnames.lock"
	claimed_lock=0
	if command -v flock >/dev/null 2>&1 &&
		mkdir -p /run/komizo 2>/dev/null &&
		: > "$claim_lock" 2>/dev/null
	then
		exec 8>"$claim_lock"
		if flock -w 60 8; then
			claimed_lock=1
		else
			echo "deploy: waited 60s for another app to finish claiming hostnames" >&2
			revert
			exit 1
		fi
	fi

	for h in $hostnames; do
		# Pathname expansion is off (set -f) so $hostnames cannot glob; restore it
		# just for this scan of the other apps' state files, then turn it back off.
		set +f
		for _st in __STATE_DIR__/*.env; do
			[ -f "$_st" ] || continue
			_other="${_st##*/}"; _other="${_other%.env}"
			[ "$_other" != "$APP_NAME" ] || continue
			_odir="$(sed -n 's/^APP_DIR=//p' "$_st" | head -n 1)"
			[ -n "$_odir" ] || continue
			[ -f "$_odir/hostnames" ] || continue
			if awk '{ print $1 }' "$_odir/hostnames" 2>/dev/null | grep -qxF "$h"; then
				set -f
				if [ "$claimed_lock" = 1 ]; then exec 8>&-; fi
				revert
				echo "deploy: '$h' is already claimed by $_other" >&2
				exit 1
			fi
		done
		set -f
	done

	# Recorded WITH annotations: the interface reads this file to attribute
	# requests, and the arrows are the only place that mapping exists.
	#
	# This write is the claim, which is why the lock spans it: another app's scan
	# above reads exactly this file.
	printf '%s\n' "$hostmap" > hostnames
	if [ "$claimed_lock" = 1 ]; then exec 8>&-; fi

	# Wildcards get their OWN site block, because `tls { on_demand }` applies to
	# every name in the block it sits in. Folded together with the concrete
	# names, one wildcard would put the whole app behind the certificate gate --
	# and the gate exists to approve preview hostnames, so it says no to the
	# app's own front page. That failed as a TLS handshake error on names that
	# had worked for months, which is a long way from the cause.
	plain=""
	wild=""
	for h in $hostnames; do
		case "$h" in
			\*.*) [ -n "$wild" ] && wild="$wild, "; wild="$wild$h" ;;
			*) [ -n "$plain" ] && plain="$plain, "; plain="$plain$h" ;;
		esac
	done

	# A wildcard needs on-demand TLS, and on-demand TLS with no approval gate is a
	# remote denial of service: anyone can open TLS connections with random SNIs
	# and make the box attempt a certificate per name, exhausting its shared ACME
	# rate limit and breaking renewal for every real certificate on it. Refuse
	# rather than ship it -- the same "fail loudly" rule as dns/passthrough above.
	if [ -n "$wild" ] && ! grep -q 'ask ' "$PROXY_DIR/Caddyfile" 2>/dev/null; then
		revert
		echo "deploy: '$wild' is a wildcard, which needs on-demand TLS with an approval gate." >&2
		echo "deploy: the proxy has no gate configured, so this would let anyone exhaust the box's certificate rate limit." >&2
		echo "deploy: configure one with 'komizo proxy --tls-ask <url>' first. See docs/tls-design.md" >&2
		exit 1
	fi

	# Access logging, emitted into every site block this generates.
	#
	# Per-site because these ARE the only site blocks on the box -- Caddy has no
	# server-wide access log, and the shared Caddyfile has nothing but imports.
	#
	# To a FILE, not stdout. The proxy's stdout is what 'l' shows on its row,
	# and it is the only place a certificate or TLS failure is explained;
	# folding every request into it would cost that for a feature nobody had
	# asked for yet. A file also rotates itself and can be totalled by reading
	# it, rather than by asking docker for a stream.
	#
	# One file for the whole box rather than one per app: Caddy opens it once
	# and the aggregate names the app on every line anyway, via the hostname.
	access_log() {
		printf '\tlog {\n'
		printf '\t\toutput file /var/log/caddy/access.log {\n'
		printf '\t\t\troll_size 10mb\n'
		printf '\t\t\troll_keep 3\n'
		printf '\t\t}\n'
		printf '\t\tformat json\n'
		printf '\t}\n'
	}

	# The upstream is derived from the app name rather than declared, so it
	# cannot collide with another app's and cannot be pointed at one.
	{
		printf '# Written by komizo from %s.\n' "$ref"
		printf '# Edits here are lost on the next deploy.\n'
		# HSTS on every site (komizo terminates TLS and redirects HTTP->HTTPS, so
		# the header is always accurate), and the X-Forwarded-For handed upstream is
		# RESET to the direct client rather than appended to: Caddy otherwise keeps
		# a client-supplied value as the first entry, which is the one an app reads
		# for allowlisting and rate limiting -- i.e. a spoofable one.
		site() {
			printf '\theader Strict-Transport-Security "max-age=31536000"\n'
			printf '\theader >X-Komizo-Revision "%s"\n' "$version"
			access_log
			printf '\treverse_proxy %s-gate:80 {\n' "$APP_NAME"
			printf '\t\theader_up X-Forwarded-For {remote_host}\n'
			printf '\t}\n'
		}
		if [ -n "$plain" ]; then
			printf '%s {\n' "$plain"
			site
			printf '}\n'
		fi
		if [ -n "$wild" ]; then
			[ -n "$plain" ] && printf '\n'
			# A wildcard cannot get an ordinary certificate, so on-demand is the
			# only thing that works for one. It needs the ask endpoint the
			# server is configured with -- see 'komizo proxy --tls-ask'.
			printf '%s {\n' "$wild"
			printf '\ttls {\n\t\ton_demand\n\t}\n'
			site
			printf '}\n'
		fi
	} > "$ROUTE_FILE"
	chown root:root "$ROUTE_FILE"
	chmod 644 "$ROUTE_FILE"
fi
[ -f hostnames ] && { chown root:root hostnames; chmod 644 hostnames; }

rm -rf "$staging"

# APP_VERSION is passed in rather than read from .env: the file is only
# updated once this check passes, so without it compose would validate the
# new file against the previous version and warn about an unset variable.
if ! APP_VERSION="$version" docker compose config -q; then
	revert
	echo "deploy: compose.yml from $ref is not valid -- reverted, nothing restarted" >&2
	exit 1
fi

# An app that publishes routes needs somewhere to publish them TO. Without this
# the route would land on disk, nothing would read it, and the deploy would
# report success -- a green pipeline and a dead domain, with nothing in the log
# saying why. Every other silent failure this script guards against is treated
# the same way.
#
# An app with no route is unaffected: a worker or a cron job is not meant to
# be reachable, and a box with no proxy can still run one.
proxy_up=0
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$PROXY_CONTAINER"; then
	proxy_up=1
fi
ingress_network="$(komizo-box workload ingress-name --policy "$WORKLOAD_POLICY")"
if [ "$proxy_up" = 1 ] && [ "$ingress_network" != "${SHARED_NETWORK:-edge}" ]; then
 if docker network inspect "$ingress_network" >/dev/null 2>&1; then
  [ "$(docker network inspect "$ingress_network" --format '{{index .Labels "io.komizo.app"}}')" = "$APP_NAME" ] || die "app ingress has no approved ownership label"
 else
  docker network create --internal --label "io.komizo.app=$APP_NAME" "$ingress_network" >/dev/null
 fi
 if ! docker inspect --format '{{range $name, $cfg := .NetworkSettings.Networks}}{{$name}}{{println}}{{end}}' "$PROXY_CONTAINER" | grep -qxF "$ingress_network"; then
  docker network connect "$ingress_network" "$PROXY_CONTAINER"
 fi
fi

if [ -f "$ROUTE_FILE" ] && [ "$proxy_up" = 0 ]; then
	revert
	echo "deploy: this app publishes routes, but the reverse proxy is not running." >&2
	echo "deploy: nothing would serve them, so this is a failure rather than a no-op." >&2
	echo "deploy: start it with 'komizo proxy --host <this box>'." >&2
	echo "deploy: reverted, nothing restarted" >&2
	exit 1
fi

# Validate BEFORE anything restarts, and validate it the way the proxy will
# actually read it: inside the container, against the whole imported config.
#
# komizo writes this file, so it is not checking the app's syntax any more --
# the app has none to get wrong. What is left is everything about the file that
# depends on its NEIGHBOURS: a hostname two apps both claim, a name that has
# become invalid since it was accepted, a proxy config that drifted. The
# hostname check above catches the common case with a better message; this
# catches the rest, and costs one exec.
if [ "$proxy_up" = 1 ]; then
	if ! caddy_err="$(docker exec "$PROXY_CONTAINER" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1)"; then
		revert
		echo "deploy: the routes generated from $ref do not load -- reverted, nothing restarted" >&2
		printf '%s\n' "$caddy_err" | sed 's/^/  /' >&2
		exit 1
	fi
fi

# The .prev files are deliberately still here. They used to be deleted at this
# point, on the reasoning that everything after it had been validated -- but
# `docker compose pull` comes next and can fail for a reason nothing above can
# see (a tag that exists for the config image but not for an app image). That
# left the box with the NEW compose.yml and the NEW route file on disk, their
# backups already gone, and only .env restored.
#
# The route file is the part that matters. It is valid, it is in the directory
# the shared proxy imports, and while this deploy does not reload Caddy, the
# next deploy of ANY app on the box does -- at which point the hostnames of a
# stack that never started begin resolving to a gate that is not there. A green
# "nothing restarted" and a domain that 502s, with nothing connecting the two.
#
# So they survive until the deploy has actually happened. See the cleanup below.

# Committed only once the config for this version is in place and valid, so a
# deploy that fails earlier leaves the box claiming the version it is actually
# still running. Persisted so a later manual 'docker compose up -d' keeps this
# commit instead of drifting back to :latest.
#
# WRITTEN EVEN WHEN NOTHING IS GOING TO BE STARTED, which is the half of the
# start decision below that is easy to get backwards, so the reasoning is here
# rather than there.
#
# A deploy to a stopped app pulls and commits and does not start. The point of
# doing the first two at all is that the NEXT `komizo start` brings up what was
# deployed: start runs `docker compose up -d`, which reads ${APP_VERSION} out of
# this file to resolve every image, so the version recorded here is the version
# that comes up. Leave it at the old one and the box has silently deployed
# nothing -- it pulled an image, wrote the new compose.yml from the new config
# image, and then pinned it to the previous tag, which is a stack assembled from
# two different commits and no message anywhere saying so.
#
# So a stopped app's recorded version is what was last DEPLOYED to it, not what
# it was last running. That reads oddly in a report next to a stopped app, and
# it is still the honest field: the alternative is a version nobody can act on,
# because the deploy that fetched the config for it has already happened and is
# not going to happen again.
# .env is read by the pull/up below for ${APP_VERSION} substitution, so it has
# to be written first -- but a pull that then fails would leave .env claiming a
# version that never started. Back it up and put it back on failure.
cp .env .env.komizo.bak 2>/dev/null || true
komizo-box workload operation --policy "$WORKLOAD_POLICY" --version "$version" --previous "$previous" --phase configured
if grep -q '^APP_VERSION=' .env; then
	sed -i "s|^APP_VERSION=.*|APP_VERSION=$version|" .env
else
	printf 'APP_VERSION=%s\n' "$version" >> .env
fi

# Pull profile-disabled operational images too. Profiles decide what `up`
# starts, not whether a reviewed release is complete on the host; a later
# allowlisted task must never need registry credentials of its own.
if ! docker compose --profile '*' pull; then
	mv -f .env.komizo.bak .env 2>/dev/null || rm -f .env.komizo.bak
	# The whole config goes back, not just .env: compose.yml, the hostnames
	# record and the generated route are all this version's and none of them
	# was ever served.
	revert
	echo "deploy: 'docker compose pull' failed -- reverted, nothing restarted" >&2
	exit 1
fi
rm -f .env.komizo.bak

# A DEPLOY MUST NOT START AN APP SOMEBODY STOPPED.
#
# architecture.md §6 keeps STOPPED as durable state on the box for two reasons.
# One is that a stopped app pages nobody. The other is this one -- "a deploy
# while stopped pulls the image without starting it" -- and until now this line
# was `docker compose up -d` with nothing in front of it, so a CI deploy brought
# an app back up that a person had deliberately taken down. Nobody ran a
# command; a merge to main did it.
#
# The failure that makes it urgent rather than untidy is what it does to PAGING.
# `komizo stop` writes STOPPED into this record (komizo#48), and box/diagnose.go
# keys the app_down problem on exactly that marker. An unconditional `up -d`
# therefore leaves the app RUNNING with STOPPED=1 still set: nothing reconciles
# the marker against the containers that are actually up, `komizo start` is a
# different path and never runs, and the only thing that clears it is somebody
# starting an app they can plainly see is already started. From that moment the
# app never pages again -- for a real outage, indefinitely, with nothing
# anywhere saying that alerting was switched off. A deliberate stop reported as
# a fault is loud and wrong in the safe direction; this is silent and wrong in
# the other one.
#
# READ AS LATE AS POSSIBLE, and this is the last thing decided before any
# container moves. Everything above -- the pull of the config image, the
# validation, the route claim, `docker compose pull` -- can take minutes on a
# slow link, and a stop that arrives during it is a decision made with full
# knowledge that a deploy is running. Reading the record at the top of the
# script would answer with what was true before the operator acted, which is the
# same window, merely wider.
#
# No lock, and this is a read rather than a rewrite. Both writers of this record
# replace it by rename and take the per-app lock around it -- box/stopped.go on
# the Go side, and the block in the provisioning script that installed THIS one
# (`komizo add` rewrites the record; it is not part of the deploy script), both
# from komizo#48. So a single read always sees one complete file and never a
# half-written one. Taking the lock here would buy nothing and would make a
# deploy wait out a `komizo add`.
#
# `[ -f ]` rather than a `2>/dev/null` over the read, and the difference is what
# happens to a record that exists and cannot be read. Suppressing stderr treats
# "no such app record" and "this box's state directory is broken" as the same
# silent empty answer, and both come out as "not stopped" -- so the one case
# where somebody needs to be told is the one that says nothing. A missing record
# is ordinary and asks nothing; anything else now prints sed's complaint into
# the deploy log. The direction is unchanged either way: an unreadable record
# starts the app, because refusing to deploy on a box whose state directory has
# gone is a much wider failure than the one it would prevent, and an app with no
# readable record is not in the report and cannot page in the first place.
#
# `tr -d '\r'` because a CR is invisible and this is a comparison against a
# literal. A record that picked up CRLF makes this read "1\r", which is not "1",
# and the deploy would decide the app was never stopped and start it -- the
# whole defect back, from a difference nobody can see in the file. `head -n 1`
# because every other reader of these records is first-wins, and a reader that
# took the last line would disagree with all of them about the same file.
#
# The marker is left ALONE either way. A deploy is not a decision about whether
# an app should be running; it is a decision about what it should run when it
# is. Clearing the marker here would be this same bug spelled differently -- CI
# overruling a person -- and setting one would stop an app nobody asked to stop.
stopped=""
if [ -f "$STATE_FILE" ]; then
	stopped="$(sed -n 's/^STOPPED=//p' "$STATE_FILE" | tr -d '\r' | head -n 1)"
fi
if [ "$stopped" = "1" ]; then
	# SAID OUT LOUD, in both a machine-readable form and a human one. Without
	# this, a deploy that deliberately leaves an app down is indistinguishable
	# in a CI log from a deploy that started it -- both are green, and the only
	# difference is a `docker compose ps` further down that a person has to
	# already suspect something to go and read. `started=` is printed on BOTH
	# branches so a caller can tell "this deploy did not start the app" from
	# "this deploy ran an older script that could not tell you", which one line
	# printed only in the unusual case cannot express.
	echo "deploy: started=no"
	echo "deploy: $APP_NAME is recorded as stopped, so $ref was pulled and APP_VERSION=$version committed, but nothing was started."
	echo "deploy: 'komizo start --host <this box> --app $APP_NAME' brings up $version."
else
	komizo-box workload operation --policy "$WORKLOAD_POLICY" --version "$version" --previous "$previous" --phase activating
	docker compose up -d --remove-orphans --pull never

	# AND READ THE MARKER AGAIN, because a stop can land between the read above
	# and the `up -d` that just ran. komizo#62.
	#
	# The interleaving: this deploy reads the marker and sees nothing; `komizo
	# stop` arrives and writes STOPPED=1 FIRST (komizo#48 chose that ordering
	# deliberately, so the marker is on the record before containers exit); its
	# `compose stop` brings them down; and the `up -d` above brings them back.
	# End state: running, with STOPPED=1 recorded.
	#
	# WHY THAT END STATE IS WORTH A SECOND READ. box/diagnose.go keys app_down
	# on the marker, so an app in it never pages again -- for a real outage,
	# indefinitely, with nothing anywhere saying alerting was switched off.
	# Nothing else reconciles the marker against the containers that are
	# actually up, and `komizo start` is the only thing that clears it, which
	# nobody runs against an app they can see is running. A narrow window is
	# fine; a narrow window onto "alerting silently off forever" is not.
	#
	# NOT A LOCK. lockRecord in box/stopped.go is best-effort with a timeout and
	# proceeds anyway, so it is explicitly not a barrier -- and holding one
	# across `up -d` would make every deploy wait out a stop while moving the
	# race rather than removing it. This is the cheap direction: do the work,
	# look again, and undo if the world changed underneath.
	#
	# THE STOP WINS, NOT THE DEPLOY. Somebody asked for this app to be down and
	# said so on the record; a deploy is a decision about WHAT an app runs, not
	# whether it should be running -- the same argument the comment above makes
	# for leaving the marker alone. So the containers go back down and the
	# marker stays. Restarting them instead would be CI overruling a person,
	# which is the defect komizo#56 exists to prevent.
	stopped_after=""
	if [ -f "$STATE_FILE" ]; then
		stopped_after="$(sed -n 's/^STOPPED=//p' "$STATE_FILE" | tr -d '\r' | head -n 1)"
	fi
	if [ "$stopped_after" = "1" ]; then
		docker compose stop
		echo "deploy: started=no"
		echo "deploy: $APP_NAME was stopped while this deploy was running, so it has been brought back down and stays recorded as stopped."
		echo "deploy: 'komizo start --host <this box> --app $APP_NAME' brings up $version."
	else
		# AFTER the start AND after the re-read, not before either. `set -e` ends
		# the script on a failed `up -d`, so an echo above it would claim the app
		# started immediately before the output showing it did not -- and the
		# machine-readable half would be the last `started=` a caller parsed.
		#
		# EXACTLY ONE `started=` LINE IS PRINTED on every path through this
		# script, which is why the undo above prints its own rather than
		# correcting this one afterwards. A caller parsing `started=` takes the
		# last it sees, so yes-then-no would be right by accident and wrong the
		# moment anybody reads the first match instead -- and the test that
		# forbids both lines appearing is asserting exactly that invariant.
		echo "deploy: started=yes"
	fi
fi

# Now the deploy has happened, so there is nothing left to go back to. Dropped
# here rather than before the pull, which is the bug described above.
rm -f compose.yml.prev hostnames.prev "$ROUTE_FILE.prev"

# Deliberately NOT pruning images here. 'docker image prune' is machine-wide,
# and this script is per-app: every other step targets this app's own name, so
# one command that reaches across every app on the box does not belong in it.
#
# It also would not do the job. Images are tagged by commit, so the version we
# just replaced is still TAGGED and never dangling -- almost nothing a komizo
# deploy leaves behind is what a bare prune collects. What actually fills the
# disk is old tagged images, and reclaiming those needs '-a --filter until=...',
# which is far too blunt to run unattended in the middle of a deploy.
#
# Disk is a SERVER concern. It belongs wherever server-wide upkeep ends up
# living, not in the one path a leaked deploy key is allowed to invoke.

# Reload AFTER the containers are up, so the upstream the route names is
# already resolvable when Caddy re-reads its config. Caddy does not watch the
# imported files, so without this the route sits on disk doing nothing.
#
# Validated above, so a failure here is unexpected -- but Caddy keeps its
# previous config when a reload fails, so the other apps on this box keep
# serving either way. Reported rather than fatal: by now this app's containers
# are up -- or deliberately are not, see the start decision above -- and failing
# the deploy would misreport whichever it is.
#
# Reloaded EVEN WHEN nothing was started, because the alternative is worse. A
# stopped app's hostnames already resolve to a gate that is not running -- that
# is what stopping it did, and this deploy changed nothing about it. What this
# deploy may have changed is WHICH hostnames it claims, and that is now written
# to disk in a directory the shared proxy imports. Skipping the reload does not
# withhold it; it defers it to whenever the next deploy of any OTHER app on the
# box reloads Caddy, at which point somebody else's pipeline publishes this
# app's route change. That is the same trap the .prev files above describe, and
# the fix is the same: let the change land where the log for it is.
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$PROXY_CONTAINER"; then
	if docker exec "$PROXY_CONTAINER" caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then
		echo "deploy: reverse proxy reloaded"
	else
		echo "deploy: the proxy would not reload; candidate routing failed" >&2
		exit 1
	fi
fi

# Show the resulting topology. Without this a compose.yml that silently drops
# or renames a service looks identical in the log to one that changed nothing.
#
# For an app left down this lists what was there BEFORE the deploy -- exited
# containers on the previous version, beside an APP_VERSION that has moved on.
# That is the true state of the box and it is worth reading as one: the config
# is the new version's, the images are pulled, and the containers are still the
# old ones because nothing has recreated them yet. The `started=no` lines above
# are what say so in words.
docker compose ps --format 'table {{.Service}}\t{{.Image}}\t{{.Status}}'
# Record only a completed deployment, under the shared app lock. Repeating
# the same revision retains the earlier rollback record. An upgraded host
# without a record cannot infer a rollback tag from a same-version redeploy.
# --- retention record begin ---
komizo_record_image_retention() {
	[ "$previous" != "$version" ] || return 0
	case "$previous" in *[!A-Za-z0-9._-]*) return 1 ;; esac
	[ ! -L .komizo-image-retention ] || return 1
	umask 077
	printf 'CURRENT=%s\nPREVIOUS=%s\n' "$version" "$previous" > .komizo-image-retention.tmp || return 1
	chmod 600 .komizo-image-retention.tmp || return 1
	mv -f .komizo-image-retention.tmp .komizo-image-retention || return 1
}
# --- retention record end ---
if ! komizo_record_image_retention; then
	echo "deploy: WARNING -- could not record image retention; pruning remains unavailable" >&2
fi
if [ "$stopped" = 1 ] || [ "${stopped_after:-}" = 1 ]; then
	operation_phase=prepared_stopped
else
	operation_phase=activated
fi
komizo-box workload operation --policy "$WORKLOAD_POLICY" --version "$version" --previous "$previous" --phase "$operation_phase"
if [ "$operation_phase" = activated ]; then
	if ! komizo-box workload ready --policy "$WORKLOAD_POLICY" --version "$version" --previous "$previous" --compose "$APP_DIR/compose.yml"; then
		# Record failures that occur before the readiness checker can journal.
		komizo-box workload operation --policy "$WORKLOAD_POLICY" --version "$version" --previous "$previous" --phase readiness_failed
		journal_finished=1
		exit 1
	fi
fi
journal_finished=1

KOMIZO_DEPLOY_EOF

# The install-time values. Every one is charset-checked above, and none of
# those charsets contain the '|' this uses as its delimiter.
sed -i \
	-e "s|__APP_NAME__|$APP_NAME|g" \
	-e "s|__APP_DIR__|$APP_DIR|g" \
	-e "s|__CONFIG_IMAGE__|$CONFIG_IMAGE|g" \
	-e "s|__PROXY_CONTAINER__|$PROXY_CONTAINER|g" \
	-e "s|__PROXY_DIR__|$PROXY_DIR|g" \
	-e "s|__ROUTES_DIR__|$ROUTES_DIR|g" \
	-e "s|__STATE_DIR__|$STATE_DIR|g" \
	-e "s|__SCOPED_ENV__|$SCOPED_ENV|g" \
	"$DEPLOY_BIN.tmp"
if grep -q '__[A-Z_][A-Z_]*__' "$DEPLOY_BIN.tmp"; then
	rm -f "$DEPLOY_BIN.tmp"
	die "the generated deploy script still has placeholders in it -- this is a komizo bug"
fi
mv "$DEPLOY_BIN.tmp" "$DEPLOY_BIN"
chown root:root "$DEPLOY_BIN"
chmod 755 "$DEPLOY_BIN"

# --- 3a1. App image retention ----------------------------------------------
# App accounts receive this fixed command, never Docker socket access. The
# caller cannot choose a family or tags; the deploy wrapper writes that state.
#
# Config images pin service images BY DIGEST, and Docker stores a digest pull
# with no tag. Retention therefore works on image IDs: it keeps every image a
# container uses, the current and rollback config tags, and every image the
# current and rollback compose files name, and removes the rest of the family
# whether tagged or not. Skipping untagged images, as an earlier version did,
# left every superseded digest-pinned gate image on disk forever.
log "Installing $PRUNE_BIN"
cat > "$PRUNE_BIN.tmp" <<'KOMIZO_PRUNE_EOF'
#!/bin/sh
# Written by komizo. Only this app's trusted deployment record selects tags.
set -eu
set -f
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG
APP_DIR="__APP_DIR__"
CONFIG_IMAGE="__CONFIG_IMAGE__"
refuse() { echo "prune: refusing: $*" >&2; exit 1; }
dry_run=0
case $# in
	0) ;;
	1) [ "$1" = --dry-run ] || refuse "only --dry-run is accepted"; dry_run=1 ;;
	*) refuse "unexpected arguments" ;;
esac
case "$CONFIG_IMAGE" in
	*/?*-config) prefix=${CONFIG_IMAGE%config} ;;
	*) refuse "config repository does not identify an app image family" ;;
esac
# Deploy and prune serialize on the same app lock. Unlike deployment, pruning
# cannot proceed if locking is unavailable: retaining images is safe.
command -v flock >/dev/null 2>&1 || refuse "app locking unavailable"
mkdir -p /run/komizo
exec 9>"/run/komizo/deploy-__APP_NAME__.lock"
flock -w 300 9 || refuse "app lock busy"
exec 6>/run/komizo/operation.lock
flock -w 300 6 || refuse "host operation busy"
cd "$APP_DIR"
record=.komizo-image-retention
[ ! -L "$record" ] && [ -f "$record" ] || refuse "trusted deployment record unavailable"
[ "$(wc -l < "$record" | tr -d ' ')" = 2 ] || refuse "malformed deployment record"
[ "$(grep -c '^CURRENT=' "$record")" = 1 ] || refuse "malformed current record"
[ "$(grep -c '^PREVIOUS=' "$record")" = 1 ] || refuse "malformed rollback record"
current=$(sed -n 's/^CURRENT=//p' "$record")
previous=$(sed -n 's/^PREVIOUS=//p' "$record")
case "$current" in ''|*[!A-Za-z0-9._-]*) refuse "invalid current tag" ;; esac
case "$previous" in *[!A-Za-z0-9._-]*) refuse "invalid rollback tag" ;; esac
[ ! -L .env ] && [ -f .env ] || refuse "deployment identity unavailable"
live=$(sed -n 's/^APP_VERSION=//p' .env)
[ "$live" = "$current" ] || refuse "deployment identity differs from retention record"
[ ! -L compose.yml ] && [ -f compose.yml ] || refuse "current compose unavailable"
work=$(mktemp -d) || refuse "no scratch directory"
cid=""
cleanup() {
	[ -z "$cid" ] || docker rm -v "$cid" >/dev/null 2>&1 || :
	rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP PIPE
# Prints one image reference per line from a compose file, with the
# deployment's APP_VERSION substituted. Fails if any reference still holds a
# variable or anything else that is not a plain image reference, so a compose
# this cannot read retains everything rather than guessing. That includes an
# image key anywhere but at the start of its own line (a one-line service, a
# JSON without the bounded host reader) and a compose naming no image at all.
compose_refs() {
	# Host admission writes canonical JSON. Do not ask Compose to evaluate
	# includes or env files just to discover retention references.
	first=$(sed -n '/[^[:space:]]/{s/^[[:space:]]*//;p;q;}' "$1")
	case "$first" in
	\{*) /usr/local/bin/komizo-box workload image-refs < "$1"; return $? ;;
	esac
	if grep -v '^[[:space:]]*#' "$1" | grep -v '^[[:space:]]*image:' | grep -q "image[\"']*[[:space:]]*:"; then
		return 1
	fi
	sed -n 's/^[[:space:]]*image:[[:space:]]*//p' "$1" | sed \
		-e 's/[[:space:]]#.*$//' -e 's/[[:space:]]*$//' \
		-e 's/^"\(.*\)"$/\1/' -e "s/^'\\(.*\\)'\$/\\1/" \
		-e "s|\\\${APP_VERSION\\(:[?-][^}]*\\)\\{0,1\\}}|$2|g" \
		-e "s|\\\$APP_VERSION|$2|g" > "$work/refs" || return 1
	while IFS= read -r ref; do
		case "$ref" in ''|*[!A-Za-z0-9._/:@-]*) return 1 ;; esac
		printf '%s\n' "$ref"
	done < "$work/refs"
	[ -s "$work/refs" ]
}
# Resolve every running/stopped container to its immutable image ID. No
# removal is attempted if any reference cannot be established.
containers=$(docker ps -aq) || refuse "cannot list containers"
used_ids=$(
	for container in $containers; do
		docker inspect --format '{{.Image}}' "$container" || exit 1
	done
) || refuse "cannot inspect containers"
images=$(docker images --no-trunc --format '{{.Repository}} {{.Tag}} {{.ID}}') || refuse "cannot list images"
ids=$(printf '%s\n' "$images" | awk 'NF == 3 { print $3 }' | sort -u)
: > "$work/names"
if [ -n "$ids" ]; then
	# shellcheck disable=SC2086 # IDs are split on purpose; globbing is off.
	docker image inspect --format '{{.Id}} {{join .RepoTags " "}} {{join .RepoDigests " "}}' $ids > "$work/names" || refuse "cannot inspect images"
fi
# The images both deployments need, named by their compose files: the live
# one on disk (its identity is checked above) and the rollback one read from
# its retained config image.
refs=$(compose_refs compose.yml "$current") || refuse "current compose names an image this cannot resolve"
untagged=1
if [ -n "$previous" ]; then
	if printf '%s\n' "$images" | awk -v repo="$CONFIG_IMAGE" -v tag="$previous" '$1 == repo && $2 == tag { found=1 } END { exit !found }'; then
		cid=$(docker create --pull never --entrypoint /nonexistent "$CONFIG_IMAGE:$previous") || refuse "cannot open rollback config $CONFIG_IMAGE:$previous"
		docker cp "$cid:/config/compose.yml" "$work/previous.yml" >/dev/null 2>&1 || refuse "rollback config $CONFIG_IMAGE:$previous has no readable compose.yml"
		docker rm -v "$cid" >/dev/null 2>&1 || refuse "cannot remove the rollback config reader"
		cid=""
		[ ! -L "$work/previous.yml" ] && [ -f "$work/previous.yml" ] || refuse "rollback compose.yml is not a regular file"
		prev_refs=$(compose_refs "$work/previous.yml" "$previous") || refuse "rollback compose names an image this cannot resolve"
		refs="$refs
$prev_refs"
	else
		# Nothing can say which untagged images the rollback needs, so all of
		# them stay. Tagged images keep their tag-based rules.
		untagged=0
		echo "prune: rollback config $CONFIG_IMAGE:$previous is not on this host; untagged images retained"
	fi
fi
printf '%s\n' "$refs" > "$work/refs"
# Maps each reference to a local image ID through RepoTags/RepoDigests.
# A digest also matches an image whose ID is that digest (containerd store).
compose_ids=$(awk '
	NR == FNR { known[$1] = 1; for (i = 2; i <= NF; i++) name[$i] = $1; next }
	$0 == "" { next }
	{
		ref = $0
		at = index(ref, "@")
		if (at) {
			repo = substr(ref, 1, at - 1); digest = substr(ref, at + 1)
			sub(/:[^\/]*$/, "", repo)
			ref = repo "@" digest
			if (digest in known) print digest
		} else if (ref !~ /:[^\/]*$/) {
			ref = ref ":latest"
		}
		if (ref in name) print name[ref]
	}' "$work/names" "$work/refs") || refuse "cannot resolve compose image references"
keep=$(printf '%s\n%s\n' "$used_ids" "$compose_ids")
removed=0
candidates=0
failed=0
seen=" "
while IFS=' ' read -r repo tag id; do
	case "$repo" in "$prefix"*) ;; *) continue ;; esac
	case "$tag" in
		''|'<none>')
			[ "$untagged" = 1 ] || continue
			# Already handled through its tag, or referenced outside the family.
			if printf '%s\n' "$images" | awk -v image="$id" '$3 == image && $2 != "" && $2 != "<none>" { found=1 } END { exit !found }'; then
				continue
			fi
			case "$seen" in *" $id "*) continue ;; esac
			seen="$seen$id "
			target=$id
			label="$repo (untagged $id)"
			;;
		*)
			[ "$tag" = "$current" ] && continue
			[ -n "$previous" ] && [ "$tag" = "$previous" ] && continue
			target=$repo:$tag
			label=$repo:$tag
			;;
	esac
	# IDs of current/rollback tags can also have aliases; keep all such IDs.
	if printf '%s\n' "$images" | awk -v image="$id" -v family="$prefix" -v current="$current" -v previous="$previous" '
		index($1, family) == 1 && $3 == image && ($2 == current || (previous != "" && $2 == previous)) { found=1 }
		END { exit !found }
	'; then
		continue
	fi
	if printf '%s\n' "$keep" | grep -qxF "$id"; then continue; fi
	candidates=$((candidates + 1))
	if [ "$dry_run" = 1 ]; then
		echo "prune: would remove $label"
	elif docker image rm "$target" >/dev/null 2>&1; then
		removed=$((removed + 1))
		echo "prune: removed $label"
	else
		failed=$((failed + 1))
		echo "prune: removal refused; kept $label" >&2
	fi
done <<IMAGES
$images
IMAGES
echo "prune: family=$prefix current=$current previous=$previous dry-run=$dry_run candidates=$candidates removed=$removed failed=$failed"
[ "$failed" = 0 ]
KOMIZO_PRUNE_EOF
sed -i \
	-e "s|__APP_NAME__|$APP_NAME|g" \
	-e "s|__APP_DIR__|$APP_DIR|g" \
	-e "s|__CONFIG_IMAGE__|$CONFIG_IMAGE|g" "$PRUNE_BIN.tmp"
if grep -q '__[A-Z_][A-Z_]*__' "$PRUNE_BIN.tmp"; then
	rm -f "$PRUNE_BIN.tmp"
	die "the generated prune script still has placeholders"
fi
mv "$PRUNE_BIN.tmp" "$PRUNE_BIN"
chown root:root "$PRUNE_BIN"
chmod 755 "$PRUNE_BIN"

# --- 3a2. Preview path -----------------------------------------------------
# Two root-owned helpers, installed for apps that have previews and reachable
# from the deploy account through doas.
#
# THEY USED TO BE HAND-INSTALLED, with hand-added doas rules, and those rules
# were written inside komizo's own managed block. `komizo update` rewrites
# that block, so the next update deleted them: gdam's previews began failing
# on "doas: Operation not permitted" in a step that had worked minutes
# earlier. A feature that needs a privilege is a feature komizo has to
# install, or the privilege goes missing the next time komizo tidies up.
#
# SHARED PATHS, not per-app ones, unlike deploy-<app> and set-secret-<app>.
# Both scripts scope themselves to the caller's own app through DOAS_USER --
# komizo-gdam may only preview gdam -- so one copy is safe, and these are the
# paths the preview action already invokes. Removal is therefore conditional
# on no OTHER app still having previews: taking them away because one app
# opted out would break every app that had not.
PREVIEW_RUN_BIN=/usr/local/bin/komizo-preview
PREVIEW_STACKENV_BIN=/usr/local/bin/write-preview-stackenv
if [ "$PREVIEW" = "1" ]; then
	log "Installing $PREVIEW_RUN_BIN and $PREVIEW_STACKENV_BIN"
	cat > "$PREVIEW_RUN_BIN.tmp" <<'KOMIZO_PREVIEW_RUN_EOF'
# __PREVIEW_RUN_BODY__
KOMIZO_PREVIEW_RUN_EOF
	cat > "$PREVIEW_STACKENV_BIN.tmp" <<'KOMIZO_PREVIEW_STACKENV_EOF'
# __PREVIEW_STACKENV_BODY__
KOMIZO_PREVIEW_STACKENV_EOF
	mv "$PREVIEW_RUN_BIN.tmp" "$PREVIEW_RUN_BIN"
	mv "$PREVIEW_STACKENV_BIN.tmp" "$PREVIEW_STACKENV_BIN"
	chown root:root "$PREVIEW_RUN_BIN" "$PREVIEW_STACKENV_BIN"
	chmod 755 "$PREVIEW_RUN_BIN" "$PREVIEW_STACKENV_BIN"
else
	rm -f "$PREVIEW_RUN_BIN.tmp" "$PREVIEW_STACKENV_BIN.tmp"
	# ONLY ON AN EXPLICIT REVOKE, and only when nothing else on the box
	# previews.
	#
	# PREVIEW_SET is the whole point of this condition. `--preview` is new, so
	# every app on every existing box records PREVIEW=0 the first time it is
	# read -- and the first `komizo update` after this feature shipped
	# therefore deleted the two helpers that were already there, hand-installed
	# and working. gdam's previews broke for the second time in one night, from
	# the change written to stop exactly that happening.
	#
	# It is the same rule as the doas block adopting rules komizo did not
	# write: an update must not take away a capability nobody asked it to
	# remove. A default of "off" is not a request to uninstall. Only
	# `--preview=false`, which sets PREVIEW_SET, is.
	if [ "$PREVIEW_SET" = "1" ]; then
		# This app's own record was rewritten above with PREVIEW=0, so a read
		# over the state directory answers about the others.
		still_wanted=0
		for _st in "$STATE_DIR"/*.env; do
			[ -f "$_st" ] || continue
			[ "$(sed -n 's/^PREVIEW=//p' "$_st" | tr -d '\r' | head -n 1)" = "1" ] || continue
			still_wanted=1
			break
		done
		if [ "$still_wanted" = "0" ]; then
			rm -f "$PREVIEW_RUN_BIN" "$PREVIEW_STACKENV_BIN"
		fi
	fi
fi

# --- 3b. Secret path -------------------------------------------------------
# Write-only by construction: the value arrives on stdin and is never echoed,
# and secrets.env stays 600 root. So CI can rotate a credential without ever
# being able to read the ones already there -- which is the property that makes
# automated secret delivery a bounded grant rather than "the deploy key can
# read production".
#
# The value is NOT passed as an argument: arguments are visible in the host's
# process list to any other user on the box.

log "Installing $SECRET_BIN"
cat > "$SECRET_BIN.tmp" <<'KOMIZO_SECRET_EOF'
#!/bin/sh
# Written by komizo. Edits are lost the next time the app is set up.
set -eu

# doas always runs this as root, so in production every chown below is a no-op
# restating what umask 077 already produced. The only caller that is not root
# is a test driving the script against a fixture: it cannot chown and does not
# need to, because the files it creates are already its own. Same reasoning
# and same helper as alpine-unset-secret.sh.
own_root() {
	[ "$(id -u)" = 0 ] || return 0
	chown "$1" "$2"
}

# Two shapes, one binary and therefore one doas grant: an env value in
# secrets.env, or a FILE under secrets/.
#
# The file shape exists because the env shape cannot carry what half these
# apps need. The refusal below is explicit about it -- "a value that contains
# a newline, which an env file cannot represent" -- and every multi-line
# credential in the portfolio went round it the same way: somebody wrote the
# file onto the box by hand. An OpenAI key that has to be MOUNTED rather than
# exported, an age backup identity, a PEM, a postgres owner password the
# database container reads before the app exists. Ten such files across five
# apps, none of them delivered by anything, none rotatable without SSH.
#
# secrets/ rather than a new directory, because that is already where those
# files are and what the compose files already mount. Delivering them through
# komizo is then a change of WRITER, not a change of layout: nothing in an
# app has to move.
#
# Same binary as the env shape on purpose. A separate one would need its own
# doas rule, and the grant is the same grant -- write this app's secrets,
# never read them.
shape="env"
uid=""
while :; do
	case "${1:-}" in
		--file) shape="file"; shift ;;
		# The container that reads a mounted secret is usually not root, and a
		# 0600 root file is unreadable to it: cazper's openai_api_key is owned
		# by nobody for exactly that reason. Numeric only -- the host does not
		# have to know the container's user names, and a numeric id is what
		# the mount compares against.
		--uid) uid="${2:-}"; shift 2 ;;
		*) break ;;
	esac
done
name="${1:-}"
cd "__APP_DIR__"

case "$uid" in
	'') ;;
	*[!0-9]*) echo "set-secret: --uid must be numeric" >&2; exit 1 ;;
esac
if [ -n "$uid" ] && [ "$shape" != "file" ]; then
	echo "set-secret: --uid applies only to --file" >&2
	exit 1
fi

# This profile's values are host-local. A stale doas grant must not write them.
profile="$(sed -n 's/^SCOPED_ENV=//p' "__STATE_FILE__" | tr -d '\r' | head -n 1)"
if [ "$profile" = "fields-postgres-v2" ]; then
	echo "set-secret: refusing: fields-postgres-v2 does not accept deploy-user secrets" >&2
	exit 1
fi

if [ "$shape" = "file" ]; then
	# A FILENAME, not an env-var name, so the charset differs from the one
	# below -- dots and hyphens are ordinary in "postgres-owner.env" and
	# "recipient.pem". What it must not do is escape secrets/: no slash, no
	# leading dot (which would hide it and could spell ".."), nothing that is
	# not a plain name.
	case "$name" in
		''|.|..) echo "set-secret: invalid file name" >&2; exit 1 ;;
		.*|-*) echo "set-secret: file name must not start with '.' or '-'" >&2; exit 1 ;;
		*[!A-Za-z0-9._-]*) echo "set-secret: invalid file name '$name'" >&2; exit 1 ;;
	esac
	umask 077
	mkdir -p secrets
	own_root root:root secrets
	chmod 700 secrets
	# Written whole through a temp file and renamed, like the env shape: a
	# container reading a mounted secret must never see a half-written one.
	# NOT $(cat) here -- that strips trailing newlines, and a file secret is
	# bytes. A PEM without its final newline is a PEM some parsers refuse.
	ftmp="$(mktemp "__APP_DIR__/secrets/.tmp.XXXXXX")"
	cat > "$ftmp"
	own_root "${uid:-0}:0" "$ftmp"
	chmod 600 "$ftmp"
	mv -f "$ftmp" "secrets/$name"
	echo "set-secret: file $name updated"
	exit 0
fi

# Env-var charset. Also makes the name safe as a grep pattern below.
case "$name" in
	*[!A-Za-z0-9_]*|'')
		echo "set-secret: invalid name '$name'" >&2
		exit 1
		;;
esac

# $(cat) strips trailing newlines, which is what an env file wants anyway.
value="$(cat)"
case "$value" in
	*"
"*)
		echo "set-secret: value for $name contains a newline, which an env file cannot represent" >&2
		exit 1
		;;
esac

umask 077
tmp="$(mktemp "__APP_DIR__/.secrets.XXXXXX")"
# Drop any existing line for this key, then append the new one. Rewriting via
# a temp file and mv makes the update atomic: a reader never sees the file
# without the key, and a crash mid-write cannot truncate it.
grep -v "^$name=" secrets.env > "$tmp" 2>/dev/null || true
printf '%s=%s\n' "$name" "$value" >> "$tmp"
own_root root:root "$tmp"
chmod 600 "$tmp"
mv -f "$tmp" secrets.env

echo "set-secret: $name updated"
KOMIZO_SECRET_EOF
sed -i \
	-e "s|__APP_DIR__|$APP_DIR|g" \
	-e "s|__STATE_FILE__|$STATE_FILE|g" \
	"$SECRET_BIN.tmp"
if grep -q '__[A-Z_][A-Z_]*__' "$SECRET_BIN.tmp"; then
	rm -f "$SECRET_BIN.tmp"
	die "the generated secret script still has placeholders in it -- this is a komizo bug"
fi
mv "$SECRET_BIN.tmp" "$SECRET_BIN"
chown root:root "$SECRET_BIN"
chmod 755 "$SECRET_BIN"

# --- 3b2. Scoped env path --------------------------------------------------
# Opt-in, and only the fixed fieldsofrevik profile. Provision is root-only
# and mode 0700. Status is the only doas grant. The old setter and its lease
# helpers are removed; they are not data.
rm -f "$SCOPED_BIN" "$SCOPED_BIN.tmp" \
	"/etc/periodic/15min/komizo-scoped-env-$APP_NAME" \
	"/etc/local.d/komizo-scoped-env-$APP_NAME.start"
if [ "$SCOPED_ENV" = "fields-postgres-v2" ]; then
	log "Installing $PROVISION_BIN and $STATUS_BIN"
	cat > "$PROVISION_BIN.tmp" <<'KOMIZO_SCOPED_EOF'
# __FIELDS_SCOPED_ENV_BODY__
KOMIZO_SCOPED_EOF
	cat > "$STATUS_BIN.tmp" <<'KOMIZO_STATUS_EOF'
# __FIELDS_SCOPED_STATUS_BODY__
KOMIZO_STATUS_EOF
	sed -i \
		-e "s|__APP_NAME__|$APP_NAME|g" \
		-e "s|__STATE_FILE__|$STATE_FILE|g" \
		-e "s|__LOCK_FILE__|/run/komizo/deploy-$APP_NAME.lock|g" \
		"$PROVISION_BIN.tmp" "$STATUS_BIN.tmp"
	if grep -q '__[A-Z_][A-Z_]*__' "$PROVISION_BIN.tmp" "$STATUS_BIN.tmp"; then
		rm -f "$PROVISION_BIN.tmp" "$STATUS_BIN.tmp"
		die "the generated scoped-env script still has placeholders in it -- this is a komizo bug"
	fi
	mv "$PROVISION_BIN.tmp" "$PROVISION_BIN"
	mv "$STATUS_BIN.tmp" "$STATUS_BIN"
	chown root:root "$PROVISION_BIN" "$STATUS_BIN"
	chmod 700 "$PROVISION_BIN"
	chmod 755 "$STATUS_BIN"
else
	rm -f "$PROVISION_BIN" "$PROVISION_BIN.tmp" "$STATUS_BIN" "$STATUS_BIN.tmp"
fi

# --- 3c. Named task path ---------------------------------------------------
# Optional and app-specific: a root-owned program the deploy account may ask
# to perform one privileged operation, without being given Docker membership
# or a shell grant.
#
# THE SCRIPT COMES FROM THE APP, THE MECHANISM COMES FROM KOMIZO. It used to
# be the other way round: 181 lines of one product's operations -- its
# compose project, its service names, its volume names, the path of a binary
# only it ships -- were compiled into this file, which is otherwise the
# generic "set an app up" script. komizo grew a per-app special case, and the
# app still could not change it without a komizo release. By the time anyone
# looked, every path in it was stale: the executable it named had been
# deleted and all three volumes belonged to a database the product had
# migrated off, so the whole profile was dead code that only komizo could
# remove.
#
# NOT FROM THE CONFIG IMAGE, deliberately, even though that image already
# reaches this box. This program runs as root, and sourcing it from something
# CI pushes would turn "can deploy" into "can run anything as root here" --
# the deploy account's whole point is that it cannot. It comes from an
# operator's machine, through `komizo add --task-script`, and is kept on the
# box so an update reinstalls what was reviewed rather than dropping it.
if [ -n "${TASK_SCRIPT_B64:-}" ]; then
	mkdir -p "$TASK_STORE"
	chown root:root "$TASK_STORE"
	chmod 700 "$TASK_STORE"
	printf '%s' "$TASK_SCRIPT_B64" | base64 -d > "$TASK_FILE.tmp"
	# A file that is not a script would still be a root-owned thing the
	# deploy account may execute, which is worth one check before installing.
	if ! head -n 1 "$TASK_FILE.tmp" | grep -q '^#!'; then
		rm -f "$TASK_FILE.tmp"
		die "--task-script must start with a #! line"
	fi
	mv -f "$TASK_FILE.tmp" "$TASK_FILE"
	chown root:root "$TASK_FILE"
	chmod 700 "$TASK_FILE"
fi
if [ -n "$TASKS" ]; then
	log "Installing $TASK_BIN from this app's task script"
	cp "$TASK_FILE" "$TASK_BIN.tmp"
	mv -f "$TASK_BIN.tmp" "$TASK_BIN"
	chown root:root "$TASK_BIN"
	chmod 755 "$TASK_BIN"
else
	# Revoked, or never had one. Both copies go: a stored script nothing
	# installs is a root-owned file waiting to be re-granted by accident.
	rm -f "$TASK_BIN" "$TASK_BIN.tmp" "$TASK_FILE" "$TASK_FILE.tmp"
fi

log "Granting '$CI_USER' narrowly scoped doas access"
# Written straight into doas.conf rather than a /etc/doas.d drop-in: doas has
# no portable include directive, and a drop-in that is never read would fail
# open-looking but silently do nothing.
touch /etc/doas.conf

# Backed up before it is touched, and restored on ANY failure between here and
# a successful `doas -C`.
#
# doas refuses to run at all against a config it cannot parse, so a file left
# invalid does not break this app -- it breaks EVERY app on the box, from an
# operation scoped to one of them, with no way back except editing the file by
# hand over the connection komizo just used. This is the one file the script
# was mutating without a way back: sshd_config below has both a backup and a
# trap, and alpine-remove.sh backs up this very file on the way out.
# PER RUN, not a fixed name. Two runs of this script at once -- an update while
# somebody adds an app, two operators, CI adding an app mid-upgrade -- shared
# one backup file: the first to finish deleted it, and the second's restore
# then had nothing to move, aborting under set -e with doas.conf left in its
# edited state. STATE_TMP above already solves this with $$; so does this.
doas_bak="/etc/doas.conf.komizo.bak.$$"
cp /etc/doas.conf "$doas_bak"
# TWO TRAPS, AND THE SIGNAL ONE EXITS.
#
# Between the sed below (which removes this account's rule block) and the
# append after it, this app cannot deploy -- doas has no rule for it. An EXIT
# trap does not run on HUP, TERM or PIPE, and those are exactly how this script
# dies in practice: `komizo update` is long, interrupting it kills the local
# ssh, and the far end then takes SIGHUP from sshd or SIGPIPE on its next write
# to a closed stdout. Left that way, the app's deploys fail until something
# re-runs the setup, and nothing on the box says why.
#
# The `exit` is not decoration. A handler for a signal RETURNS to where it was
# interrupted -- it does not stop the script -- so listing the signals without
# it puts the file back and then carries on: the block is re-appended, the run
# continues on a box whose operator has already cancelled the command, and it
# reaches the sshd section below, where the same interruption leaves the WORSE
# of the two windows open (see the trap there). Absorbing the signal moves the
# exposure rather than closing it.
#
# PIPE is in the list because it is the likeliest of the four. Killing the
# local ssh does not always deliver a signal here at all; what does is the next
# `log` line this script writes to a stdout with nothing on the other end.
#
# The two compose safely: `exit` from a signal handler runs the EXIT trap as
# well, and this handler is idempotent -- `mv -f` over a source that is already
# gone, with the failure swallowed.
#
# It was survivable when this block ran once, because somebody chose to run
# `komizo add`. komizo#58 made it run once per app on every upgrade. The
# generated deploy script already traps a set like this for a smaller stake.
trap 'mv -f "$doas_bak" /etc/doas.conf 2>/dev/null || true' EXIT
trap 'mv -f "$doas_bak" /etc/doas.conf 2>/dev/null || true; exit 129' INT TERM HUP PIPE

# Delimited block, so the rule set can grow without the removal logic having to
# know how many lines it spans.
# Keyed on the project rather than this file, so adding a script for another
# distro later does not orphan rules written by this one.
# Drop the previous account's block too, if this app was renamed onto a new
# account (OLD_CI_USER is set only when it is safe to retire the old one).
# ADOPT ANYTHING IN THE BLOCK KOMIZO DID NOT WRITE, BEFORE DELETING IT.
#
# The removal below drops the account's whole block, and the append after it
# writes back exactly the rules komizo knows about. Any line an operator added
# inside the markers therefore disappeared -- silently, with no backup kept
# (the one taken above is removed on success), and with nothing on the box or
# in the output saying a privilege had just been revoked.
#
# That is not hypothetical. komizo 0.0.43 rolled onto komizo.avior.studio and
# took three hand-added rules with it; gdam's PR previews then failed on
# `doas: Operation not permitted` in a step that had worked minutes earlier,
# and the cause was invisible from both the failure and this script.
#
# Deleting is wrong and so is keeping: a grant komizo does not understand must
# not sit inside a block that says komizo manages it. So the lines are moved
# OUT, into a section of their own, and named on stdout. The next run finds
# the block clean and leaves the adopted section alone, which makes this
# idempotent without needing to remember anything.
adopted_file="/tmp/.komizo-adopted.$$"
: > "$adopted_file"
# The rules komizo itself writes are recognised by the BINARY they grant, and
# the list is built here rather than spelled out as six whole rule strings.
#
# $SCOPED_BIN is in it on purpose and for the opposite reason to the others.
# That setter is the withdrawn path (see its definition above): komizo REVOKES
# it, so a stale grant naming it must be dropped by this scan and not carried
# out into the adopted section, which would resurrect a privilege the rest of
# this script exists to remove.
recognised="$DEPLOY_BIN $PRUNE_BIN $SECRET_BIN $STATUS_BIN $TASK_BIN $SCOPED_BIN $PROVISION_BIN"
# The preview helpers are komizo's own as of this change. Without them
# here, the first update after it would "adopt" the very rules it had
# just written and carry them out of the block.
recognised="$recognised $PREVIEW_RUN_BIN $PREVIEW_STACKENV_BIN"
awk -v begin="# $PROJECT_MARKER: $CI_USER BEGIN" \
    -v end="# $PROJECT_MARKER: $CI_USER END" \
    -v user="$CI_USER" \
    -v bins="$recognised" '
	BEGIN {
		n = split(bins, b, " ")
		for (i = 1; i <= n; i++) mine["permit nopass " user " as root cmd " b[i]] = 1
	}
	$0 == begin { inside = 1; next }
	$0 == end   { inside = 0; next }
	!inside { next }
	$0 in mine { next }
	{ print }
' /etc/doas.conf > "$adopted_file"

[ -n "$OLD_CI_USER" ] && sed -i -E "/^# $PROJECT_MARKER: $OLD_CI_USER BEGIN\$/,/^# $PROJECT_MARKER: $OLD_CI_USER END\$/d" /etc/doas.conf
sed -i -E "/^# $PROJECT_MARKER: $CI_USER BEGIN\$/,/^# $PROJECT_MARKER: $CI_USER END\$/d" /etc/doas.conf
# The adopted rules, back on the file but outside the managed block, so the
# next run of this script leaves them alone.
#
# Emitted BEFORE the block rather than after it. The block is deleted from
# wherever it sat and re-appended at the end, so appending the adopted lines
# afterwards put them above the block on the next run and below it on this
# one -- same rules, different file, which is a diff an operator has to read
# to dismiss. This way the order is settled from the first run.
#
# Named on stdout, every one of them, because a privilege komizo is carrying
# without understanding is exactly the thing an operator has to decide about:
# either it becomes a komizo feature, or it should not be there at all.
if [ -s "$adopted_file" ]; then
	{
		printf '# komizo adopted these on %s: they were inside the\n' "$(date -u +%FT%TZ)"
		printf '# "%s: %s" block but komizo did not write them, and a block rewrite\n' "$PROJECT_MARKER" "$CI_USER"
		printf '# would have deleted them. Out here they survive. Make them a komizo\n'
		printf '# feature or remove them; do not move them back inside the markers.\n'
		cat "$adopted_file"
	} >> /etc/doas.conf
	log "Adopted $(wc -l < "$adopted_file" | tr -d ' ') hand-added doas rule(s) for '$CI_USER' -- kept, moved outside komizo's block:"
	while IFS= read -r _line; do [ -n "$_line" ] && log "    $_line"; done < "$adopted_file"
fi
rm -f "$adopted_file"
cat >> /etc/doas.conf <<-EOF
	# komizo: $CI_USER BEGIN
	permit nopass $CI_USER as root cmd $DEPLOY_BIN
	permit nopass $CI_USER as root cmd $PRUNE_BIN
EOF
if [ "$SCOPED_ENV" = "fields-postgres-v2" ]; then
	# Status only. Provision is mode 0700 and is not in doas. set-secret is
	# not granted for this profile; the script also refuses if a stale rule
	# remains.
	printf 'permit nopass %s as root cmd %s\n' "$CI_USER" "$STATUS_BIN" >> /etc/doas.conf
else
	printf 'permit nopass %s as root cmd %s\n' "$CI_USER" "$SECRET_BIN" >> /etc/doas.conf
fi
if [ -n "$TASKS" ]; then
	# Exactly one extra rule, for the root-owned validator/executor. Dynamic
	# task/mode matching lives in that wrapper because doas args cannot express
	# this small OR-list without duplicating grants.
	printf 'permit nopass %s as root cmd %s\n' "$CI_USER" "$TASK_BIN" >> /etc/doas.conf
fi
if [ "$PREVIEW" = "1" ]; then
	# The two preview helpers. No "args" clause on either: what they take is
	# an app name and a PR number, and both scripts check the app against the
	# CALLER's own rather than against a list doas would have to be re-taught
	# for every app on the box.
	printf 'permit nopass %s as root cmd %s\n' "$CI_USER" "$PREVIEW_RUN_BIN" >> /etc/doas.conf
	printf 'permit nopass %s as root cmd %s\n' "$CI_USER" "$PREVIEW_STACKENV_BIN" >> /etc/doas.conf
fi
cat >> /etc/doas.conf <<-EOF
	# komizo: $CI_USER END
EOF
chown root:root /etc/doas.conf
chmod 600 /etc/doas.conf
if ! doas -C /etc/doas.conf; then
	mv -f "$doas_bak" /etc/doas.conf
	trap - EXIT INT TERM HUP PIPE
	die "the generated doas.conf is invalid, reverted -- no rules were changed"
fi
# Success: stop guarding it and drop the backup, so a later run's "backup" is
# not one that already carries komizo's edits. BOTH traps are cleared, not just
# the EXIT one: the signal handler exits, so one left installed would abandon a
# later step -- and it would do it while restoring a backup that no longer
# exists, i.e. doing nothing except stopping the run.
trap - EXIT INT TERM HUP PIPE
# Keep ONE rolling copy of what this file looked like before the run, rather
# than deleting the only evidence the moment the run succeeds. A successful
# rewrite is precisely when nobody is looking, and it is the rewrite that
# changes privileges. One fixed name, not one per run: a directory of dated
# copies of a privilege file is its own problem.
mv -f "$doas_bak" /etc/doas.conf.komizo.previous
chown root:root /etc/doas.conf.komizo.previous
chmod 600 /etc/doas.conf.komizo.previous

# --- 4. sshd ---------------------------------------------------------------
# Two separate things, deliberately:
#
#   ALWAYS   a Match block scoped to $CI_USER. It constrains only the account
#            this script just created, so it can never lock anyone out and
#            needs no opt-out. This is where the real value is: without
#            AllowTcpForwarding no, a leaked deploy key can tunnel arbitrary
#            TCP through this box -- reaching a database bound to localhost,
#            or anything else routable from here. It is also what points sshd
#            at the root-owned key list, so the account cannot authorise a
#            second key for itself.
#
#   OPT-IN   the global PermitRootLogin / PasswordAuthentication settings.
#            Whether root may use a password is a policy decision about the
#            whole machine, not something a deploy tool should impose.
#            HARDEN_SSH=1 asks for it.

# komizo: sshd-validation BEGIN
# Is the config valid FOR THE BINARY THAT WILL LOAD IT?
#
# komizo#77. `sshd -t` resolves to /usr/sbin/sshd. Alpine's init script runs
# /usr/sbin/sshd.pam when the config says `UsePAM yes` -- a DIFFERENT binary,
# not a link, that disagrees about which options exist. `UsePAM yes` is Alpine's
# own default, and plain sshd calls it an unsupported option. So on every box
# with openssh-server-pam installed, this check was validating a program that
# was never going to read the file.
#
# Both directions are wrong and only one is safe: a good config rejected merely
# reverts an edit, but a config the running daemon will NOT accept passing this
# check is a reload into a broken sshd -- which is the thing the deferred reload
# exists to prevent.
#
# The init script already selects the binary and exposes `checkconfig`, so this
# ASKS IT instead of reimplementing update_command(). Copying that selection
# would be copying vendor logic that can drift out from under us, and it does
# not just test for the binary's existence -- it tests the config to decide.
#
# Where the action does not exist, `sshd -t` is what there is. That is no worse
# than before this function existed.
#
# NOT SIDE-EFFECT FREE, and worth knowing rather than discovering: Alpine's
# checkconfig runs `ssh-keygen -A` first, which creates any host key type the
# box is missing. On a machine komizo is reaching over SSH they already exist,
# so it is a no-op in practice -- but it is a write on a path named `validate`,
# and it happens during a removal too. Found in review of komizo#77.
komizo_sshd_config_ok() {
	if [ -f /etc/init.d/sshd ] && grep -qE '^extra_commands=.*checkconfig' /etc/init.d/sshd; then
		rc-service sshd checkconfig
	else
		sshd -t
	fi
}
# AND IS IT THE FILE THE DAEMON ACTUALLY READS?
#
# nicodes/komizo-be#164, and the other half of the problem above. Validating the
# right file with the right binary is only correct if komizo is EDITING the file
# the daemon reads -- and Alpine's init script takes `cfgfile` from
# /etc/conf.d/sshd, so an operator can point their daemon anywhere.
#
# komizo wrote to /etc/ssh/sshd_config unconditionally. On a box with cfgfile
# set, every consequence is silent: the deploy account's Match block is not in
# force, so AllowTcpForwarding no and the rest never take effect and a leaked
# deploy key can tunnel TCP through the box; AuthorizedKeysFile still points
# wherever the real config says, so the root-owned key list komizo relies on is
# not the one consulted and the account can authorise a second key for itself;
# and a key rotation rewrites a file nothing loads, so the old key keeps
# working. komizo reports success for all three.
#
# READ THE SAME WAY THE INIT SCRIPT READS IT -- last assignment wins, quotes
# stripped -- rather than grepping for the default. A file that sets it twice
# is a file whose daemon uses the second one.
komizo_sshd_conf() {
	_cf=""
	if [ -r /etc/conf.d/sshd ]; then
		_cf=$(sed -n "s/^[[:space:]]*cfgfile=//p" /etc/conf.d/sshd |
			tail -n 1 | tr -d "\"'" | tr -d "\r")
	fi
	[ -n "$_cf" ] || _cf=/etc/ssh/sshd_config
	printf '%s\n' "$_cf"
}

# REFUSED RATHER THAN FOLLOWED, and that is the deliberate half.
#
# A box with a relocated sshd config is one somebody configured on purpose.
# Silently rewriting their real config is worse than stopping: komizo would be
# editing a file it was never asked to own, on the strength of a variable it
# just discovered. Saying which file this box uses is the whole remedy -- move
# it back, or manage that box's ssh rules yourself.
komizo_sshd_conf_is_ours() {
	_conf=$(komizo_sshd_conf)
	[ "$_conf" = /etc/ssh/sshd_config ] && return 0
	echo "error: this box points sshd at $_conf (cfgfile in /etc/conf.d/sshd)." >&2
	echo "       komizo only manages /etc/ssh/sshd_config, so the deploy account's" >&2
	echo "       restrictions would be written to a file the daemon never reads." >&2
	return 1
}
# komizo: sshd-validation END

# BEFORE ANYTHING IS TOUCHED, and the validation block above it is there for
# exactly that reason.
#
# The first version of this called the check while the block still sat further
# down the file, under a comment saying so as though shell hoisted definitions.
# It does not: `komizo add` reached this line and died with
# `sh: komizo_sshd_conf_is_ours: not found`, after creating the deploy account,
# the app directory and the doas rules. The test extracted the block and
# appended the call AFTER it, which is an order the real script never runs in.
#
# Called here rather than later because the first write is the backup below --
# refusing after that has already put a .komizo.bak beside a file komizo does
# not own.
if ! komizo_sshd_conf_is_ours; then
	exit 1
fi

conf=/etc/ssh/sshd_config
# Per run, for the reason doas_bak above is: two concurrent runs sharing one
# backup name lose each other's, and the loser restores a file that already
# carries the winner's edits -- or nothing at all.
conf_bak="$conf.komizo.bak.$$"
cp "$conf" "$conf_bak"

# Restore on ANY failure between here and a successful reload. A half-edited
# sshd_config that lost the Match block would fall back to the account's own
# ~/.ssh/authorized_keys -- which it can write -- reintroducing the very thing
# the root-owned key list exists to prevent. The explicit reverts below stay for
# their specific messages; this catches every other way out. Cleared on success.
#
# The same two traps as the doas block above, and for the same reasons -- but
# this window is the worse of the two, which is why the signal handler exits
# rather than resuming. Between the sed below and the append further down, this
# account has NO Match block: it loses the root-owned AuthorizedKeysFile and
# every restriction in it (AllowTcpForwarding no and the rest). sshd has not
# been reloaded yet, so it does not bite now -- it bites at the next reboot, a
# long way from anything anyone would connect it to.
trap 'mv -f "$conf_bak" "$conf" 2>/dev/null || true' EXIT
trap 'mv -f "$conf_bak" "$conf" 2>/dev/null || true; exit 129' INT TERM HUP PIPE

# Retire the previous account's Match block too, if this app was renamed onto a
# new account (OLD_CI_USER is set only when it is safe to do so).
[ -n "$OLD_CI_USER" ] && sed -i -E "/^# $PROJECT_MARKER: sshd $OLD_CI_USER BEGIN\$/,/^# $PROJECT_MARKER: sshd $OLD_CI_USER END\$/d" "$conf"

# The deploy-user block is always removed, because it is always re-added
# below. The global block is only removed when we are about to rewrite it --
# otherwise re-running WITHOUT HARDEN_SSH=1 would silently undo hardening a
# previous run applied.
# Keyed on the USER, so a box hosting several apps -- each with its own deploy
# account -- gets one Match block per account instead of them overwriting each
# other.
sed -i -E "/^# $PROJECT_MARKER: sshd $CI_USER BEGIN\$/,/^# $PROJECT_MARKER: sshd $CI_USER END\$/d" "$conf"

if [ "$HARDEN_SSH" = "1" ]; then
	log "Hardening sshd for all users"
	# Refuse to disable password auth unless root can still get in by key,
	# otherwise a box with no console access becomes unreachable.
	if [ ! -s /root/.ssh/authorized_keys ]; then
		mv "$conf_bak" "$conf"
		die "/root/.ssh/authorized_keys is empty -- install your own key first, or drop the hardening flag"
	fi
	# Only komizo's own block is removed. Deleting every PermitRootLogin and
	# PasswordAuthentication line in the file used to reach inside the
	# administrator's own Match blocks and silently rewrite policy for accounts
	# this tool knows nothing about -- and it was never needed, because the
	# block below is PREPENDED and sshd takes the first value it obtains for a
	# keyword.
	sed -i -E "/^# $PROJECT_MARKER: global BEGIN\$/,/^# $PROJECT_MARKER: global END\$/d" "$conf"
	# PREPENDED, not appended. sshd_config takes the FIRST value it obtains for
	# a keyword, and a Match block applies to everything after it -- so a global
	# block written at the end would land inside whichever Match block happens
	# to precede it, silently scoping machine-wide settings to one account.
	# At the top it wins outright and sits before every Match.
	tmp_conf="$(mktemp "$conf.komizo.XXXXXX")"
	{
		printf '%s\n' "# komizo: global BEGIN"
		printf '%s\n' "PermitRootLogin prohibit-password"
		printf '%s\n' "PasswordAuthentication no"
		printf '%s\n' "# komizo: global END"
		cat "$conf"
	} > "$tmp_conf"
	cat "$tmp_conf" > "$conf"
	rm -f "$tmp_conf"
else
	log "Leaving global sshd settings alone (password auth unchanged)"
fi

# Appended LAST, and this matters: a Match block applies to every directive
# after it, to the end of the file. Anything written below would silently
# become $CI_USER-scoped rather than global.
log "Restricting '$CI_USER' in sshd"
cat >> "$conf" <<-EOF
	# komizo: sshd $CI_USER BEGIN
	# Applies to $CI_USER only; no other account is affected.
	# NOTE: everything below this line is inside the Match block. Put global
	# settings ABOVE it.
	Match User $CI_USER
	    # Root-owned, outside the account's home. The account cannot add a key
	    # for itself, so rotating the deploy key actually removes access.
	    AuthorizedKeysFile $KEYS_DIR/%u
	    PasswordAuthentication no
	    PermitEmptyPasswords no
	    AllowTcpForwarding no
	    AllowAgentForwarding no
	    AllowStreamLocalForwarding no
	    PermitTunnel no
	    GatewayPorts no
	    X11Forwarding no
	# komizo: sshd $CI_USER END
EOF


if komizo_sshd_config_ok; then
	# ONE RELOAD PER UPDATE, NOT ONE PER APP.
	#
	# komizo#65. This script runs once per app, and komizo#58 made `komizo
	# update` run it for every app on the box -- so an upgrade of N apps
	# reloaded sshd N times. Each reload is a window in which a CI deploy
	# dialling this box can fail, and the count grew with the fleet rather than
	# staying at one.
	#
	# The reload is DEFERRED, not skipped: the check above still validates every
	# app's edit as it is made, so a broken config is still caught by the app
	# that caused it and reverted by the guard. What is postponed is only the
	# moment the running daemon picks the file up, which the caller does once
	# after the last app.
	#
	# An update that dies midway therefore leaves a valid config the daemon has
	# not read yet -- the previous rules stay in force until the next reload,
	# which is the safe direction: an app whose block did not take effect cannot
	# deploy, where a half-applied reload could have let one through.
	if [ "${DEFER_SSHD_RELOAD:-0}" = "1" ]; then
		echo "komizo: sshd config validated; reload deferred to the end of this update"
	else
		rc-service sshd reload || rc-service sshd restart
	fi
	# Success: stop guarding the file and drop the backup, so a re-run's "backup"
	# is the pre-komizo config rather than one that already carries komizo's edits.
	trap - EXIT INT TERM HUP PIPE
	rm -f "$conf_bak"
else
	mv "$conf_bak" "$conf"
	trap - EXIT INT TERM HUP PIPE
	die "sshd config test failed, reverted -- nothing was restarted"
fi

log "Done"
SCOPED_HINT=""
SCOPED_NOTE=""
if [ "$SCOPED_ENV" = "fields-postgres-v2" ]; then
	SCOPED_HINT="doas $STATUS_BIN"
	SCOPED_NOTE="
When the fields-postgres-v2 profile is installed, '$CI_USER' can run
$STATUS_BIN and nothing else for secrets. It prints one nonsecret status line.
Provisioning is root-only: $PROVISION_BIN, once, before the first postgres
start. It is not in doas. set-secret is not granted for this profile."
	# CLERK_SECRET_KEY stays on the box. It is not a deploy argument and not
	# a value this note or the status line can carry.
fi
cat <<EOF

  app:      $APP_NAME
  user:     $CI_USER (no docker group, no shell privileges)
  app dir:  $APP_DIR (root-owned)
  keys:     $KEYS_FILE (root-owned -- the account cannot add its own)
  deploy:   doas $DEPLOY_BIN
  prune:    doas $PRUNE_BIN [--dry-run]
  secrets:  doas $SECRET_BIN <NAME>  (value on stdin)
  scoped:   ${SCOPED_HINT:-}
  config:   $CONFIG_IMAGE
  docker:   $(docker --version)

EOF

cat <<-EOF
	compose.yml comes from $CONFIG_IMAGE:<tag> on every deploy.
	Nothing to install by hand. From CI:
	  ssh $CI_USER@<host> doas $DEPLOY_BIN <tag>
EOF

cat <<EOF

The privileged commands above are scoped to this app. Image retention reads
trusted deployment state and keeps current and rollback images; --dry-run shows
candidates. Secret access depends on the app's configured profile. Optional
reviewed task and preview commands may also be installed.

The account also has an ordinary, unprivileged SSH shell session as itself, so
a workflow can run a migration or a backup. It cannot access Docker directly,
write under $APP_DIR, or change these root-owned commands. compose.yml arrives
as a registry layer that root extracts; changing it requires registry push.
${SCOPED_NOTE:-}

The host validates workload privileges before activation. When source identity
is configured in its workload policy, it also authenticates the release workflow
and pins every application image to verified content. The deploy key is confined
to this app's installed commands. A leaked deploy key lets an attacker roll the stack back to
any tag you have already published -- including one with a known bug -- and
overwrite (not read) secrets. It does not let them run code of their own, and
it cannot authorise a second key: the key list is root's, so rotating removes
the leaked key rather than adding beside it.

Protect registry push accordingly, and pin your CI's third-party actions by
SHA: they run in the same job as the deploy key.
EOF
