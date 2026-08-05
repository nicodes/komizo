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
# One account per app, so a key that leaks reaches only its own app. Sharing one
# account across apps is possible with an explicit CI_USER, but then its doas
# block covers all of them.
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
SECRET_BIN="/usr/local/bin/set-secret-$APP_NAME"

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

# If this app was previously set up under a DIFFERENT deploy account, that old
# account's key file, doas rule and sshd Match block would otherwise be orphaned
# -- an invisible, still-privileged account that a key rotation never touches.
# Note it now, before the state file is rewritten below, and remove it further
# down. Skipped when the account is shared with another app (an explicit CI_USER
# can be), since removing it would break those apps.
OLD_CI_USER=""
_old="$(sed -n 's/^CI_USER=//p' "$STATE_FILE" 2>/dev/null | head -n 1)"
case "$_old" in
	''|"$CI_USER") ;;                     # nothing recorded, or unchanged
	*[!A-Za-z0-9_-]*) ;;                  # legacy/unreadable value -- leave it be
	*)
		OLD_CI_USER="$_old"
		for _st in "$STATE_DIR"/*.env; do
			[ -f "$_st" ] || continue
			_a="${_st##*/}"; _a="${_a%.env}"
			[ "$_a" = "$APP_NAME" ] && continue
			if [ "$(sed -n 's/^CI_USER=//p' "$_st" | head -n 1)" = "$OLD_CI_USER" ]; then
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
	KNOWN_AS="$(sed -n 's/^KNOWN_AS=//p' "$STATE_FILE" | head -n 1)"
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
STOPPED_KEEP=""
if [ -f "$STATE_FILE" ] && [ "$(sed -n 's/^STOPPED=//p' "$STATE_FILE" | head -n 1)" = "1" ]; then
	STOPPED_KEEP="$(printf 'STOPPED=1\nSTOPPED_BY=%s\nSTOPPED_AT=%s' \
		"$(sed -n 's/^STOPPED_BY=//p' "$STATE_FILE" | head -n 1)" \
		"$(sed -n 's/^STOPPED_AT=//p' "$STATE_FILE" | head -n 1)")"
fi

cat > "$STATE_FILE" <<EOF
# Written by komizo. This is what komizo knows about this app; edit with
# 'komizo add' rather than by hand.
APP_NAME=$APP_NAME
APP_DIR=$APP_DIR
CI_USER=$CI_USER
CONFIG_IMAGE=$CONFIG_IMAGE
KNOWN_AS=$KNOWN_AS
EOF
if [ -n "$STOPPED_KEEP" ]; then
	printf '%s\n' "$STOPPED_KEEP" >> "$STATE_FILE"
fi
chown root:root "$STATE_FILE"
chmod 640 "$STATE_FILE"

# --- 3. Deploy path --------------------------------------------------------
# The only privileged thing the CI user may do, besides setting a secret.
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
trap 'rm -rf "$staging" "${DOCKER_CONFIG:-}" 2>/dev/null || true
	rm -f "$APP_DIR/.env.komizo.bak" 2>/dev/null || true' EXIT INT TERM

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

# One deploy of this app at a time.
#
# Two runs of the same app interleave their compose.yml swaps and their .env
# writes, and the loser wins on some files and loses on others -- a stack
# running one commit's containers against another commit's config, from two
# green pipelines. The wait is bounded so a stuck deploy fails the second run
# with a message rather than hanging CI until it times out.
#
# Per app, so two DIFFERENT apps still deploy concurrently: they share nothing
# but the daemon.
# Skipped, not fatal, wherever it cannot be taken -- a busybox built without the
# flock applet, or a /run this cannot write. Refusing to deploy at all in those
# cases would trade a race for an outage, and the race is the smaller problem.
#
# Every step is proved before the redirection, because `exec 9>` on a path that
# cannot be opened takes the whole shell down with it under set -e.
komizo_lock="/run/komizo/deploy-__APP_NAME__.lock"
if command -v flock >/dev/null 2>&1 &&
	mkdir -p /run/komizo 2>/dev/null &&
	: > "$komizo_lock" 2>/dev/null
then
	exec 9>"$komizo_lock"
	if ! flock -w 300 9; then
		echo "deploy: another deploy of __APP_NAME__ has been running for over 5 minutes" >&2
		exit 1
	fi
fi

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
	case "$registry_user" in
		''|*[!A-Za-z0-9._@-]*)
			echo "deploy: refusing registry user '$registry_user'" >&2
			exit 1
			;;
	esac
	DOCKER_CONFIG="$(mktemp -d)"
	export DOCKER_CONFIG
	# Credentials must not outlive the deploy; the EXIT trap set above drops both
	# this directory and the staging dir however we leave.
	if ! docker login "$registry" -u "$registry_user" --password-stdin >/dev/null; then
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
revert() {
	cat compose.yml.prev > compose.yml
	rm -f "$ROUTE_FILE"
	[ -f "$ROUTE_FILE.prev" ] && mv "$ROUTE_FILE.prev" "$ROUTE_FILE"
	rm -f hostnames
	[ -f hostnames.prev ] && mv hostnames.prev hostnames
	rm -f compose.yml.prev
	return 0
}

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
			[ -n "$_odir" ] && [ -f "$_odir/hostnames" ] || continue
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

if [ -f "$ROUTE_FILE" ] && [ "$proxy_up" = 0 ]; then
	revert
	echo "deploy: this app publishes routes, but the reverse proxy is not running." >&2
	echo "deploy: nothing would serve them, so this is a failure rather than a no-op." >&2
	echo "deploy: start it with 'komizo proxy --host <this box>', or press s in the interface." >&2
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
# .env is read by the pull/up below for ${APP_VERSION} substitution, so it has
# to be written first -- but a pull that then fails would leave .env claiming a
# version that never started. Back it up and put it back on failure.
cp .env .env.komizo.bak 2>/dev/null || true
if grep -q '^APP_VERSION=' .env; then
	sed -i "s|^APP_VERSION=.*|APP_VERSION=$version|" .env
else
	printf 'APP_VERSION=%s\n' "$version" >> .env
fi

if ! docker compose pull; then
	mv -f .env.komizo.bak .env 2>/dev/null || rm -f .env.komizo.bak
	# The whole config goes back, not just .env: compose.yml, the hostnames
	# record and the generated route are all this version's and none of them
	# was ever served.
	revert
	echo "deploy: 'docker compose pull' failed -- reverted, nothing restarted" >&2
	exit 1
fi
rm -f .env.komizo.bak
docker compose up -d --remove-orphans

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
# serving either way. Reported rather than fatal: the containers for THIS app
# are already running by now, and failing the deploy would misreport that.
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$PROXY_CONTAINER"; then
	if docker exec "$PROXY_CONTAINER" caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then
		echo "deploy: reverse proxy reloaded"
	else
		echo "deploy: WARNING -- the proxy would not reload; it is still serving its previous routes" >&2
	fi
fi

# Show the resulting topology. Without this a compose.yml that silently drops
# or renames a service looks identical in the log to one that changed nothing.
docker compose ps --format 'table {{.Service}}\t{{.Image}}\t{{.Status}}'
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
	"$DEPLOY_BIN.tmp"
if grep -q '__[A-Z_][A-Z_]*__' "$DEPLOY_BIN.tmp"; then
	rm -f "$DEPLOY_BIN.tmp"
	die "the generated deploy script still has placeholders in it -- this is a komizo bug"
fi
mv "$DEPLOY_BIN.tmp" "$DEPLOY_BIN"
chown root:root "$DEPLOY_BIN"
chmod 755 "$DEPLOY_BIN"

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

name="${1:-}"
cd "__APP_DIR__"

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
chown root:root "$tmp"
chmod 600 "$tmp"
mv -f "$tmp" secrets.env

echo "set-secret: $name updated"
KOMIZO_SECRET_EOF
sed -i -e "s|__APP_DIR__|$APP_DIR|g" "$SECRET_BIN.tmp"
if grep -q '__[A-Z_][A-Z_]*__' "$SECRET_BIN.tmp"; then
	rm -f "$SECRET_BIN.tmp"
	die "the generated secret script still has placeholders in it -- this is a komizo bug"
fi
mv "$SECRET_BIN.tmp" "$SECRET_BIN"
chown root:root "$SECRET_BIN"
chmod 755 "$SECRET_BIN"

log "Granting '$CI_USER' doas access to $DEPLOY_BIN and $SECRET_BIN only"
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
doas_bak="/etc/doas.conf.komizo.bak"
cp /etc/doas.conf "$doas_bak"
trap 'mv -f "$doas_bak" /etc/doas.conf 2>/dev/null || true' EXIT

# Delimited block, so the rule set can grow without the removal logic having to
# know how many lines it spans.
# Keyed on the project rather than this file, so adding a script for another
# distro later does not orphan rules written by this one.
# Drop the previous account's block too, if this app was renamed onto a new
# account (OLD_CI_USER is set only when it is safe to retire the old one).
[ -n "$OLD_CI_USER" ] && sed -i -E "/^# $PROJECT_MARKER: $OLD_CI_USER BEGIN\$/,/^# $PROJECT_MARKER: $OLD_CI_USER END\$/d" /etc/doas.conf
sed -i -E "/^# $PROJECT_MARKER: $CI_USER BEGIN\$/,/^# $PROJECT_MARKER: $CI_USER END\$/d" /etc/doas.conf
cat >> /etc/doas.conf <<-EOF
	# komizo: $CI_USER BEGIN
	permit nopass $CI_USER as root cmd $DEPLOY_BIN
	permit nopass $CI_USER as root cmd $SECRET_BIN
	# komizo: $CI_USER END
EOF
chown root:root /etc/doas.conf
chmod 600 /etc/doas.conf
if ! doas -C /etc/doas.conf; then
	mv -f "$doas_bak" /etc/doas.conf
	trap - EXIT
	die "the generated doas.conf is invalid, reverted -- no rules were changed"
fi
# Success: stop guarding it and drop the backup, so a later run's "backup" is
# not one that already carries komizo's edits.
trap - EXIT
rm -f "$doas_bak"

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

conf=/etc/ssh/sshd_config
conf_bak="$conf.komizo.bak"
cp "$conf" "$conf_bak"

# Restore on ANY failure between here and a successful reload. A half-edited
# sshd_config that lost the Match block would fall back to the account's own
# ~/.ssh/authorized_keys -- which it can write -- reintroducing the very thing
# the root-owned key list exists to prevent. The explicit reverts below stay for
# their specific messages; this catches every other way out. Cleared on success.
trap 'mv -f "$conf_bak" "$conf" 2>/dev/null || true' EXIT

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

if sshd -t; then
	rc-service sshd reload || rc-service sshd restart
	# Success: stop guarding the file and drop the backup, so a re-run's "backup"
	# is the pre-komizo config rather than one that already carries komizo's edits.
	trap - EXIT
	rm -f "$conf_bak"
else
	mv "$conf_bak" "$conf"
	trap - EXIT
	die "sshd config test failed, reverted -- nothing was restarted"
fi

log "Done"
cat <<EOF

  app:      $APP_NAME
  user:     $CI_USER (no docker group, no shell privileges)
  app dir:  $APP_DIR (root-owned)
  keys:     $KEYS_FILE (root-owned -- the account cannot add its own)
  deploy:   doas $DEPLOY_BIN
  secrets:  doas $SECRET_BIN <NAME>  (value on stdin)
  config:   $CONFIG_IMAGE
  docker:   $(docker --version)

EOF

cat <<-EOF
	compose.yml comes from $CONFIG_IMAGE:<tag> on every deploy.
	Nothing to install by hand. From CI:
	  ssh $CI_USER@<host> doas $DEPLOY_BIN <tag>
EOF

cat <<EOF

NOTE on what this contains. As root, via doas, '$CI_USER' can do exactly two
things: deploy a tag that already exists in your registry, and set a secret it
cannot read back. It also gets an ordinary, unprivileged SSH shell session as
itself -- deliberately, so a workflow can run a migration or a backup -- but it
cannot run docker, write anything under $APP_DIR, or introduce new code:
compose.yml arrives as a registry layer that root extracts, so changing the
shape of the stack requires push access to the registry.

That is the real boundary: REGISTRY PUSH is root-equivalent on this box, the
deploy key is not. A leaked deploy key lets an attacker roll the stack back to
any tag you have already published -- including one with a known bug -- and
overwrite (not read) secrets. It does not let them run code of their own, and
it cannot authorise a second key: the key list is root's, so rotating removes
the leaked key rather than adding beside it.

Protect registry push accordingly, and pin your CI's third-party actions by
SHA: they run in the same job as the deploy key.
EOF
