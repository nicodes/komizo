#!/bin/sh
# cli/scripts/alpine.sh - sets one app up on a server, run as root on the box.
#
# ncicd embeds this file and pipes it over SSH; you do not normally run it
# yourself. To read what will run as root on your server:
#
#   ncicd script           # prints this file
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
#   CI_USER        deploy account            (default: cd-<app>, cd-user for app)
#   APP_DIR        root-owned app directory                (default: /srv/<app>)
#   HARDEN_SSH     1 to also harden sshd machine-wide             (default: 0)
#   SHARED_NETWORK docker network to create for a reverse proxy   (default: none)

set -eu

# One box can host several apps. Everything that could collide between them --
# the directory, the two privileged scripts, the deploy account, the doas rules
# -- is named after the app, so bootstrapping a second one cannot disturb the
# first.
#
# APP_NAME=app is the single-app default and keeps the unsuffixed names.
APP_NAME="${APP_NAME:-}"
case "$APP_NAME" in
	'') echo "error: APP_NAME is required" >&2; exit 1 ;;
	*[!A-Za-z0-9_-]*) echo "error: APP_NAME must be letters, digits, underscore or hyphen" >&2; exit 1 ;;
esac

# Every app is named, always -- there is no unsuffixed "the app" special case.
# A box set up for one app can host a second later without renaming anything
# that already exists, which is not true if the first one owns the bare paths.
#
# One account per app, so a key that leaks reaches only its own app. Sharing one
# account across apps is possible with an explicit CI_USER, but then its doas
# block covers all of them.
CI_USER="${CI_USER:-cd-$APP_NAME}"
DEPLOY_BIN="/usr/local/bin/deploy-$APP_NAME"
SECRET_BIN="/usr/local/bin/set-secret-$APP_NAME"

APP_DIR="${APP_DIR:-/srv/$APP_NAME}"

# Config we write into /etc is tagged with a marker so a re-run can find and
# replace its own block. This alternation is every name this project has been
# published under: matching all of them means an upgrade replaces the old block
# instead of leaving one behind, while what we WRITE is always "ncicd".
PROJECT_MARKERS='(ncicd|cicd|alpine-server-scripts|boot\.sh)'
CI_PUBKEY="${CI_PUBKEY:-${1:-}}"
CONFIG_IMAGE="${CONFIG_IMAGE:-}"
HARDEN_SSH="${HARDEN_SSH:-0}"
SHARED_NETWORK="${SHARED_NETWORK:-}"

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root"
[ -n "$CI_PUBKEY" ] || die "no SSH public key given (pass as \$1 or CI_PUBKEY)"
case "$CI_PUBKEY" in
	ssh-*|ecdsa-*) ;;
	*) die "CI_PUBKEY does not look like an SSH public key" ;;
esac

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

# --- 1. Docker -------------------------------------------------------------

log "Installing Docker"
apk update
apk add --no-cache docker docker-cli-compose openssh doas

log "Enabling Docker at boot"
rc-update add docker default
rc-service docker start || true   # already running on re-run

# A network several apps can join, so a shared reverse proxy can reach them
# without any app publishing a port. Declared `external: true` in each app's
# compose.yml. Created here because it has to exist before the first app that
# references it, and nothing else on the box owns it.
if [ -n "$SHARED_NETWORK" ]; then
	if docker network inspect "$SHARED_NETWORK" >/dev/null 2>&1; then
		log "Shared network '$SHARED_NETWORK' already exists"
	else
		log "Creating shared network '$SHARED_NETWORK'"
		docker network create "$SHARED_NETWORK" >/dev/null
	fi
fi

# --- 2. CI user ------------------------------------------------------------

log "Creating user '$CI_USER'"
if ! id "$CI_USER" >/dev/null 2>&1; then
	# -D: no password (key-only login), -s: shell needed for SSH commands
	adduser -D -s /bin/sh "$CI_USER"
fi
# The password field must be "*", and this is load-bearing rather than tidy-up.
#
# "adduser -D" writes "!", which sshd reads as ACCOUNT LOCKED and then refuses
# every authentication method -- including publickey. The deploy user could not
# log in at all:
#
#   User cd-app not allowed because account is locked
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

log "Installing deploy key"
ssh_dir="/home/$CI_USER/.ssh"
mkdir -p "$ssh_dir"
touch "$ssh_dir/authorized_keys"

# Keys are matched on their COMMENT field, so rotating a key replaces the old
# one instead of leaving it authorized alongside the new one. Appending was the
# earlier behaviour and it meant every rotation silently widened access --
# the old key kept working until someone remembered to prune the file by hand.
#
# A key with no comment cannot be matched that way, so fall back to exact-line
# dedup for those. Either path leaves the file identical on a re-run.
key_comment="$(printf '%s' "$CI_PUBKEY" | cut -d' ' -f3-)"
if [ -n "$key_comment" ]; then
	tmp="$ssh_dir/.authorized_keys.$$"
	awk -v want="$key_comment" '
		{
			com = ""
			for (i = 3; i <= NF; i++) com = com (i > 3 ? " " : "") $i
			if (com != want) print
		}
	' "$ssh_dir/authorized_keys" > "$tmp"
	mv "$tmp" "$ssh_dir/authorized_keys"
	printf '%s\n' "$CI_PUBKEY" >> "$ssh_dir/authorized_keys"
else
	grep -qxF "$CI_PUBKEY" "$ssh_dir/authorized_keys" || \
		printf '%s\n' "$CI_PUBKEY" >> "$ssh_dir/authorized_keys"
fi

chmod 700 "$ssh_dir"
chmod 600 "$ssh_dir/authorized_keys"
chown -R "$CI_USER:$CI_USER" "$ssh_dir"

log "Preparing $APP_DIR"
# Root-owned on purpose: if the CI user could edit compose.yml it could mount
# the host filesystem into a container, which is the same as being root.
mkdir -p "$APP_DIR"
chown root:root "$APP_DIR"
chmod 755 "$APP_DIR"
if [ ! -f "$APP_DIR/compose.yml" ]; then
	printf 'services: {}\n' > "$APP_DIR/compose.yml"
fi
chown root:root "$APP_DIR/compose.yml"
chmod 644 "$APP_DIR/compose.yml"
# Three env files, split by who writes them and who may read them:
#
#   .env         APP_VERSION only. Compose reads this for ${APP_VERSION}
#                substitution in compose.yml. Written by the deploy script.
#   config.env   Non-secret service config, shipped in the config image and
#                replaced on every deploy. Safe to read; it is in a registry.
#   secrets.env  Production credentials, written only by set-secret. 600 so the
#                CI user cannot read it back -- it may set values, never read
#                them.
for f in .env config.env secrets.env; do
	touch "$APP_DIR/$f"
	chown root:root "$APP_DIR/$f"
done
chmod 600 "$APP_DIR/.env" "$APP_DIR/secrets.env"
chmod 644 "$APP_DIR/config.env"

# --- 3. Deploy path --------------------------------------------------------
# The only privileged thing the CI user may do, besides setting a secret.
#
# It takes one argument, the image tag to deploy. doas "cmd" without an "args"
# clause permits ANY arguments, so the script validates the tag itself rather
# than trusting the caller -- it is substituted into .env via sed, and used as
# an image tag and a path component, so a value containing a newline, a slash
# or a shell metacharacter could otherwise do real damage.
#
# When CONFIG_IMAGE is set, compose.yml and config.env come OUT OF THE IMAGE
# for that tag rather than off the disk. That is what lets CI change the shape
# of the stack without ever writing to this box: the file arrives as a registry
# layer that root extracts, so altering it requires registry push, which
# already implied code execution here. The CI user gains nothing.

log "Installing $DEPLOY_BIN"
cat > "$DEPLOY_BIN" <<EOF
#!/bin/sh
set -eu

CONFIG_IMAGE="$CONFIG_IMAGE"

version="\${1:-}"
cd "$APP_DIR"

# Tags and SHAs only: letters, digits, dot, underscore, hyphen. Required --
# every deploy names a version, because the config for that version has to be
# fetched before anything can run.
case "\$version" in
	*[!A-Za-z0-9._-]*|'')
		echo "deploy: usage: deploy <tag>" >&2
		echo "deploy: refusing version '\$version'" >&2
		exit 1
		;;
esac

# Reported because the CI user cannot read .env itself (600 root) and has no
# other way to learn what it is replacing. Printed before anything changes, so
# it is still correct if a later step fails -- which is exactly when a caller
# wants it, to roll back to. Machine-readable on purpose: the set-version
# action parses this line.
previous="\$(sed -n 's/^APP_VERSION=//p' .env 2>/dev/null | head -n 1)"
echo "deploy: previous-version=\${previous:-}"

ref="\$CONFIG_IMAGE:\$version"
echo "deploy: fetching config from \$ref"
docker pull -q "\$ref" >/dev/null

# 'docker create' + 'docker cp' rather than 'docker run': the config image
# is FROM scratch and has no shell to run anything with.
#
# --entrypoint is required, not cosmetic: 'docker create' refuses an image
# with no command at all, which a bare scratch image has. The container is
# only ever created and copied out of, never started, so the value is
# irrelevant -- it just has to be present.
staging="\$(mktemp -d)"
cid="\$(docker create --entrypoint /nonexistent "\$ref")"
docker cp "\$cid:/config/." "\$staging/" >/dev/null
docker rm -v "\$cid" >/dev/null

if [ ! -f "\$staging/compose.yml" ]; then
	rm -rf "\$staging"
	echo "deploy: \$ref has no /config/compose.yml" >&2
	exit 1
fi

# Swap both files in, then validate what compose actually resolves. A
# broken compose.yml must not be left behind on a box that was working, so
# keep backups and put them back if the check fails.
cp compose.yml compose.yml.prev
cp config.env config.env.prev
cat "\$staging/compose.yml" > compose.yml
if [ -f "\$staging/config.env" ]; then
	cat "\$staging/config.env" > config.env
fi
rm -rf "\$staging"

# APP_VERSION is passed in rather than read from .env: the file is only
# updated once this check passes, so without it compose would validate the
# new file against the previous version and warn about an unset variable.
if ! APP_VERSION="\$version" docker compose config -q; then
	cat compose.yml.prev > compose.yml
	cat config.env.prev > config.env
	rm -f compose.yml.prev config.env.prev
	echo "deploy: compose.yml from \$ref is not valid -- reverted, nothing restarted" >&2
	exit 1
fi
rm -f compose.yml.prev config.env.prev

# Committed only once the config for this version is in place and valid, so a
# deploy that fails earlier leaves the box claiming the version it is actually
# still running. Persisted so a later manual 'docker compose up -d' keeps this
# commit instead of drifting back to :latest.
if grep -q '^APP_VERSION=' .env; then
	sed -i "s|^APP_VERSION=.*|APP_VERSION=\$version|" .env
else
	printf 'APP_VERSION=%s\n' "\$version" >> .env
fi

docker compose pull
docker compose up -d --remove-orphans
docker image prune -f

# Show the resulting topology. Without this a compose.yml that silently drops
# or renames a service looks identical in the log to one that changed nothing.
docker compose ps --format 'table {{.Service}}\t{{.Image}}\t{{.Status}}'
EOF
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
cat > "$SECRET_BIN" <<EOF
#!/bin/sh
set -eu

name="\${1:-}"
cd "$APP_DIR"

# Env-var charset. Also makes the name safe as a grep pattern below.
case "\$name" in
	*[!A-Za-z0-9_]*|'')
		echo "set-secret: invalid name '\$name'" >&2
		exit 1
		;;
esac

# \$(cat) strips trailing newlines, which is what an env file wants anyway.
value="\$(cat)"
case "\$value" in
	*"
"*)
		echo "set-secret: value for \$name contains a newline, which an env file cannot represent" >&2
		exit 1
		;;
esac

umask 077
tmp="\$(mktemp "$APP_DIR/.secrets.XXXXXX")"
# Drop any existing line for this key, then append the new one. Rewriting via
# a temp file and mv makes the update atomic: a reader never sees the file
# without the key, and a crash mid-write cannot truncate it.
grep -v "^\$name=" secrets.env > "\$tmp" 2>/dev/null || true
printf '%s=%s\n' "\$name" "\$value" >> "\$tmp"
chown root:root "\$tmp"
chmod 600 "\$tmp"
mv -f "\$tmp" secrets.env

echo "set-secret: \$name updated"
EOF
chown root:root "$SECRET_BIN"
chmod 755 "$SECRET_BIN"

log "Granting '$CI_USER' doas access to $DEPLOY_BIN and $SECRET_BIN only"
# Written straight into doas.conf rather than a /etc/doas.d drop-in: doas has
# no portable include directive, and a drop-in that is never read would fail
# open-looking but silently do nothing.
touch /etc/doas.conf
# Delimited block, so the rule set can grow without the removal logic having to
# know how many lines it spans.
# Keyed on the project rather than this file, so adding a script for another
# distro later does not orphan rules written by this one.
# The alternation covers names this project has been published under, so a
# re-run over a box bootstrapped by an older version replaces its block rather
# than leaving a second one behind.
sed -i -E "/^# $PROJECT_MARKERS: $CI_USER BEGIN\$/,/^# $PROJECT_MARKERS: $CI_USER END\$/d" /etc/doas.conf
# Older still: a single unmarked rule, before the block form existed.
sed -i "/# boot.sh: $CI_USER deploy/,+1d" /etc/doas.conf
cat >> /etc/doas.conf <<-EOF
	# ncicd: $CI_USER BEGIN
	permit nopass $CI_USER as root cmd $DEPLOY_BIN
	permit nopass $CI_USER as root cmd $SECRET_BIN
	# ncicd: $CI_USER END
EOF
chown root:root /etc/doas.conf
chmod 600 /etc/doas.conf
doas -C /etc/doas.conf || die "generated doas.conf is invalid"

# --- 4. sshd ---------------------------------------------------------------
# Two separate things, deliberately:
#
#   ALWAYS   a Match block scoped to $CI_USER. It constrains only the account
#            this script just created, so it can never lock anyone out and
#            needs no opt-out. This is where the real value is: without
#            AllowTcpForwarding no, a leaked deploy key can tunnel arbitrary
#            TCP through this box -- reaching a database bound to localhost,
#            or anything else routable from here.
#
#   OPT-IN   the global PermitRootLogin / PasswordAuthentication settings.
#            Whether root may use a password is a policy decision about the
#            whole machine, not something a deploy tool should impose.
#            HARDEN_SSH=1 asks for it.

conf=/etc/ssh/sshd_config
cp "$conf" "$conf.bak.boot"

# The deploy-user block is always removed, because it is always re-added
# below. The global block is only removed when we are about to rewrite it --
# otherwise re-running WITHOUT HARDEN_SSH=1 would silently undo hardening a
# previous run applied.
# Keyed on the USER, so a box hosting several apps -- each with its own deploy
# account -- gets one Match block per account instead of them overwriting each
# other.
sed -i -E \
	-e "/^# $PROJECT_MARKERS: sshd $CI_USER BEGIN\$/,/^# $PROJECT_MARKERS: sshd $CI_USER END\$/d" \
	-e "/^# $PROJECT_MARKERS: deploy-user BEGIN\$/,/^# $PROJECT_MARKERS: deploy-user END\$/d" \
	"$conf"

if [ "$HARDEN_SSH" = "1" ]; then
	log "Hardening sshd for all users"
	# Refuse to disable password auth unless root can still get in by key,
	# otherwise a box with no console access becomes unreachable.
	if [ ! -s /root/.ssh/authorized_keys ]; then
		mv "$conf.bak.boot" "$conf"
		die "/root/.ssh/authorized_keys is empty -- install your own key first, or drop the hardening flag"
	fi
	sed -i -E \
		-e "/^# $PROJECT_MARKERS: global BEGIN\$/,/^# $PROJECT_MARKERS: global END\$/d" \
		-e "/^[[:space:]]*# set by $PROJECT_MARKERS[[:space:]]*\$/d" \
		-e '/^[[:space:]]*#?[[:space:]]*(PermitRootLogin|PasswordAuthentication)[[:space:]]/d' \
		"$conf"
	# PREPENDED, not appended. sshd_config takes the FIRST value it obtains for
	# a keyword, and a Match block applies to everything after it -- so a global
	# block written at the end would land inside whichever Match block happens
	# to precede it, silently scoping machine-wide settings to one account.
	# At the top it wins outright and sits before every Match.
	tmp_conf="$conf.cicd.$$"
	{
		printf '%s\n' "# ncicd: global BEGIN"
		printf '%s\n' "PermitRootLogin prohibit-password"
		printf '%s\n' "PasswordAuthentication no"
		printf '%s\n' "# ncicd: global END"
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
	# ncicd: sshd $CI_USER BEGIN
	# Applies to $CI_USER only; no other account is affected.
	# NOTE: everything below this line is inside the Match block. Put global
	# settings ABOVE it.
	Match User $CI_USER
	    PasswordAuthentication no
	    PermitEmptyPasswords no
	    AllowTcpForwarding no
	    AllowAgentForwarding no
	    PermitTunnel no
	    GatewayPorts no
	    X11Forwarding no
	# ncicd: sshd $CI_USER END
EOF

if sshd -t; then
	rc-service sshd reload || rc-service sshd restart
else
	mv "$conf.bak.boot" "$conf"
	die "sshd config test failed, reverted -- nothing was restarted"
fi

log "Done"
cat <<EOF

  app:      $APP_NAME
  user:     $CI_USER (no docker group, no shell privileges)
  app dir:  $APP_DIR (root-owned)
  deploy:   doas $DEPLOY_BIN
  secrets:  doas $SECRET_BIN <NAME>  (value on stdin)
  config:   $CONFIG_IMAGE
  docker:   $(docker --version)

EOF

cat <<-EOF
	compose.yml and config.env come from $CONFIG_IMAGE:<tag> on every deploy.
	Nothing to install by hand. From CI:
	  ssh $CI_USER@<host> doas $DEPLOY_BIN <tag>
EOF

cat <<EOF

NOTE on what this contains. '$CI_USER' can do exactly two things: deploy a tag
that already exists in your registry, and set a secret it cannot read back. It
cannot run docker, write anything under $APP_DIR, or introduce new code --
compose.yml arrives as a registry layer that root extracts, so changing the
shape of the stack requires push access to the registry.

That is the real boundary: REGISTRY PUSH is root-equivalent on this box, the
deploy key is not. A leaked deploy key lets an attacker roll the stack back to
any tag you have already published -- including one with a known bug -- and
overwrite (not read) secrets. It does not let them run code of their own.

Protect registry push accordingly, and pin your CI's third-party actions by
SHA: they run in the same job as the deploy key.
EOF
