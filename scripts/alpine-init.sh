#!/bin/sh
# cli/scripts/alpine-init.sh - prepares a fresh server, run as root on the box.
#
# komizo embeds this and pipes it over SSH. To read it: `komizo script init`.
#
# This is everything that belongs to the SERVER rather than to any one app:
# the container runtime and the network apps share. It creates no accounts,
# writes nothing into /srv, and knows about no apps.
#
# It is a separate step, and separate on purpose. Installing Docker as a side
# effect of adding the first app meant a fresh box had no state you could name:
# `komizo proxy` would fail on it, and there was nothing to look at that said
# what was and was not set up. Now a server is either initialised or it is not,
# and the interface can say which.
#
# Safe to re-run: apk is idempotent, and the network is only created if absent.
#
# Inputs, all environment variables:
#   SHARED_NETWORK docker network apps join to be reachable  (default: edge)

set -eu

SHARED_NETWORK="${SHARED_NETWORK:-edge}"

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root"

case "$SHARED_NETWORK" in
	''|*[!A-Za-z0-9._-]*) die "SHARED_NETWORK must be letters, digits, dot, underscore or hyphen" ;;
esac

RECLAIM_BIN=/etc/periodic/daily/komizo-reclaim

# --- 1. packages -----------------------------------------------------------
# openssh and doas are here rather than assumed: doas is what grants the deploy
# accounts their two privileged commands, and a box reached over SSH already has
# sshd but not necessarily the config tooling.

log "Installing Docker"
apk update
# Only what is MISSING is installed. `apk add` on an already-present package
# upgrades it to whatever the repository now offers, and this script is re-run
# by "update komizo" (u in the interface) -- whose prompt promises the apps keep
# running and nothing is deleted. Silently staging a new Docker under a box full
# of running containers is not that promise: the daemon holds its old binary
# until something restarts it, so the change lands at the next reboot rather
# than at the operation that caused it.
#
# Upgrading is a real thing to want, and it is a thing to do on purpose:
# `apk upgrade docker` over the same connection, when you have decided to.
missing=""
for pkg in docker docker-cli-compose openssh doas; do
	apk info -e "$pkg" >/dev/null 2>&1 || missing="$missing $pkg"
done
if [ -n "$missing" ]; then
	log "Installing:$missing"
	# shellcheck disable=SC2086 # deliberate word splitting: one package per arg
	apk add --no-cache $missing
else
	log "Docker, compose, openssh and doas are already installed"
fi

log "Enabling Docker at boot"
rc-update add docker default
rc-service docker start || true   # already running on re-run

# Wait for the daemon rather than assuming `rc-service start` means ready: the
# next step talks to it, and on a cold boot the socket can lag the service by a
# second or two.
i=0
while ! docker info >/dev/null 2>&1; do
	i=$((i + 1))
	[ "$i" -gt 30 ] && die "Docker did not become ready within 30s -- check 'rc-service docker status'"
	sleep 1
done

# --- 2. the shared network -------------------------------------------------
# Created here rather than by any app's compose or by the proxy, because it
# outlives all of them: an app can declare it `external: true` before the proxy
# exists, and removing an app must not take it with them.

if docker network inspect "$SHARED_NETWORK" >/dev/null 2>&1; then
	log "Shared network '$SHARED_NETWORK' already exists"
else
	log "Creating shared network '$SHARED_NETWORK'"
	docker network create "$SHARED_NETWORK" >/dev/null
fi

# --- 3. keep containers off the cloud metadata endpoint --------------------
# Every container can otherwise reach 169.254.169.254 -- the instance metadata
# service, which on AWS/GCP hands IAM credentials to anything that asks from the
# instance. An SSRF or RCE in any app would then read the box's cloud creds. A
# DROP in DOCKER-USER (the chain Docker leaves for operator rules, evaluated
# before its own forwarding) closes it for containers without touching host
# traffic. Applied now, and re-applied at boot via /etc/local.d because Docker
# rebuilds its chains on restart and iptables rules do not survive a reboot.
#
# NOTE: if an app on this box is MEANT to use an IAM role from the metadata
# service, remove /etc/local.d/komizo-firewall.start and flush the rule.
metadata_guard() {
	command -v iptables >/dev/null 2>&1 || return 0
	iptables -L DOCKER-USER >/dev/null 2>&1 || return 0
	iptables -C DOCKER-USER -d 169.254.169.254/32 -j DROP 2>/dev/null \
		|| iptables -I DOCKER-USER -d 169.254.169.254/32 -j DROP
}
log "Blocking container access to the cloud metadata endpoint (169.254.169.254)"
metadata_guard || true

mkdir -p /etc/local.d
cat > /etc/local.d/komizo-firewall.start <<'EOF'
#!/bin/sh
# Written by komizo (alpine-init.sh). Re-applies the container metadata-endpoint
# block at boot, because Docker rebuilds its iptables chains on start and the
# rule does not otherwise persist a reboot. Remove this file to allow access.
command -v iptables >/dev/null 2>&1 || exit 0
iptables -L DOCKER-USER >/dev/null 2>&1 || exit 0
iptables -C DOCKER-USER -d 169.254.169.254/32 -j DROP 2>/dev/null \
	|| iptables -I DOCKER-USER -d 169.254.169.254/32 -j DROP
EOF
chmod 755 /etc/local.d/komizo-firewall.start
rc-update add local default >/dev/null 2>&1 || true

# --- Reclaim images no container is using --------------------------------
#
# Every deploy and every preview pulls an image tagged by commit, and nothing
# had ever removed the one it replaced. Two boxes reached 92% and 84%
# reclaimable: 162 and 172 images, of which 15 and 8 were in use. gdam alone
# held fourteen copies of the same 157MB gate image, all from one day.
#
# The deploy script explains at length why it is not the place for this -- a
# machine-wide prune does not belong in a per-app path a deploy key can
# invoke -- and ends "Disk is a SERVER concern. It belongs wherever
# server-wide upkeep ends up living." This is that place: server-level,
# operator-run, and reachable by nobody's deploy key.
#
# KEEP WHAT A CONTAINER REFERENCES, DROP THE REST. Not "the last few
# versions": a rollback never needs a local image. revert() in the app script
# restores config files and deliberately restarts nothing, so the previous
# containers are still up and still hold their images; going back to an older
# release is an ordinary deploy of that tag, which pulls it. The worst a
# too-eager prune can cost is one pull, and ghcr is the source of truth.
#
# Stopped containers count as references, so an app somebody has stopped keeps
# the image it will start again with.
#
# ON A SCHEDULE, not once. The first version of this ran here and only here,
# which meant it ran the day the box was built and never again -- and the
# thing it defends against is accumulation over weeks. A box drifted to 92%
# full, crossed the capacity floor the deploy script enforces, and then every
# app on it refused to deploy with no way to recover but an operator at an SSH
# prompt. A floor with nothing keeping the box above it converts a slow
# problem into a hard stop. So the reclaim is installed as a daily job and
# then invoked once, here: same script both times, so the scheduled run and
# the init run can never drift apart.
# --- komizo's own preview database server -------------------------------------
#
# ONE postgres per host, owned by komizo, for the per-PR databases previews
# need. It is not any product's: no product connects to it in production, no
# product's data is in it, and losing it costs nothing but open previews.
#
# This replaces reaching into the app's production postgres. `komizo preview
# up` used to run CREATE ROLE and CREATE DATABASE as superuser against the
# container serving production, discovered by inspecting the app's compose
# project. It was carefully contained -- only its own objects named, and
# teardown dropped only those -- but the blast radius was the production
# database server of the thing being previewed, which is the opposite of
# what komizo is for. It also meant a product with no database could not
# have a preview at all, because there was nothing to put one beside:
#
#   no postgres container is running in ctcalc's project
#   -- a preview needs the app's database to put its own beside
#
# A NAMED VOLUME, on disk, not a tmpfs. These boxes have 960MB of RAM with
# roughly 400MB free, so holding preview data in memory would put postgres
# and every app on the box in the same OOM. Disk is the resource there is
# 16GB of. Growth is bounded by teardown dropping each preview's database
# and by the TTL reaper, and the capacity floors still guard the rest.
#
# NO PUBLISHED PORT. It is reachable only over the shared network, by the
# preview containers attached to it, by container name.
#
# Same digest the products pin, so the host holds one postgres image rather
# than two, and a preview runs the server version production runs.
PREVIEW_DB_IMAGE="postgres@sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280"
PREVIEW_DB_NAME="komizo-previews"

log "Provisioning komizo's preview database server"
if [ "$(docker inspect -f '{{.State.Running}}' "$PREVIEW_DB_NAME" 2>/dev/null || echo false)" = "true" ]; then
	printf '    %s is already running\n' "$PREVIEW_DB_NAME"
else
	docker rm -f "$PREVIEW_DB_NAME" >/dev/null 2>&1 || true
	# The superuser password is generated and then DELIBERATELY DISCARDED.
	# komizo reaches postgres only by `docker exec`, over the unix socket,
	# which the stock image's pg_hba trusts -- so no superuser credential
	# has to be stored on the box or handed to anything.
	#
	# What the password buys is the other half: without POSTGRES_PASSWORD
	# the image wants POSTGRES_HOST_AUTH_METHOD=trust, and trust would let
	# ANY container on the shared network -- every preview, every app gate
	# -- connect to this server as the postgres superuser and read every
	# other preview's database. With scram over TCP, a preview can only
	# authenticate as the role it was given, with the password generated
	# for it alone.
	docker run -d \
		--name "$PREVIEW_DB_NAME" \
		--restart unless-stopped \
		--network "$SHARED_NETWORK" \
		-e POSTGRES_PASSWORD="$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')" \
		-e POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 \
		-e POSTGRES_USER=postgres \
		-e POSTGRES_DB=postgres \
		-v komizo-previews-data:/var/lib/postgresql/data \
		--memory 256m \
		"$PREVIEW_DB_IMAGE" >/dev/null ||
		die "could not start $PREVIEW_DB_NAME"
	printf '    started %s on %s\n' "$PREVIEW_DB_NAME" "$SHARED_NETWORK"
fi

# Running is not accepting connections. Wait here, once, so the first
# `preview up` on a fresh box does not fail on a server still recovering.
i=0
while [ "$i" -lt 60 ]; do
	if docker exec "$PREVIEW_DB_NAME" pg_isready -U postgres -d postgres >/dev/null 2>&1; then
		break
	fi
	i=$((i + 1))
	sleep 1
done
if [ "$i" -ge 60 ]; then
	die "$PREVIEW_DB_NAME started but never accepted connections"
fi
printf '    accepting connections\n'

log "Installing the daily image reclaim"
mkdir -p /etc/periodic/daily
cat > "$RECLAIM_BIN.tmp" <<'KOMIZO_RECLAIM_EOF'
#!/bin/sh
# /etc/periodic/daily/komizo-reclaim - installed by `komizo init`.
#
# Removes Docker images no container references. See the long explanation in
# alpine-init.sh for why this is server-level and why "referenced by a
# container" is the right rule rather than an age window.
#
# Never fails: this runs unattended out of crond, and a non-zero exit from a
# periodic job is noise an operator cannot act on. A prune that could not run
# today is a prune that runs tomorrow.
set -u

LOG=/var/log/komizo-reclaim.log

note() { printf '%s %s\n' "$(date -u '+%FT%TZ')" "$*" >> "$LOG"; }

if ! docker info >/dev/null 2>&1; then
	note "skipped: docker is not responding"
	exit 0
fi

# PREVIEWS FIRST, images second, and the order is the point. A preview whose
# PR was closed is torn down by CI, which stops its containers and so makes
# its image collectable by the prune below -- but only if the teardown
# actually happened. `preview gc` is the backstop for the ones where it did
# not: a PR left open for a month, a teardown job that failed, a stack from a
# branch nobody remembers. It reaps on the TTL and the max-N ceiling, and it
# touches ONLY previews it holds a state record for -- never an app, never a
# container or image it did not create. Like the prune, it was written and
# then never scheduled.
#
# Reaping before pruning means a preview released tonight has its image
# collected tonight, rather than sitting on disk until tomorrow.
if [ -x /usr/local/bin/komizo-box ]; then
	if out="$(/usr/local/bin/komizo-box preview gc 2>&1)"; then
		note "preview gc: $(printf '%s' "$out" | tr '\n' ' ')"
	else
		note "preview gc: failed, kept everything: $(printf '%s' "$out" | tr '\n' ' ')"
	fi
fi

before="$(docker system df --format '{{.Reclaimable}}' 2>/dev/null | head -1)"
docker image prune -af >/dev/null 2>&1 || true
note "reclaimed; was ${before:-unknown} reclaimable, now $(df -h / | awk 'NR==2 {print $4}') free on $(df -h / | awk 'NR==2 {print $6}')"

# One line a day, so a year of history is a year of lines. Trimmed rather
# than rotated: logrotate is one more thing to install and get wrong for a
# file that grows by about 90 bytes a day.
if [ -f "$LOG" ]; then
	tail -n 400 "$LOG" > "$LOG.tmp" 2>/dev/null && mv -f "$LOG.tmp" "$LOG"
fi
exit 0
KOMIZO_RECLAIM_EOF
mv "$RECLAIM_BIN.tmp" "$RECLAIM_BIN"
chown root:root "$RECLAIM_BIN"
chmod 755 "$RECLAIM_BIN"

# busybox crond is what runs /etc/periodic. It ships with Alpine but is not
# started on a minimal install, and an unstarted crond makes the job above a
# file nobody executes -- the exact failure this change exists to fix, just
# quieter.
rc-update add crond default >/dev/null 2>&1 || true
rc-service crond start >/dev/null 2>&1 || true
if ! rc-service crond status >/dev/null 2>&1; then
	printf '    WARNING: crond is not running; the daily reclaim will not fire\n' >&2
fi

log "Reclaiming images no container is using"
"$RECLAIM_BIN"
printf '    %s\n' "$(tail -n 1 /var/log/komizo-reclaim.log 2>/dev/null || echo 'no reclaim recorded')"
printf '    next run: nightly via %s\n' "$RECLAIM_BIN"

log "Done"
cat <<EOF

  docker:   $(docker --version)
  compose:  $(docker compose version 2>/dev/null || echo 'not reporting a version')
  network:  $SHARED_NETWORK

This server is ready for apps. Nothing has been created for any app yet, and no
accounts exist -- adding one is what creates its directory, its deploy account
and its privileged commands.
EOF
