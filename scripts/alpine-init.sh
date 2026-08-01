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

log "Done"
cat <<EOF

  docker:   $(docker --version)
  compose:  $(docker compose version 2>/dev/null || echo 'not reporting a version')
  network:  $SHARED_NETWORK

This server is ready for apps. Nothing has been created for any app yet, and no
accounts exist -- adding one is what creates its directory, its deploy account
and its privileged commands.
EOF
