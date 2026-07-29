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
apk add --no-cache docker docker-cli-compose openssh doas

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

log "Done"
cat <<EOF

  docker:   $(docker --version)
  compose:  $(docker compose version 2>/dev/null || echo 'not reporting a version')
  network:  $SHARED_NETWORK

This server is ready for apps. Nothing has been created for any app yet, and no
accounts exist -- adding one is what creates its directory, its deploy account
and its privileged commands.
EOF
