#!/bin/sh
# Read-only fields-postgres-v1 status. One nonsecret line. No env values.
set -eu

APP_NAME="__APP_NAME__"
STATE_FILE="__STATE_FILE__"
LOCK_FILE="__LOCK_FILE__"
PROFILE="fields-postgres-v1"

hex32() {
	awk -v s="$1" 'BEGIN { exit (s ~ /^[0-9a-f]{32}$/) ? 0 : 1 }'
}

[ "$#" -eq 0 ] || exit 1
if [ ! -t 0 ]; then
	if IFS= read -r _extra; then
		exit 1
	fi
fi
[ "$(id -u)" -eq 0 ] || exit 1

emit() {
	printf 'wire=v2 profile=fields-postgres-v1 source=host-local state=%s generation=%s reason=%s\n' "$1" "$2" "$3"
	exit 0
}

state_get() {
	sed -n "s/^$1=//p" "$STATE_FILE" | tr -d '\r' | head -n 1
}

if [ ! -f "$STATE_FILE" ] || [ "$(state_get APP_NAME)" != "$APP_NAME" ] || [ "$(state_get SCOPED_ENV)" != "$PROFILE" ]; then
	emit invalid none profile-mismatch
fi
APP_DIR=$(state_get APP_DIR)
case "$APP_DIR" in
	/*) ;;
	*) emit invalid none profile-mismatch ;;
esac

if ! command -v flock >/dev/null 2>&1; then
	exit 1
fi
mkdir -p "$(dirname "$LOCK_FILE")"
: > "$LOCK_FILE"
exec 9>"$LOCK_FILE"
if ! flock -w 300 9; then
	exit 75
fi

secrets="$APP_DIR/secrets"
if [ -L "$secrets" ]; then
	emit invalid none symlink
fi
if [ ! -d "$secrets" ]; then
	emit missing none no-current
fi
if [ -L "$secrets/generations" ]; then
	emit invalid none symlink
fi
if [ -e "$secrets/current" ] && [ ! -L "$secrets/current" ]; then
	emit invalid none partial
fi
if [ ! -L "$secrets/current" ]; then
	if [ -d "$secrets/generations" ] && [ -n "$(ls -A "$secrets/generations" 2>/dev/null || true)" ]; then
		emit invalid none partial
	fi
	emit missing none no-current
fi
target=$(readlink "$secrets/current" || true)
id=${target#generations/}
if [ "$target" = "$id" ] || ! hex32 "$id" || [ "$target" != "generations/$id" ]; then
	emit invalid none symlink
fi
gdir="$secrets/generations/$id"
if [ -L "$gdir" ] || [ ! -d "$gdir" ]; then
	emit invalid none partial
fi
for f in postgres.env migrate.env api.env godot-api.env; do
	p="$gdir/$f"
	if [ -L "$p" ]; then
		emit invalid none symlink
	fi
	if [ ! -f "$p" ]; then
		emit invalid none partial
	fi
	mode=$(stat -c %a "$p" 2>/dev/null || true)
	owner=$(stat -c %u "$p" 2>/dev/null || true)
	if [ "$mode" != "600" ] || [ "$owner" != "0" ]; then
		emit invalid none bad-mode
	fi
done
for d in "$secrets" "$secrets/generations" "$gdir"; do
	if [ -L "$d" ] || [ ! -d "$d" ]; then
		emit invalid none symlink
	fi
	mode=$(stat -c %a "$d" 2>/dev/null || true)
	owner=$(stat -c %u "$d" 2>/dev/null || true)
	if [ "$mode" != "700" ] || [ "$owner" != "0" ]; then
		emit invalid none bad-mode
	fi
done
recorded=$(state_get SCOPED_GENERATION || true)
if [ "$recorded" != "$id" ]; then
	emit invalid none partial
fi
emit ready "$id" ok
