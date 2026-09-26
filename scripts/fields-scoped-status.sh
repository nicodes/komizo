#!/bin/sh
# Read-only fields-postgres-v2 status. One nonsecret line. No env values.
# A fields-postgres-v1 record, or a generation without a production
# CLERK_SECRET_KEY confined to api.env, is not ready.
set -eu

APP_NAME="__APP_NAME__"
STATE_FILE="__STATE_FILE__"
LOCK_FILE="__LOCK_FILE__"
PROFILE="fields-postgres-v2"

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
	printf 'wire=v2 profile=fields-postgres-v2 source=host-local state=%s generation=%s reason=%s\n' "$1" "$2" "$3"
	exit 0
}

state_get() {
	sed -n "s/^$1=//p" "$STATE_FILE" | tr -d '\r' | head -n 1
}

# Names only, plus the production-key prefix. File bytes are not printed.
v2_layout() {
	gdir=$1
	awk '
	function bad(s) {
		if (length(s) < 9 || length(s) > 4096) return 1
		if (substr(s, 1, 8) == "sk_test_") return 1
		if (substr(s, 1, 8) != "sk_live_") return 1
		n = length(s)
		for (i = 1; i <= n; i++) {
			c = substr(s, i, 1)
			if (c ~ /[ "#$'\''\\`]/) return 1
			if (c < "!" || c > "~") return 1
		}
		return 0
	}
	BEGIN {
		req["postgres.env"] = " POSTGRES_PASSWORD REVIK_MIGRATOR_PASSWORD REVIK_APP_PASSWORD REVIK_BACKUP_PASSWORD "
		req["migrate.env"] = " DATABASE_MIGRATION_URL "
		req["api.env"] = " DATABASE_URL WS_SECRET CLERK_ISSUER CLERK_JWKS_URL CLERK_AUTHORIZED_PARTIES CLERK_SECRET_KEY "
		req["godot-api.env"] = " WS_SECRET "
		secrets = 0
		failed = 0
	}
	{
		fn = FILENAME
		sub(/^.*\//, "", fn)
		if (index($0, "CLERK_SECRET_KEY") != 0) {
			if (fn != "api.env" || $0 !~ /^CLERK_SECRET_KEY=/) failed = 1
			secrets++
			if (bad(substr($0, 18))) failed = 1
		}
		if ($0 ~ /^[A-Za-z0-9_]+=/) {
			k = $0
			sub(/=.*/, "", k)
			seen[fn, k] = 1
		}
	}
	END {
		if (failed || secrets != 1) exit 1
		for (fn in req) {
			n = split(req[fn], keys, " ")
			for (i = 1; i <= n; i++) {
				if (keys[i] != "" && seen[fn, keys[i]] != 1) exit 1
			}
		}
		exit 0
	}
	' "$gdir/postgres.env" "$gdir/migrate.env" "$gdir/api.env" "$gdir/godot-api.env"
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
if ! v2_layout "$gdir"; then
	emit invalid none profile-mismatch
fi
emit ready "$id" ok
