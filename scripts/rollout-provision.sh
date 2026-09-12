#!/bin/sh
# Install only a validated app-scoped rollout profile and its new authority
# files. The app broker itself is refreshed separately from its existing record.
set -eu
umask 077

[ "$(id -u)" = 0 ] || { echo 'rollout provision requires root' >&2; exit 1; }
case "${APP_NAME:-}" in
	''|*[!A-Za-z0-9_-]*) echo 'invalid rollout application scope' >&2; exit 1 ;;
esac
[ -f "/var/lib/komizo/apps/$APP_NAME.env" ] || {
	echo "rollout provision: $APP_NAME is not an existing Komizo application" >&2
	exit 1
}
[ -x "/usr/local/bin/rollout-$APP_NAME" ] || {
	echo "rollout provision: refresh the $APP_NAME broker before installing its profile" >&2
	exit 1
}

tmp=$(mktemp "/tmp/komizo-rollout-$APP_NAME.XXXXXX")
cleanup() { rm -f "$tmp"; }
trap cleanup EXIT
trap 'cleanup; exit 129' HUP INT TERM PIPE
printf '%s' '__PROFILE_BASE64__' | base64 -d > "$tmp"
chown root:root "$tmp"
chmod 600 "$tmp"
__ROLLOUT_BIN__ rollout profile --provision --profile "$tmp" --app "$APP_NAME"
echo "rollout provision: installed inactive authority for $APP_NAME"
