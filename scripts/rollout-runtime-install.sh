#!/bin/sh
# Install the matching komizo-box only for one application's rollout broker.
# This deliberately does not replace /usr/local/bin/komizo-box or restart any
# shared service on a host carrying other applications.
set -eu

staged=__STAGED__
destination=__DESTINATION__
expected=__SHA256__

cleanup() { rm -f "$staged"; }
trap cleanup EXIT
trap 'cleanup; exit 129' HUP INT TERM PIPE

[ "$(id -u)" = 0 ] || { echo 'rollout runtime installation requires root' >&2; exit 1; }
[ -f "$staged" ] && [ ! -L "$staged" ] || { echo 'staged rollout runtime is unsafe' >&2; exit 1; }
[ "$(stat -c '%u:%g' "$staged")" = '0:0' ] || { echo 'staged rollout runtime is not root-owned' >&2; exit 1; }
[ "$(sha256sum "$staged" | cut -d ' ' -f 1)" = "$expected" ] || { echo 'staged rollout runtime checksum mismatch' >&2; exit 1; }

for directory in /usr/local /usr/local/libexec /usr/local/libexec/komizo /usr/local/libexec/komizo/rollouts "${destination%/*}"; do
	if [ ! -e "$directory" ] && [ ! -L "$directory" ]; then
		mkdir "$directory"
		chown root:root "$directory"
		chmod 755 "$directory"
	fi
	[ -d "$directory" ] && [ ! -L "$directory" ] || { echo 'rollout runtime directory is unsafe' >&2; exit 1; }
	owner_mode=$(stat -c '%u:%g:%a' "$directory")
	case "$owner_mode" in
		0:0:755|0:0:750|0:0:700) ;;
		*) echo 'rollout runtime directory is not safely root-owned' >&2; exit 1 ;;
	esac
done

chown root:root "$staged"
chmod 755 "$staged"
mv -f "$staged" "$destination"
[ -x "$destination" ] && [ ! -L "$destination" ]
"$destination" rollout profile --help >/dev/null
echo 'installed app-scoped rollout runtime'
