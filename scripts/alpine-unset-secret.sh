#!/bin/sh
# cli/scripts/alpine-unset-secret.sh - take secrets off a server, run as root.
#
# The CLI embeds this and pipes it over SSH. To read it: `komizo script unset-secret`.
#
# WHY THIS EXISTS. set-secret writes a key and never deletes one, so until now
# nothing could take a value off a box. A key dropped from a workflow stayed in
# secrets.env indefinitely -- referenced by nothing, rotated by nothing, and
# still readable by every container that reads the file. Across one portfolio
# that left twelve credentials on three servers, including a PocketBase admin
# password for a PocketBase that had been gone for months. The only way to
# remove one was to hand-edit secrets.env over SSH, which is exactly the
# unaccountable write the secret store exists to prevent.
#
# THE OPPOSITE OF set-secret, DELIBERATELY. set-secret is write-only and lives
# on the deploy account: CI can rotate a credential without being able to read
# the ones already there. This is neither of those things. It runs as root from
# an operator's machine, over the same connection `komizo remove` uses, and it
# is NOT installed on the box and NOT reachable through doas. A pipeline that
# could delete a secret could take an app down by deleting the one it needs to
# start, and no workflow has ever needed to.
#
# It prints the names it removed. It never prints, logs or copies a value --
# not the one being deleted and not the ones beside it. The backup it takes is
# a file mode 0600 owned by root, beside the original.
#
# Inputs:
#   APP_NAME  which app                                        (required)
#   NAMES     the keys to remove, whitespace-separated   (required unless LIST)
#   KEEP      1 to treat NAMES as the keys to KEEP instead      (default: 0)
#   LIST      1 to print the key names and change nothing       (default: 0)
#   APP_DIR   its directory                       (default: /srv/<app>)

set -eu

# root owns secrets.env and every copy of it. The CLI always pipes this to a
# root shell, so the only caller that is not root is a test driving the script
# against a fixture -- which cannot chown and does not need to, because the
# files it makes are already its own. Stated as a function so the ownership
# rule stays visible at each use rather than becoming a silent `|| true`.
own_root() {
	[ "$(id -u)" = 0 ] || return 0
	chown root:root "$1"
}

APP_NAME="${APP_NAME:-}"
NAMES="${NAMES:-}"
KEEP="${KEEP:-0}"
LIST="${LIST:-0}"

case "$APP_NAME" in
	'') echo "error: APP_NAME is required" >&2; exit 1 ;;
	# Reserved for komizo's own directories, /srv/_proxy among them.
	_*) echo "error: APP_NAME must not start with '_' -- those names are reserved" >&2; exit 1 ;;
	*[!A-Za-z0-9_-]*) echo "error: APP_NAME must be letters, digits, underscore or hyphen" >&2; exit 1 ;;
esac

if [ "$LIST" != 1 ]; then
	[ -n "$NAMES" ] || { echo "error: NAMES is required" >&2; exit 1; }
fi

# The env-var charset set-secret enforces on the way in, enforced again on the
# way out. Also what makes each name safe as a grep pattern below: a name
# containing a regex metacharacter would match keys nobody asked to remove.
for name in $NAMES; do
	case "$name" in
		*[!A-Za-z0-9_]*)
			echo "error: '$name' is not a valid secret name" >&2
			exit 1 ;;
	esac
done

# What komizo recorded when this app was set up, so an app given a custom
# directory is edited in its real one rather than in the default.
STATE_FILE="/var/lib/komizo/apps/$APP_NAME.env"
APP_DIR="${APP_DIR:-}"
if [ -z "$APP_DIR" ] && [ -f "$STATE_FILE" ]; then
	APP_DIR=$(sed -n 's/^APP_DIR=//p' "$STATE_FILE" | head -n 1)
fi
APP_DIR="${APP_DIR:-/srv/$APP_NAME}"

SECRETS="$APP_DIR/secrets.env"
if [ ! -f "$SECRETS" ]; then
	echo "error: $SECRETS does not exist -- is '$APP_NAME' an app on this box?" >&2
	exit 1
fi

cd "$APP_DIR"

# NAMES ONLY, and this is the one read in the file.
#
# There is no komizo command that prints a secret's value and there should not
# be: the store is write-only so that holding the deploy key is not the same as
# holding production. Knowing WHICH keys a box has is what an operator needs to
# find the ones nothing delivers any more, and it gives away nothing the
# repository's own workflow does not already say out loud.
if [ "$LIST" = 1 ]; then
	echo "$APP_NAME: $SECRETS"
	grep -oE '^[A-Za-z0-9_]+=' "$SECRETS" | tr -d '=' | sed 's/^/  /' || true
	exit 0
fi

# Refuse before changing anything when a name is not there.
#
# A no-op that reports success is how the twelve stale keys survived several
# people looking at them: every attempt to tidy up "worked". A typo in a key
# name is the likely cause, and the useful answer is which name, not silence.
#
# Skipped for --keep, where the caller is naming a desired end state rather
# than specific keys, and a name already absent is that state.
if [ "$KEEP" != 1 ]; then
	missing=
	for name in $NAMES; do
		grep -q "^$name=" "$SECRETS" || missing="$missing $name"
	done
	if [ -n "$missing" ]; then
		echo "error: not in $SECRETS:$missing" >&2
		echo "       nothing was changed. Read the current names with:" >&2
		echo "         komizo unset-secret --host HOST --app $APP_NAME --list" >&2
		exit 1
	fi
fi

# A dated copy, root-only, beside the original. Deleting a credential is the
# one operation here with no undo, and the value may be the last copy of
# something -- an age identity, a key nobody wrote down. The operator deletes
# this once the next deploy has proved the app still starts.
umask 077
backup="$SECRETS.$(date +%Y%m%d%H%M%S).bak"
cp -p "$SECRETS" "$backup"
own_root "$backup"
chmod 600 "$backup"

# Rewrite through a temp file and mv, the way set-secret does: the update is
# atomic, so a reader never sees the file mid-write and a crash cannot
# truncate it.
tmp="$(mktemp "$APP_DIR/.secrets.XXXXXX")"
if [ "$KEEP" = 1 ]; then
	for name in $NAMES; do
		grep "^$name=" "$SECRETS" >> "$tmp" || true
	done
else
	cp "$SECRETS" "$tmp"
	for name in $NAMES; do
		# Each pass reads the file written by the last one, so removing several
		# names cannot reinstate one an earlier pass took out.
		inner="$(mktemp "$APP_DIR/.secrets.XXXXXX")"
		grep -v "^$name=" "$tmp" > "$inner" || true
		mv -f "$inner" "$tmp"
	done
fi
own_root "$tmp"
chmod 600 "$tmp"

before=$(grep -cE '^[A-Za-z0-9_]+=' "$SECRETS" || true)
mv -f "$tmp" "$SECRETS"
after=$(grep -cE '^[A-Za-z0-9_]+=' "$SECRETS" || true)

echo "unset-secret: $APP_NAME went from $before to $after keys"
echo "unset-secret: a copy of the previous file is $backup -- delete it once a deploy has proved the app still starts"
echo "unset-secret: running containers keep the values they started with; the next deploy is what recreates them without these"
