#!/bin/sh
# cli/scripts/preview-stackenv.sh - write ONE preview's stack.env, run as root.
#
# Installed on the box as /usr/local/bin/write-preview-stackenv for apps that
# have previews, and reachable from the deploy account through doas.
#
# WHY IT IS ROOT'S. A preview's stack.env holds the credentials that preview
# runs with, so it is written 0600 root:root into a directory the deploy
# account cannot otherwise touch. The account may only ASK for it to be
# written -- it never holds the path, the mode, or the ownership, and it
# cannot read the result back.
#
# WHY IT EXISTS HERE RATHER THAN ON THE BOX. It was a hand-installed script
# with a hand-added doas rule, and the rule lived inside komizo's own managed
# block: `komizo update` rewrote the block and deleted it, and gdam's previews
# failed on "doas: Operation not permitted" until somebody put it back. A
# feature that needs a privilege is a feature komizo has to install, or the
# privilege goes missing the next time komizo tidies up.
#
# The value arrives on STDIN and never as an argument: argv is visible in the
# host's process list to every other user on the box.
set -eu

[ "$#" -eq 2 ] || { echo "write-preview-stackenv: usage: <app> <pr>" >&2; exit 1; }
app="$1"
pr="$2"

# The app name reaches a path below, and the PR number reaches it too.
case "$app" in
	''|*[!a-z0-9-]*) echo "write-preview-stackenv: refused: bad app" >&2; exit 2 ;;
esac
case "$pr" in
	''|*[!0-9]*) echo "write-preview-stackenv: refused: bad pr" >&2; exit 2 ;;
esac

# One account, one app. doas sets DOAS_USER, and komizo names every deploy
# account komizo-<app>, so komizo-gdam writing a termcade preview is a request
# this refuses rather than one the doas rule has to be clever enough to
# prevent. Unset DOAS_USER means root ran it directly.
if [ -n "${DOAS_USER:-}" ] && [ "$DOAS_USER" != "komizo-$app" ]; then
	echo "write-preview-stackenv: refused: $DOAS_USER may not write $app previews" >&2
	exit 2
fi

dir="/var/lib/komizo/previews/${app}-pr-${pr}"
# Belt and braces over the two charset checks above: whatever those let
# through, the path this writes to still has to look like a preview's.
case "$dir" in
	/var/lib/komizo/previews/*-pr-*) : ;;
	*) echo "write-preview-stackenv: refused: bad path" >&2; exit 2 ;;
esac

install -d -m 0750 -o root -g root "$dir"
install -m 0600 -o root -g root /dev/stdin "$dir/stack.env"
