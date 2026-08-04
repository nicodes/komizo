set -eu
log() { printf '\n==> %s\n' "$*"; }

# Stop reporting, and forget the credential. Run as root, from
# `komizo enrol --remove`.
#
# The SERVICE side -- revoking the token -- is done there. Neither implies the
# other: a box that has forgotten still has a row going quiet on the dashboard,
# and a revoked token still sits on a box until somebody removes it.

if command -v rc-update >/dev/null 2>&1; then
	rc-service komizo-agent stop >/dev/null 2>&1 || true
	rc-update del komizo-agent default >/dev/null 2>&1 || true

	# And the read API. Un-enrolling removes the credential, so it holds the
	# key this verified against -- a box that kept serving after it would be
	# answering to a registry it no longer belongs to.
	rc-service komizo-api stop >/dev/null 2>&1 || true
	rc-update del komizo-api default >/dev/null 2>&1 || true
fi

log "Removing the credential"

# if-then-else, not `A && B || C`: in that form C also runs when B FAILS, so an
# unenrol that errored would fall through to the rm and hide why.
if [ -x /usr/local/bin/komizo-box ]; then
	/usr/local/bin/komizo-box unenrol
else
	# No binary to ask. The file is the credential, so removing it is the whole
	# of what unenrolling means.
	rm -f __CONF__
	printf 'removed __CONF__\n'
fi
