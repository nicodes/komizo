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
fi

log "Removing the credential"
[ -x /usr/local/bin/komizo-box ] && /usr/local/bin/komizo-box unenrol || rm -f __CONF__
