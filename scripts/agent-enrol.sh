set -eu
log() { printf '\n==> %s\n' "$*"; }

# Exchange an enrolment token for this box's credential, and start the agent.
#
# Run as ROOT, on the box, from `komizo enrol`. The values arrive down the SSH
# connection in this script rather than on a remote command line, because a
# command line is visible in the process table to every account on the machine
# for as long as it runs.

[ -x /usr/local/bin/komizo-box ] || {
	echo "error: no komizo agent on this box -- run 'komizo init' first" >&2
	exit 1
}

log "Exchanging the enrolment token"
/usr/local/bin/komizo-box enrol --api __API__ --token __TOKEN__

# The property the agent depends on, PROVEN rather than assumed: root wrote the
# credential, and the account with no privileges can read it.
#
# Checked by actually reading it as that account. This is the third place the
# same shape has mattered -- the report, the state directory, and now this -- and
# it is the only one that would have failed silently, as an agent that starts,
# says it is not enrolled, and exits.
if ! su komizo_monitor -s /bin/sh -c "cat __CONF__ >/dev/null" 2>/dev/null; then
	printf 'error: komizo_monitor cannot read __CONF__.\n' >&2
	printf '       The agent runs as that account and cannot start without it.\n' >&2
	exit 1
fi

# Enabled only now. The agent exits immediately on a box with no credential, so
# starting it at install time would leave a service in the "crashed" column of
# every box that is only ever used through the CLI.
if command -v rc-update >/dev/null 2>&1; then
	rc-update add komizo-agent default >/dev/null 2>&1 || true
	rc-service komizo-agent restart >/dev/null 2>&1 || rc-service komizo-agent start >/dev/null 2>&1 || true
fi

log "Reporting as $(sed -n 's/.*"server_id": *"\([^"]*\)".*/\1/p' __CONF__ 2>/dev/null)"
