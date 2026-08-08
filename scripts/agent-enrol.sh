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
# __DEVICE_KEYS__ expands to zero or more `--device-key <key>` pairs, each
# shell-quoted where it is rendered. They are PUBLIC keys and carry no secret,
# but they are the list of who may command this box, so they go down the
# connection in this script with everything else rather than on a remote command
# line every account on the machine can read from the process table.
/usr/local/bin/komizo-box enrol --api __API__ --token __TOKEN__ --api-host __API_HOST__ __DEVICE_KEYS__

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

	# The read API, only if this enrolment actually brought a key. A service
	# that offered none leaves a box that reports and does not serve, which is
	# exactly the box komizo had before it could serve at all -- so there is
	# nothing to start and nothing to warn about.
	if grep -q '"registry_key"' __CONF__ 2>/dev/null; then
		rc-update add komizo-api default >/dev/null 2>&1 || true
		rc-service komizo-api restart >/dev/null 2>&1 || rc-service komizo-api start >/dev/null 2>&1 || true
	fi
fi

# The route that makes this box readable from the app.
#
# Only when it has an endpoint: a box addressed by an IP has none, because no
# certificate authority issues for an address and a browser refuses a
# self-signed origin outright for an app's requests.
#
# REFUSED rather than written if an app already claims the name. Two site blocks
# for one hostname is a config Caddy will not load, and this proxy is shared --
# so getting it wrong would take every app on the box down, not just komizo.
#
# AND IT SAYS SO WHEN IT DOES NOT WRITE IT. The guard below used to fail in
# silence, and komizo init ran this step BEFORE installing the proxy -- so on
# every fresh box the directory did not exist yet, the route was skipped, and
# nothing anywhere said a step had not happened. The box came up enrolled,
# reporting, and unreachable at its own name, and the app blamed DNS.
#
# The ordering is fixed in internal/app/init.go. This message is the part that
# would have found it in an afternoon instead of a week, and it stays for the
# next time something arrives here before the proxy does.
API_HOST=__API_HOST__
if [ -n "$API_HOST" ] && [ ! -d /srv/_proxy/routes ]; then
	printf 'warning: the proxy is not installed, so %s was not published.\n' "$API_HOST" >&2
	printf '         Run "komizo proxy", then "komizo enrol", to make this box readable.\n' >&2
fi
if [ -n "$API_HOST" ] && [ -d /srv/_proxy/routes ]; then
	if grep -rlF "$API_HOST" /srv/_proxy/routes 2>/dev/null | grep -qv "_komizo.caddy"; then
		printf 'warning: %s is already served by an app on this box; leaving the proxy alone.\n' "$API_HOST" >&2
		printf '         The app cannot read this server until it has a name of its own.\n' >&2
	else
		log "Publishing $API_HOST"
		cat > /srv/_proxy/routes/_komizo.caddy <<KOMIZO_ROUTE_EOF
# Written by komizo. This box answering for itself -- see komizo-be
# design/registry.md. The upstream is a unix socket, so nothing new listens on
# the network and no port is opened.
$API_HOST {
	# The app is served from another origin, so a browser asks first. It sends
	# Authorization, which is not a simple header, so the preflight is not
	# optional -- without this the request never happens and the console says
	# only that it was blocked.
	@preflight method OPTIONS
	handle @preflight {
		header {
			Access-Control-Allow-Origin "https://app.komizo.dev"
			Access-Control-Allow-Methods "GET, POST, OPTIONS"
			Access-Control-Allow-Headers "Authorization, Content-Type"
			Access-Control-Max-Age "600"
		}
		respond 204
	}

	header {
		# ONE origin, not a wildcard. A wildcard here would let any page on the
		# internet read this server with a token it happened to obtain, and the
		# whole point of the token being short-lived is that it is not the only
		# thing standing there.
		Access-Control-Allow-Origin "https://app.komizo.dev"
		Vary "Origin"
		X-Content-Type-Options "nosniff"
	}

	# LOGGED, and deliberately rather than by omission. This route is reads of
	# somebody's server -- who asked this box for a report, and when. It kept no
	# record of that at all, which is the one question an operator cannot answer
	# any other way.
	#
	# THE REDACTION MATTERS MOST HERE, because every request to this route
	# carries a device token in Authorization. Caddy logs that header as
	# REDACTED by default and the global "log_credentials" option is what turns
	# that off -- so it is not set anywhere, and setting it would write live
	# credentials for this server onto this server.
	log {
		output file /var/log/caddy/access.log {
			roll_size 10mb
			roll_keep 3
		}
		format json
	}

	reverse_proxy unix/__API_SOCKET__
}
KOMIZO_ROUTE_EOF
		chown root:root /srv/_proxy/routes/_komizo.caddy
		chmod 644 /srv/_proxy/routes/_komizo.caddy

		# Validated BEFORE reloading, because this proxy is shared: a config
		# that will not load is every app on the box, not just this route.
		if docker exec komizo-proxy caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then
			docker exec komizo-proxy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 ||
				printf 'warning: the route was written but the proxy did not reload.\n' >&2
		else
			rm -f /srv/_proxy/routes/_komizo.caddy
			printf 'warning: that route would not load, so it was removed and nothing changed.\n' >&2
		fi
	fi
fi

log "Reporting as $(sed -n 's/.*"server_id": *"\([^"]*\)".*/\1/p' __CONF__ 2>/dev/null)"
