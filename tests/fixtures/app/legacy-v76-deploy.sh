#!/bin/sh
# Written by komizo. Edits are lost the next time the app is set up.
set -eu
# No pathname expansion. Several loops below iterate $hostnames (whitespace-
# separated, straight from the config image), and a hostname of "*" or "*.prev"
# would otherwise glob into the files in this directory and be published as bogus
# routes -- slipping past the wildcard check, which never sees a literal "*".
# Re-enabled only around the one place a glob is intended (the state-file scan).
set -f

CONFIG_IMAGE="__CONFIG_IMAGE__"
PROXY_CONTAINER="__PROXY_CONTAINER__"
PROXY_DIR="__PROXY_DIR__"

# Baked in rather than derived. The app's name decides the upstream the shared
# proxy is pointed at (<app>-gate), and its directory is where the hostnames
# it has claimed are recorded -- both are read below, so both have to be values
# this script carries rather than things it works out.
APP_NAME="__APP_NAME__"
APP_DIR="__APP_DIR__"
ROUTE_FILE="__ROUTES_DIR__/__APP_NAME__.caddy"
SCOPED_ENV="__SCOPED_ENV__"
WORKLOAD_POLICY="/etc/komizo/workloads/__APP_NAME__.json"

# Root policy opts this installed app into the durable typed transaction. Once
# enabled, a submission failure is terminal; it never falls back to shell
# staging. The compatibility transaction below remains for older installations.
if komizo-box workload deployment-enabled --policy "$WORKLOAD_POLICY" 2>/dev/null; then
	if [ "$SCOPED_ENV" = "fields-postgres-v2" ]; then
		[ "$#" -eq 4 ] || { echo "deploy: scoped generation missing" >&2; exit 1; }
	elif [ "$#" -ne 1 ] && [ "$#" -ne 3 ]; then
		echo "deploy: unexpected arguments" >&2
		exit 1
	fi
	submission=$(komizo-box workload deployment-submit --policy "$WORKLOAD_POLICY" \
		--version "${1:-}" --registry "${2:-}" --registry-user "${3:-}" --generation "${4:-}") || exit 1
	printf '%s\n' "$submission"
	operation_id=$(printf '%s\n' "$submission" | tail -n 1)
	exec komizo-box workload activation-wait --id "$operation_id"
fi

# This app's own record, which is where a DELIBERATE STOP is written down.
#
# The deploy reads it and refuses to start an app somebody stopped -- see the
# start decision near the end of this script for the whole argument. Named here,
# beside the other baked-in values, because the cross-app hostname scan below
# already reaches into __STATE_DIR__ and two spellings of the same directory in
# one script is one of them going stale.
#
# A FILE, deliberately, and not a question asked of komizo. appify.md §2 is
# explicit that a deploy must not depend on anything off the box: a deploy that
# has to consult a service to find out whether it may start the app is a deploy
# that fails when the service is down.
STATE_FILE="__STATE_DIR__/__APP_NAME__.env"

# Metadata, file type, owner, and mode, plus the nonsecret provenance marker
# written only by v2 provision. Env files are not opened, so a deploy log
# cannot carry a credential. A missing or escaping current link fails before
# compose.yml is swapped: the running stack is still the previous one.
komizo_scoped_env_ready() {
	recorded=$(sed -n 's/^APP_DIR=//p' "$STATE_FILE" | tr -d '\r' | head -n 1)
	if [ "$recorded" != "$APP_DIR" ]; then
		echo "deploy: refusing: app record APP_DIR does not match this deploy script" >&2
		return 1
	fi
	secrets="$APP_DIR/secrets"
	if [ -L "$secrets" ] || [ ! -d "$secrets" ]; then
		echo "deploy: refusing: scoped env is not staged (secrets is missing or a symlink)" >&2
		return 1
	fi
	if [ ! -L "$secrets/current" ]; then
		echo "deploy: refusing: scoped env current link is missing" >&2
		return 1
	fi
	target=$(readlink "$secrets/current") || {
		echo "deploy: refusing: cannot read scoped env current link" >&2
		return 1
	}
	case "$target" in
		generations/[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
		*)
			echo "deploy: refusing: scoped env current link is not a confined generation" >&2
			return 1
			;;
	esac
	id=${target#generations/}
	gdir="$secrets/generations/$id"
	if [ -L "$gdir" ] || [ ! -d "$gdir" ]; then
		echo "deploy: refusing: scoped env generation is missing or a symlink" >&2
		return 1
	fi
	for f in postgres.env migrate.env api.env godot-api.env; do
		p="$gdir/$f"
		if [ -L "$p" ] || [ ! -f "$p" ]; then
			echo "deploy: refusing: scoped env file $f is missing or a symlink" >&2
			return 1
		fi
		mode=$(stat -c %a "$p" 2>/dev/null || true)
		owner=$(stat -c %u "$p" 2>/dev/null || true)
		if [ "$mode" != "600" ] || [ "$owner" != "0" ]; then
			echo "deploy: refusing: scoped env file $f is not root-owned mode 600" >&2
			return 1
		fi
	done
	if [ "$id" != "${expected_generation:-}" ]; then
		echo "deploy: refusing: scoped generation mismatch" >&2
		return 1
	fi
	recorded_gen=$(sed -n 's/^SCOPED_GENERATION=//p' "$STATE_FILE" | tr -d '\r' | head -n 1)
	if [ "$recorded_gen" != "$id" ]; then
		echo "deploy: refusing: scoped generation mismatch" >&2
		return 1
	fi
	marker="$gdir/provenance"
	if [ -L "$marker" ] || [ ! -f "$marker" ]; then
		echo "deploy: refusing: scoped env is not a fields-postgres-v2 generation" >&2
		return 1
	fi
	mode=$(stat -c %a "$marker" 2>/dev/null || true)
	owner=$(stat -c %u "$marker" 2>/dev/null || true)
	if [ "$mode" != "400" ] || [ "$owner" != "0" ]; then
		echo "deploy: refusing: scoped env file provenance is not root-owned mode 400" >&2
		return 1
	fi
	size=$(stat -c %s "$marker" 2>/dev/null || true)
	expected_size=$(printf 'profile=fields-postgres-v2\nschema=11\ngeneration=%s\n' "$id" | wc -c | tr -d '[:space:]')
	match=0
	if [ "$size" = "$expected_size" ]; then
		printf 'profile=fields-postgres-v2\nschema=11\ngeneration=%s\n' "$id" | cmp -s - "$marker" || match=$?
	else
		match=1
	fi
	if [ "$match" -ne 0 ]; then
		echo "deploy: refusing: scoped env is not a fields-postgres-v2 generation" >&2
		return 1
	fi
	return 0
}


# Operator-written host-wide floors. Komizo never creates this file. Empty or
# missing keys mean no floor: deploys fail-open with a warning rather than
# inventing a production SLO here. CI only reaches deploy-APP, so the operator
# writes this on the box as root.
FLOORS_FILE="/etc/komizo/deploy-floors"
REPORT_JSON="/run/komizo/report.json"

# Numbers from compact encoding/json output. No jq on the box. Brace-matched so
# a nested swap object inside mem does not clip available. BusyBox awk %d is
# 32-bit, so large byte counts are printed with %.0f (exact to 2^53).
json_mem_available() {
	awk '
	{
		buf = buf $0
	}
	END {
		gsub(/[ \t\n\r]/, "", buf)
		pat = "\"mem\":{"
		i = index(buf, pat)
		if (i == 0) exit
		rest = substr(buf, i + length(pat) - 1)
		depth = 0
		obj = ""
		n = length(rest)
		for (k = 1; k <= n; k++) {
			c = substr(rest, k, 1)
			obj = obj c
			if (c == "{") depth++
			if (c == "}") {
				depth--
				if (depth == 0) break
			}
		}
		i = index(obj, "\"available\":")
		if (i == 0) exit
		rest = substr(obj, i + 12)
		if (match(rest, /^[0-9]+/)) printf "%.0f\n", substr(rest, RSTART, RLENGTH) + 0
	}' "$1" 2>/dev/null || true
}

json_disk_available() {
	awk '
	{
		buf = buf $0
	}
	END {
		gsub(/[ \t\n\r]/, "", buf)
		i = index(buf, "\"disks\":[")
		if (i == 0) exit
		rest = substr(buf, i + 9)
		depth = 0
		arr = ""
		n = length(rest)
		for (k = 1; k <= n; k++) {
			c = substr(rest, k, 1)
			arr = arr c
			if (c == "[") depth++
			if (c == "]") {
				depth--
				if (depth == 0) break
			}
		}
		have = 0
		minv = 0
		s = arr
		while ((j = index(s, "\"available\":")) > 0) {
			s = substr(s, j + 12)
			if (!match(s, /^[0-9]+/)) break
			v = substr(s, RSTART, RLENGTH) + 0
			if (!have || v < minv) minv = v
			have = 1
			s = substr(s, RLENGTH + 1)
		}
		if (have) printf "%.0f\n", minv
	}' "$1" 2>/dev/null || true
}

# True when A < B. BusyBox [ ] is 32-bit signed; disk bytes are not.
below_bytes() {
	awk -v a="$1" -v b="$2" 'BEGIN { exit (a + 0 < b + 0) ? 0 : 1 }'
}

version="${1:-}"
registry="${2:-}"
registry_user="${3:-}"
cd "$APP_DIR"

# Clean up scratch however this exits. Several validation failures below exit
# without reaching an explicit cleanup, and each would otherwise leave a
# root-owned copy of the config image -- or the per-run registry credentials --
# behind in /tmp.
#
# The .env backup is in here for the same reason. It is removed on both the
# success and the failure path below, but a kill between writing it and reaching
# either would leave a copy of this app's environment sitting in its directory
# until something happened to overwrite it.
staging=""
release_dir=""
journal_started=0
journal_finished=0
#
# AND IT STOPS, rather than only tidying. A handler for a non-EXIT signal in
# POSIX sh RESUMES at the interruption point when it returns, so `EXIT INT TERM`
# cleaned up and then carried on deploying a box whose operator had just
# cancelled -- the same defect Review 2 found in the doas and sshd windows
# below, in a third place nobody had looked. HUP and PIPE were absent entirely,
# which are precisely how a dropped SSH connection arrives: the tidy-up did not
# run at all on the two signals most likely to fire, leaving the registry
# credential in /tmp and a copy of the app's environment beside it.
#
# `exit` from a handler runs the EXIT trap too, so the cleanup is written once.
cleanup_staging() {
	if [ "$journal_started" = 1 ] && [ "$journal_finished" = 0 ]; then
		komizo-box workload operation --policy "$WORKLOAD_POLICY" --version "$version" --previous "$previous" --phase failed >/dev/null 2>&1 || true
	fi
	rm -rf "$staging" "$release_dir" "${DOCKER_CONFIG:-}" 2>/dev/null || true
	rm -f "$APP_DIR/.env.komizo.bak" 2>/dev/null || true
}
trap cleanup_staging EXIT
trap 'cleanup_staging; exit 129' INT TERM HUP PIPE

# Tags and SHAs only: letters, digits, dot, underscore, hyphen. Required --
# every deploy names a version, because the config for that version has to be
# fetched before anything can run.
case "$version" in
	*[!A-Za-z0-9._-]*|'')
		echo "deploy: usage: deploy <tag> [<registry> <registry-user>]  (token on stdin)" >&2
		echo "deploy: refusing version '$version'" >&2
		exit 1
		;;
esac

# fields-postgres-v2 always takes four arguments. The generation is not a
# secret and is not read from stdin; stdin remains the registry token, and is
# left unread when the registry arguments are both empty. Any other app stays
# at one or three arguments and rejects a fourth rather than ignoring it.
expected_generation=""
if [ "$SCOPED_ENV" = "fields-postgres-v2" ]; then
	if [ "$#" -ne 4 ]; then
		echo "deploy: refusing: scoped generation missing" >&2
		exit 1
	fi
	expected_generation=$4
	case "$expected_generation" in
		*[!0-9a-f]*|'')
			echo "deploy: refusing: scoped generation malformed" >&2
			exit 1
			;;
	esac
	if [ "${#expected_generation}" -ne 32 ]; then
		echo "deploy: refusing: scoped generation malformed" >&2
		exit 1
	fi
	if [ -z "$registry" ] && [ -n "$registry_user" ]; then
		echo "deploy: refusing: registry user set without registry" >&2
		exit 1
	fi
	if [ -n "$registry" ] && [ -z "$registry_user" ]; then
		echo "deploy: refusing registry user '$registry_user'" >&2
		exit 1
	fi
elif [ "$#" -ne 1 ] && [ "$#" -ne 3 ]; then
	echo "deploy: usage: deploy <tag> [<registry> <registry-user>]  (token on stdin)" >&2
	echo "deploy: refusing: unexpected arguments" >&2
	exit 1
fi

# One deploy of this app at a time.
#
# Two runs of the same app interleave their compose.yml swaps and their .env
# writes, and the loser wins on some files and loses on others -- a stack
# running one commit's containers against another commit's config, from two
# green pipelines. The wait is bounded so a stuck deploy fails the second run
# with a message rather than hanging CI until it times out.
#
# Both locks are mandatory. A host operation serializes pulls, Compose startup
# and pruning across products; the app lock also coordinates scoped secrets.
komizo-box workload activation-idle
komizo_lock="/run/komizo/deploy-__APP_NAME__.lock"
command -v flock >/dev/null 2>&1 || { echo "deploy: refusing: locking unavailable" >&2; exit 1; }
mkdir -p /run/komizo || { echo "deploy: refusing: lock directory unavailable" >&2; exit 1; }
exec 9>"$komizo_lock"
flock -w 300 9 || { echo "deploy: refusing: app lock busy" >&2; exit 1; }
exec 6>/run/komizo/operation.lock
flock -w 300 6 || { echo "deploy: refusing: host operation busy" >&2; exit 1; }
komizo-box workload activation-idle

# Resource floors, if the operator set any. Until they do, fail-open with a
# loud warning that prints the reported available bytes. No sample sizes are
# encoded as defaults. If floors exist and report.json is missing, unreadable,
# or lacks the available fields those floors need, refuse-closed -- before
# pulling images or composing up.
disk_floor=""
mem_floor=""
if [ -e "$FLOORS_FILE" ]; then
	if [ ! -f "$FLOORS_FILE" ] || [ ! -r "$FLOORS_FILE" ]; then
		echo "deploy: refusing: cannot read $FLOORS_FILE" >&2
		exit 1
	fi
	disk_floor="$(sed -n 's/^DISK_AVAILABLE_FLOOR_BYTES=//p' "$FLOORS_FILE" | tr -d '\r \t' | head -n 1)"
	mem_floor="$(sed -n 's/^MEM_AVAILABLE_FLOOR_BYTES=//p' "$FLOORS_FILE" | tr -d '\r \t' | head -n 1)"
	case "$disk_floor" in
		''|*[!0-9]*)
			if [ -n "$disk_floor" ]; then
				echo "deploy: refusing: $FLOORS_FILE has a non-numeric DISK_AVAILABLE_FLOOR_BYTES" >&2
				exit 1
			fi
			;;
	esac
	case "$mem_floor" in
		''|*[!0-9]*)
			if [ -n "$mem_floor" ]; then
				echo "deploy: refusing: $FLOORS_FILE has a non-numeric MEM_AVAILABLE_FLOOR_BYTES" >&2
				exit 1
			fi
			;;
	esac
fi
mem_avail=""
disk_avail=""
if [ -f "$REPORT_JSON" ] && [ -r "$REPORT_JSON" ]; then
	mem_avail="$(json_mem_available "$REPORT_JSON")"
	disk_avail="$(json_disk_available "$REPORT_JSON")"
fi
if [ -n "$disk_floor" ] || [ -n "$mem_floor" ]; then
	if [ ! -f "$REPORT_JSON" ] || [ ! -r "$REPORT_JSON" ]; then
		echo "deploy: refusing: $FLOORS_FILE sets floors but $REPORT_JSON is missing or unreadable" >&2
		exit 1
	fi
	if [ -n "$mem_floor" ] && [ -z "$mem_avail" ]; then
		echo "deploy: refusing: $FLOORS_FILE sets floors but $REPORT_JSON lacks available fields" >&2
		exit 1
	fi
	if [ -n "$disk_floor" ] && [ -z "$disk_avail" ]; then
		echo "deploy: refusing: $FLOORS_FILE sets floors but $REPORT_JSON lacks available fields" >&2
		exit 1
	fi
	komizo-box workload capacity --report "$REPORT_JSON" || { echo "deploy: refusing: stale capacity report" >&2; exit 1; }
	if [ -n "$mem_floor" ] && below_bytes "$mem_avail" "$mem_floor"; then
		echo "deploy: refusing: mem available ${mem_avail} bytes is below floor ${mem_floor} bytes" >&2
		exit 1
	fi
	if [ -n "$disk_floor" ] && below_bytes "$disk_avail" "$disk_floor"; then
		echo "deploy: refusing: disk available ${disk_avail} bytes is below floor ${disk_floor} bytes" >&2
		exit 1
	fi
	# Past the floor is not the same as comfortable. Between 1x and 2x the
	# floor the deploy proceeds, but loudly: tonight's disk died between one
	# deploy and the next, and a box drifting toward the line should be
	# audible in the log before it is over it. Doubled with awk for the same
	# reason below_bytes exists -- BusyBox [ ] is 32-bit signed; bytes are not.
	if [ -n "$mem_floor" ] && below_bytes "$mem_avail" "$(awk -v f="$mem_floor" 'BEGIN{printf "%.0f", f*2}')"; then
		echo "deploy: WARNING -- mem available ${mem_avail} bytes is below twice the floor ${mem_floor} bytes" >&2
	fi
	if [ -n "$disk_floor" ] && below_bytes "$disk_avail" "$(awk -v f="$disk_floor" 'BEGIN{printf "%.0f", f*2}')"; then
		echo "deploy: WARNING -- disk available ${disk_avail} bytes is below twice the floor ${disk_floor} bytes" >&2
	fi
else
	echo "deploy: WARNING -- no operator resource floors configured ($FLOORS_FILE absent or keys empty); deploying anyway" >&2
	echo "deploy: WARNING -- reported available bytes: mem=${mem_avail:-unknown} disk=${disk_avail:-unknown}" >&2
fi

release_wire=""
# Registry authentication happens HERE, as root, and not over the deploy user's
# SSH session. It has to: this script pulls as root, so a 'docker login' run as
# the deploy user would write to that user's home instead and the pull below
# would still be anonymous -- which fails only on a private registry, and looks
# like a broken image reference.
#
# Into a config directory of this run's own, rather than root's shared
# ~/.docker/config.json. Two apps deploying at once would otherwise log each
# other out through the same file -- and credentials that outlive the deploy
# are credentials sitting on the box.
#
# The token arrives on STDIN, never as an argument: arguments are visible in the
# host's process list to every other user on the box.
if [ -n "$registry" ]; then
	case "$registry" in
		*[!A-Za-z0-9.:_-]*)
			echo "deploy: refusing registry '$registry'" >&2
			exit 1
			;;
	esac
	# GitHub's workflow actor is this literal bot after an automated merge.
	# Other bracketed or shell-special usernames remain invalid.
	case "$registry_user" in
		'github-actions[bot]') ;;
		''|*[!A-Za-z0-9._@-]*)
			echo "deploy: refusing registry user '$registry_user'" >&2
			exit 1
			;;
	esac
	DOCKER_CONFIG="$(mktemp -d)"
	export DOCKER_CONFIG
	# Credentials must not outlive the deploy; the EXIT trap set above drops both
	# this directory and the staging dir however we leave.
	registry_password=""
	IFS= read -r registry_password || true
	release_wire=$(head -c 131073)
	if ! printf '%s' "$registry_password" | docker login "$registry" -u "$registry_user" --password-stdin >/dev/null; then
		echo "deploy: could not authenticate to $registry as $registry_user" >&2
		exit 1
	fi
	echo "deploy: authenticated to $registry as $registry_user"
fi

# Reported because the CI user cannot read .env itself (600 root) and has no
# other way to learn what it is replacing. Printed before anything changes, so
# it is still correct if a later step fails -- which is exactly when a caller
# wants it, to roll back to. Machine-readable on purpose: the activate action
# parses this line.
previous="$(sed -n 's/^APP_VERSION=//p' .env 2>/dev/null | head -n 1)"
echo "deploy: previous-version=${previous:-}"
release_dir=$(mktemp -d)
if ! printf '%s' "$release_wire" | komizo-box workload release-admit --policy "$WORKLOAD_POLICY" --version "$version" --output "$release_dir/accepted.json"; then
	echo "deploy: refusing: host release verification failed" >&2
	exit 1
fi
komizo-box workload operation --policy "$WORKLOAD_POLICY" --version "$version" --previous "$previous" --phase admitted
journal_started=1

ref="$CONFIG_IMAGE:$version"
echo "deploy: fetching config from $ref"
docker pull -q "$ref" >/dev/null

# 'docker create' + 'docker cp' rather than 'docker run': the config image
# is FROM scratch and has no shell to run anything with.
#
# --entrypoint is required, not cosmetic: 'docker create' refuses an image
# with no command at all, which a bare scratch image has. The container is
# only ever created and copied out of, never started, so the value is
# irrelevant -- it just has to be present.
staging="$(mktemp -d)"
cid="$(docker create --entrypoint /nonexistent "$ref")"
docker cp "$cid:/config/." "$staging/" >/dev/null
docker rm -v "$cid" >/dev/null

if [ ! -f "$staging/compose.yml" ]; then
	echo "deploy: $ref has no /config/compose.yml" >&2
	exit 1
fi

# A config image is data, not a way to make root read the host. `docker cp`
# preserves symlinks, and the cat/sed below would follow one out of the staging
# dir into an arbitrary host file. Refuse symlinks for the two files consumed.
if [ -L "$staging/compose.yml" ]; then
	echo "deploy: compose.yml in $ref is a symlink, which is not allowed" >&2
	exit 1
fi
if [ -L "$staging/hostnames" ]; then
	echo "deploy: hostnames in $ref is a symlink, which is not allowed" >&2
	exit 1
fi

# Parse and restrict untrusted YAML before Compose can read an env_file,
# include, provider or external configuration. Only canonical, host-approved
# JSON reaches Compose; validation failure leaves all installed files alone.
if ! komizo-box workload validate --policy "$WORKLOAD_POLICY" \
	--app "$APP_NAME" --app-dir "$APP_DIR" --version "$version" \
	--compose "$staging/compose.yml" --output "$staging/approved.json"; then
	echo "deploy: refusing: host workload policy" >&2
	exit 1
fi
if ! komizo-box workload release-bind --policy "$WORKLOAD_POLICY" --version "$version" --config-image "$ref" \
	--release "$release_dir/accepted.json" --compose "$staging/approved.json" --output "$staging/bound.json"; then
	echo "deploy: refusing: image identity differs from the authenticated release" >&2
	exit 1
fi
mv "$staging/bound.json" "$staging/compose.yml"

# The hostnames this app claims, one per line. This is the whole of what the
# app tells the reverse proxy: komizo writes the routes itself, so an app can
# no longer author server config, and no app's mistake can be another app's
# outage.
#
# Optional. An app with no hostnames publishes nothing and is reachable only
# from inside its own network -- a worker, a cron job, a queue consumer.
#
# A line may name where the hostname goes -- "api.example.com -> api" -- which
# is metadata for the interface and NOTHING ELSE. Routing reads the first field
# and ignores the rest, so the shared proxy is still pointed at <app>-gate
# whatever the arrow says: a wrong annotation mislabels a chart, it cannot
# misroute a request. The app is the only thing that knows which of its
# containers serves a name, and this is the only way it can say so without
# shipping config the server loads.
hostnames=""
hostmap=""
if [ -f "$staging/hostnames" ]; then
	hostmap="$(sed 's/#.*//' "$staging/hostnames" | tr -d '\r' | awk 'NF { print }')"
	hostnames="$(printf '%s\n' "$hostmap" | awk '{ print $1 }' | sed '/^$/d')"
fi

# Swap everything in, then validate. A broken config must not be left behind
# on a box that was working, so keep backups and put them back if a check
# fails -- including the reverse-proxy route, which is why this is a function
# rather than three copies of the same three lines.
#
# It puts FILES back and starts nothing, which is why every failure path below
# says "reverted, nothing restarted" and means it. That is now load-bearing
# rather than incidental: the start decision at the end of this script is the
# ONE place containers come up, and it is the one place that consults the stop
# marker. A failure path that grew a `docker compose up` to put the previous
# version back would become a second way to start an app somebody stopped, and
# the worse one to find -- it runs only when something else has already gone
# wrong, which is not when anybody is reading the log for this. If one is ever
# added, it has to read the marker the same way.
revert() {
	cat compose.yml.prev > compose.yml
	rm -f "$ROUTE_FILE"
	[ -f "$ROUTE_FILE.prev" ] && mv "$ROUTE_FILE.prev" "$ROUTE_FILE"
	rm -f hostnames
	[ -f hostnames.prev ] && mv hostnames.prev hostnames
	rm -f compose.yml.prev
	return 0
}

if [ "$SCOPED_ENV" = "fields-postgres-v2" ]; then
	# Once, under the lock taken above, immediately before the first app-config
	# mutation. The config image is still only in the staging directory.
	if ! /usr/local/bin/provision-scoped-env-$APP_NAME --check-compose "$staging/compose.yml"; then
		echo "deploy: refusing: scoped compose map" >&2
		exit 1
	fi
	komizo_scoped_env_ready || exit 1
	echo "deploy: scoped-generation=$expected_generation"
fi
cp compose.yml compose.yml.prev
rm -f "$ROUTE_FILE.prev"
[ -f "$ROUTE_FILE" ] && cp -a "$ROUTE_FILE" "$ROUTE_FILE.prev"
rm -f hostnames.prev
[ -f hostnames ] && cp -a hostnames hostnames.prev

cat "$staging/compose.yml" > compose.yml

# The reverse-proxy route, WRITTEN BY KOMIZO from the hostnames above.
#
# The app used to ship Caddy config and this script concatenated it into a file
# the shared proxy imported. That made every app on the box an author of one
# config loaded by one process: a syntax error anywhere failed the combined
# validate for everyone, and Caddy accepts exactly one global options block, so
# the second app to want one broke the first.
#
# Now the app declares names and nothing else. Everything a request meets after
# the hostname match is inside the app, in its own gate container.
#
# Replaced wholesale rather than merged: a hostname the app has stopped
# publishing must disappear, and the config image is the whole truth about this
# version.
rm -f "$ROUTE_FILE"
rm -f hostnames

if [ -n "$hostnames" ]; then
	# The SHAPE of each line, before any of it is believed.
	#
	# A line is a hostname, optionally followed by "-> <container>". Nothing
	# else. The routing itself only ever reads the first word, which means a
	# line of prose -- or a name with a stray space in it -- had its first word
	# quietly published as a hostname and the rest dropped. The CI action
	# rejects those; the host, which is the side that has to be right, did not.
	# A line is a name, optionally the container that serves it, optionally how
	# its certificate is obtained:
	#
	#   example.com
	#   api.example.com        -> api
	#   *.preview.example.com  -> api  on-demand
	#   *.preview.example.com         on-demand
	#
	# The mode is last so the arrow reads the way it did before, and so a file
	# written without one is still valid -- which is every file written so far.
	bad_line="$(printf '%s\n' "$hostmap" | awk '
		function mode(m) { return m == "on-demand" || m == "dns" || m == "passthrough" }
		NF == 0 { next }
		NF == 1 { next }
		NF == 2 && mode($2) { next }
		NF == 3 && $2 == "->" && $3 ~ /^[A-Za-z0-9_-]+$/ { next }
		NF == 4 && $2 == "->" && $3 ~ /^[A-Za-z0-9_-]+$/ && mode($4) { next }
		{ print; exit }')"
	if [ -n "$bad_line" ]; then
		revert
		echo "deploy: '$bad_line' is not a hostname, optionally '-> <container>', optionally one of: on-demand dns passthrough" >&2
		exit 1
	fi

	# Modes komizo accepts in a file but cannot yet serve. Refused here rather
	# than ignored: silently falling back to on-demand would hand a name the
	# certificate strategy it asked NOT to have, and the reason to ask is
	# usually that the other one is wrong for it. See docs/tls-design.md.
	unsupported="$(printf '%s\n' "$hostmap" | awk '
		{ for (i = 2; i <= NF; i++) if ($i == "dns" || $i == "passthrough") { print $1 " " $i; exit } }')"
	if [ -n "$unsupported" ]; then
		revert
		echo "deploy: $unsupported is not supported yet -- komizo only obtains certificates on demand. See docs/tls-design.md" >&2
		exit 1
	fi

	# Validated before it is written, because these land in a config the whole
	# box loads. Charset first, then shape: a leading '*.' is the only wildcard
	# Caddy takes, and anything else with a '*' in it would adapt to something
	# nobody meant.
	for h in $hostnames; do
		case "$h" in
			*[!A-Za-z0-9.*-]*)
				revert
				echo "deploy: '$h' is not a valid hostname (letters, digits, dot, hyphen, and a leading '*.')" >&2
				exit 1 ;;
		esac
		case "$h" in
			\*.*)
				case "${h#\*.}" in
					*\**)
						revert
						echo "deploy: '$h' has more than one wildcard; Caddy takes at most a leading '*.'" >&2
						exit 1 ;;
				esac ;;
			*\**)
				revert
				echo "deploy: '$h' puts a wildcard somewhere Caddy will not take one; only a leading '*.' works" >&2
				exit 1 ;;
		esac
	done

	# A hostname claimed twice on one box is two site blocks for one name, which
	# Caddy rejects outright -- so it would take down every app, not just the
	# two arguing. Caught here, against what the other apps have already
	# published, so the deploy that would cause it is the deploy that fails.
	#
	# Compared on the FIRST FIELD of each line, not the whole line: a recorded
	# hostname may carry an annotation ("api.example.com -> api"), and a
	# whole-line match silently misses every one that does -- which let the
	# duplicate through to fail later as an unexplained "routes do not load".
	#
	# The apps are enumerated from komizo's own records rather than by globbing
	# /srv, because an app is not required to live there: --app-dir puts it
	# anywhere, and such an app was neither checked against nor checked.
	# Held across the check AND the claim, box-wide.
	#
	# The deploy lock above is per-app, deliberately, so two different apps still
	# deploy at once -- they share nothing but the daemon. This one is the
	# exception: checking whether a hostname is taken and then taking it is a
	# read-then-write over state every app on the box shares, and two apps
	# claiming the same name at the same moment both passed the check. Neither
	# was told what had happened; they wrote their routes, and whichever ran
	# `caddy validate` second failed with "the routes generated from X do not
	# load" -- or, on the other interleaving, the FIRST app failed for a conflict
	# the second one caused. The good message this check exists to produce is the
	# one that got skipped.
	#
	# A short critical section, not the whole deploy: it is a scan of a few small
	# files and one write, so this costs concurrent deploys nothing measurable
	# while making the claim atomic.
	#
	# Skipped wherever the lock cannot be taken, exactly as the deploy lock is --
	# a busybox without the flock applet, or a /run this cannot write. Refusing
	# to deploy would trade a rare bad error message for a certain outage.
	claim_lock="/run/komizo/hostnames.lock"
	claimed_lock=0
	if command -v flock >/dev/null 2>&1 &&
		mkdir -p /run/komizo 2>/dev/null &&
		: > "$claim_lock" 2>/dev/null
	then
		exec 8>"$claim_lock"
		if flock -w 60 8; then
			claimed_lock=1
		else
			echo "deploy: waited 60s for another app to finish claiming hostnames" >&2
			revert
			exit 1
		fi
	fi

	for h in $hostnames; do
		# Pathname expansion is off (set -f) so $hostnames cannot glob; restore it
		# just for this scan of the other apps' state files, then turn it back off.
		set +f
		for _st in __STATE_DIR__/*.env; do
			[ -f "$_st" ] || continue
			_other="${_st##*/}"; _other="${_other%.env}"
			[ "$_other" != "$APP_NAME" ] || continue
			_odir="$(sed -n 's/^APP_DIR=//p' "$_st" | head -n 1)"
			[ -n "$_odir" ] || continue
			[ -f "$_odir/hostnames" ] || continue
			if awk '{ print $1 }' "$_odir/hostnames" 2>/dev/null | grep -qxF "$h"; then
				set -f
				if [ "$claimed_lock" = 1 ]; then exec 8>&-; fi
				revert
				echo "deploy: '$h' is already claimed by $_other" >&2
				exit 1
			fi
		done
		set -f
	done

	# Recorded WITH annotations: the interface reads this file to attribute
	# requests, and the arrows are the only place that mapping exists.
	#
	# This write is the claim, which is why the lock spans it: another app's scan
	# above reads exactly this file.
	printf '%s\n' "$hostmap" > hostnames
	if [ "$claimed_lock" = 1 ]; then exec 8>&-; fi

	# Wildcards get their OWN site block, because `tls { on_demand }` applies to
	# every name in the block it sits in. Folded together with the concrete
	# names, one wildcard would put the whole app behind the certificate gate --
	# and the gate exists to approve preview hostnames, so it says no to the
	# app's own front page. That failed as a TLS handshake error on names that
	# had worked for months, which is a long way from the cause.
	plain=""
	wild=""
	for h in $hostnames; do
		case "$h" in
			\*.*) [ -n "$wild" ] && wild="$wild, "; wild="$wild$h" ;;
			*) [ -n "$plain" ] && plain="$plain, "; plain="$plain$h" ;;
		esac
	done

	# A wildcard needs on-demand TLS, and on-demand TLS with no approval gate is a
	# remote denial of service: anyone can open TLS connections with random SNIs
	# and make the box attempt a certificate per name, exhausting its shared ACME
	# rate limit and breaking renewal for every real certificate on it. Refuse
	# rather than ship it -- the same "fail loudly" rule as dns/passthrough above.
	if [ -n "$wild" ] && ! grep -q 'ask ' "$PROXY_DIR/Caddyfile" 2>/dev/null; then
		revert
		echo "deploy: '$wild' is a wildcard, which needs on-demand TLS with an approval gate." >&2
		echo "deploy: the proxy has no gate configured, so this would let anyone exhaust the box's certificate rate limit." >&2
		echo "deploy: configure one with 'komizo proxy --tls-ask <url>' first. See docs/tls-design.md" >&2
		exit 1
	fi

	# Access logging, emitted into every site block this generates.
	#
	# Per-site because these ARE the only site blocks on the box -- Caddy has no
	# server-wide access log, and the shared Caddyfile has nothing but imports.
	#
	# To a FILE, not stdout. The proxy's stdout is what 'l' shows on its row,
	# and it is the only place a certificate or TLS failure is explained;
	# folding every request into it would cost that for a feature nobody had
	# asked for yet. A file also rotates itself and can be totalled by reading
	# it, rather than by asking docker for a stream.
	#
	# One file for the whole box rather than one per app: Caddy opens it once
	# and the aggregate names the app on every line anyway, via the hostname.
	access_log() {
		printf '\tlog {\n'
		printf '\t\toutput file /var/log/caddy/access.log {\n'
		printf '\t\t\troll_size 10mb\n'
		printf '\t\t\troll_keep 3\n'
		printf '\t\t}\n'
		printf '\t\tformat json\n'
		printf '\t}\n'
	}

	# The upstream is derived from the app name rather than declared, so it
	# cannot collide with another app's and cannot be pointed at one.
	{
		printf '# Written by komizo from %s.\n' "$ref"
		printf '# Edits here are lost on the next deploy.\n'
		# HSTS on every site (komizo terminates TLS and redirects HTTP->HTTPS, so
		# the header is always accurate), and the X-Forwarded-For handed upstream is
		# RESET to the direct client rather than appended to: Caddy otherwise keeps
		# a client-supplied value as the first entry, which is the one an app reads
		# for allowlisting and rate limiting -- i.e. a spoofable one.
		site() {
			printf '\theader Strict-Transport-Security "max-age=31536000"\n'
			printf '\theader >X-Komizo-Revision "%s"\n' "$version"
			access_log
			printf '\treverse_proxy %s-gate:80 {\n' "$APP_NAME"
			printf '\t\theader_up X-Forwarded-For {remote_host}\n'
			printf '\t}\n'
		}
		if [ -n "$plain" ]; then
			printf '%s {\n' "$plain"
			site
			printf '}\n'
		fi
		if [ -n "$wild" ]; then
			[ -n "$plain" ] && printf '\n'
			# A wildcard cannot get an ordinary certificate, so on-demand is the
			# only thing that works for one. It needs the ask endpoint the
			# server is configured with -- see 'komizo proxy --tls-ask'.
			printf '%s {\n' "$wild"
			printf '\ttls {\n\t\ton_demand\n\t}\n'
			site
			printf '}\n'
		fi
	} > "$ROUTE_FILE"
	chown root:root "$ROUTE_FILE"
	chmod 644 "$ROUTE_FILE"
fi
[ -f hostnames ] && { chown root:root hostnames; chmod 644 hostnames; }

rm -rf "$staging"

# APP_VERSION is passed in rather than read from .env: the file is only
# updated once this check passes, so without it compose would validate the
# new file against the previous version and warn about an unset variable.
if ! APP_VERSION="$version" docker compose config -q; then
	revert
	echo "deploy: compose.yml from $ref is not valid -- reverted, nothing restarted" >&2
	exit 1
fi

# An app that publishes routes needs somewhere to publish them TO. Without this
# the route would land on disk, nothing would read it, and the deploy would
# report success -- a green pipeline and a dead domain, with nothing in the log
# saying why. Every other silent failure this script guards against is treated
# the same way.
#
# An app with no route is unaffected: a worker or a cron job is not meant to
# be reachable, and a box with no proxy can still run one.
proxy_up=0
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$PROXY_CONTAINER"; then
	proxy_up=1
fi
ingress_network="$(komizo-box workload ingress-name --policy "$WORKLOAD_POLICY")"
if [ "$proxy_up" = 1 ] && [ "$ingress_network" != "${SHARED_NETWORK:-edge}" ]; then
 if docker network inspect "$ingress_network" >/dev/null 2>&1; then
  [ "$(docker network inspect "$ingress_network" --format '{{index .Labels "io.komizo.app"}}')" = "$APP_NAME" ] || die "app ingress has no approved ownership label"
 else
  docker network create --internal --label "io.komizo.app=$APP_NAME" "$ingress_network" >/dev/null
 fi
 if ! docker inspect --format '{{range $name, $cfg := .NetworkSettings.Networks}}{{$name}}{{println}}{{end}}' "$PROXY_CONTAINER" | grep -qxF "$ingress_network"; then
  docker network connect "$ingress_network" "$PROXY_CONTAINER"
 fi
fi

if [ -f "$ROUTE_FILE" ] && [ "$proxy_up" = 0 ]; then
	revert
	echo "deploy: this app publishes routes, but the reverse proxy is not running." >&2
	echo "deploy: nothing would serve them, so this is a failure rather than a no-op." >&2
	echo "deploy: start it with 'komizo proxy --host <this box>'." >&2
	echo "deploy: reverted, nothing restarted" >&2
	exit 1
fi

# Validate BEFORE anything restarts, and validate it the way the proxy will
# actually read it: inside the container, against the whole imported config.
#
# komizo writes this file, so it is not checking the app's syntax any more --
# the app has none to get wrong. What is left is everything about the file that
# depends on its NEIGHBOURS: a hostname two apps both claim, a name that has
# become invalid since it was accepted, a proxy config that drifted. The
# hostname check above catches the common case with a better message; this
# catches the rest, and costs one exec.
if [ "$proxy_up" = 1 ]; then
	if ! caddy_err="$(docker exec "$PROXY_CONTAINER" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1)"; then
		revert
		echo "deploy: the routes generated from $ref do not load -- reverted, nothing restarted" >&2
		printf '%s\n' "$caddy_err" | sed 's/^/  /' >&2
		exit 1
	fi
fi

# The .prev files are deliberately still here. They used to be deleted at this
# point, on the reasoning that everything after it had been validated -- but
# `docker compose pull` comes next and can fail for a reason nothing above can
# see (a tag that exists for the config image but not for an app image). That
# left the box with the NEW compose.yml and the NEW route file on disk, their
# backups already gone, and only .env restored.
#
# The route file is the part that matters. It is valid, it is in the directory
# the shared proxy imports, and while this deploy does not reload Caddy, the
# next deploy of ANY app on the box does -- at which point the hostnames of a
# stack that never started begin resolving to a gate that is not there. A green
# "nothing restarted" and a domain that 502s, with nothing connecting the two.
#
# So they survive until the deploy has actually happened. See the cleanup below.

# Committed only once the config for this version is in place and valid, so a
# deploy that fails earlier leaves the box claiming the version it is actually
# still running. Persisted so a later manual 'docker compose up -d' keeps this
# commit instead of drifting back to :latest.
#
# WRITTEN EVEN WHEN NOTHING IS GOING TO BE STARTED, which is the half of the
# start decision below that is easy to get backwards, so the reasoning is here
# rather than there.
#
# A deploy to a stopped app pulls and commits and does not start. The point of
# doing the first two at all is that the NEXT `komizo start` brings up what was
# deployed: start runs `docker compose up -d`, which reads ${APP_VERSION} out of
# this file to resolve every image, so the version recorded here is the version
# that comes up. Leave it at the old one and the box has silently deployed
# nothing -- it pulled an image, wrote the new compose.yml from the new config
# image, and then pinned it to the previous tag, which is a stack assembled from
# two different commits and no message anywhere saying so.
#
# So a stopped app's recorded version is what was last DEPLOYED to it, not what
# it was last running. That reads oddly in a report next to a stopped app, and
# it is still the honest field: the alternative is a version nobody can act on,
# because the deploy that fetched the config for it has already happened and is
# not going to happen again.
# .env is read by the pull/up below for ${APP_VERSION} substitution, so it has
# to be written first -- but a pull that then fails would leave .env claiming a
# version that never started. Back it up and put it back on failure.
cp .env .env.komizo.bak 2>/dev/null || true
komizo-box workload operation --policy "$WORKLOAD_POLICY" --version "$version" --previous "$previous" --phase configured
if grep -q '^APP_VERSION=' .env; then
	sed -i "s|^APP_VERSION=.*|APP_VERSION=$version|" .env
else
	printf 'APP_VERSION=%s\n' "$version" >> .env
fi

# Pull profile-disabled operational images too. Profiles decide what `up`
# starts, not whether a reviewed release is complete on the host; a later
# allowlisted task must never need registry credentials of its own.
if ! docker compose --profile '*' pull; then
	mv -f .env.komizo.bak .env 2>/dev/null || rm -f .env.komizo.bak
	# The whole config goes back, not just .env: compose.yml, the hostnames
	# record and the generated route are all this version's and none of them
	# was ever served.
	revert
	echo "deploy: 'docker compose pull' failed -- reverted, nothing restarted" >&2
	exit 1
fi
rm -f .env.komizo.bak

# Rootd owns activation after durable submission. Disconnection only stops this
# read-only waiter; the local worker keeps its locks, deadline and journal.
# Mark the shell journal delegated BEFORE submission so a signal arriving after
# the pending file is committed cannot rewrite it out from under rootd.
journal_finished=1
if ! activation_id=$(komizo-box workload activation-submit --policy "$WORKLOAD_POLICY" --version "$version" --previous "$previous" --route "$ROUTE_FILE" --proxy "$PROXY_CONTAINER"); then
	komizo-box workload operation --policy "$WORKLOAD_POLICY" --version "$version" --previous "$previous" --phase failed >/dev/null 2>&1 || true
	exit 1
fi
flock -u 6
exec 6>&-
flock -u 9
exec 9>&-
komizo-box workload activation-wait --id "$activation_id"

