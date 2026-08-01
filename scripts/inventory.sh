set -u

__LIB_STATE__

# Whether the server has been set up at all. Everything else here assumes
# docker, so this is reported first and the caller checks it before reading the
# rest -- an uninitialised box is a state to show, not an error.
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
	printf 'server\tready\t%s\n' "$(docker --version 2>/dev/null | head -n 1)"
	# The host's own public keys, for the known_hosts value CI pins. Read here
	# rather than only when adding an app: they belong to the SERVER, every app
	# on the box shares them, and needing them again should not mean re-running
	# setup. Public by definition -- what they need is integrity, not secrecy.
	for f in /etc/ssh/ssh_host_*_key.pub; do
		[ -f "$f" ] || continue
		awk '{ if ($1 ~ /^(ssh-|ecdsa-)/) printf "hostkey\t%s\t%s\n", $1, $2 }' "$f"
	done
elif command -v docker >/dev/null 2>&1; then
	printf 'server\tdocker-stopped\t\n'
else
	printf 'server\tbare\t\n'
fi

# What komizo itself has installed here, as the stamp it wrote at the time.
#
# Read back rather than assumed. The alternative is for the interface to print
# what it WOULD install, which is a fact about the laptop rather than about the
# server -- and would read as up to date on a box that had never been touched.
#
# In the inventory rather than in the probe: the probe is shared with the
# sampler, and the sampler has no business reporting its own version to a log.
if [ -f /var/lib/komizo/version ]; then
	printf 'komizo\t%s\t%s\n' \
		"$(sed -n 1p /var/lib/komizo/version 2>/dev/null)" \
		"$(sed -n 2p /var/lib/komizo/version 2>/dev/null)"
fi

# What the box actually runs, as the distribution names itself. Read rather
# than assumed: komizo installs Alpine, but it is pointed at existing servers
# too, and a page that says "alpine" about a Debian box is wrong in the row
# whose whole job is to state facts.
awk -F= '$1 == "PRETTY_NAME" {
	v = substr($0, index($0, "=") + 1)
	gsub(/^"|"$/, "", v)
	printf "os\t%s\n", v
	exit
}' /etc/os-release 2>/dev/null

__LIB_SYSTEM_PROBE__

# Every container on the box, once, so the per-app loop below can look one up
# without another docker call each time. Read here rather than per app because
# 'docker ps' is the slow part of this script over a slow link, and one call is
# one round of that cost no matter how many apps the box hosts.
#
# .State is the machine-readable word (running, exited); .Status is docker's own
# prose (Up 3 hours), which is what a person actually wants to read.
allc=""
starts=""
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
	allc="$(docker ps -a --no-trunc \
		--format '{{.ID}}	{{.Names}}	{{.State}}	{{.Status}}	{{.Label "com.docker.compose.service"}}	{{.Image}}' \
		2>/dev/null || true)"
	# When each container last started and last stopped, and why -- as
	# timestamps and a number rather than docker's prose.
	#
	# "Up 3 hours" and "Exited (1) 2 minutes ago" cannot be compared, added up,
	# or rendered in one format, and every row on this page shows a duration.
	# An app's uptime is also a question about several containers at once.
	#
	# From inspect rather than ps, because ps offers only .RunningFor (prose)
	# and .CreatedAt (creation, which a restart does not move). One call for the
	# whole box, like the one above.
	ids="$(docker ps -aq --no-trunc 2>/dev/null || true)"
	if [ -n "$ids" ]; then
		# shellcheck disable=SC2086 # deliberate word splitting: one container id per arg
		starts="$(docker inspect $ids \
			--format '{{.Id}}	{{.State.StartedAt}}	{{.State.FinishedAt}}	{{.State.ExitCode}}	{{.State.Pid}}' \
			2>/dev/null || true)"
	fi
fi

# The ports a container is actually listening on.
#
# /proc/<pid>/net/tcp IS that container's network namespace, so this is read
# from the host with no exec, no ss, and no cooperation from the image -- which
# matters because most of these images have no shell tools in them at all.
#
# Observed, not declared. The port used to be parsed out of the app's caddy
# fragment, which said where the proxy DIALLED rather than where the process
# listens; and EXPOSE is inherited from base images, so a Caddy gate
# "exposes" 443 and 2019 it never binds.
#
# State 0A is LISTEN. The address field is hex, and busybox awk has no
# strtonum, so the shell converts. Ports in the ephemeral range are dropped:
# they are a runtime's private business, not something anything dials on
# purpose.
container_ports() {
	_pid="$1"
	[ -n "$_pid" ] && [ "$_pid" != "0" ] || return 0
	_out=""
	# shellcheck disable=SC2013 # these are single hex fields, never lines with spaces
	for _h in $(awk '$4 == "0A" { split($2, a, ":"); print a[2] }' \
		"/proc/$_pid/net/tcp" "/proc/$_pid/net/tcp6" 2>/dev/null | sort -u); do
		# clamp-ok: a TCP port, converted from the hex /proc gives. Ports are
		# 16-bit, so this cannot pass 65535 let alone 2^31.
		_p=$(printf '%d' "0x$_h" 2>/dev/null) || continue
		[ "$_p" -ge 32768 ] && [ "$_p" -le 60999 ] && continue
		_out="$_out$_p
"
	done
	printf '%s' "$_out" | sort -un | tr '\n' ',' | sed 's/,$//'
}

for state in /var/lib/komizo/apps/*.env; do
	[ -f "$state" ] || continue
	app="${state##*/}"; app="${app%.env}"
	dir="$(komizo_state "$state" APP_DIR)"
	img="$(komizo_state "$state" CONFIG_IMAGE)"
	# The names CI dials this app by, recorded when it was added.
	kas="$(komizo_state "$state" KNOWN_AS)"
	usr="$(komizo_state "$state" CI_USER)"
	ver=""
	[ -n "$dir" ] && [ -f "$dir/.env" ] && ver="$(sed -n 's/^APP_VERSION=//p' "$dir/.env" | head -n 1)"
	running=0
	if [ -n "$dir" ] && [ -f "$dir/compose.yml" ]; then
		# The app's containers, named individually rather than only counted.
		# A count says three are up; it cannot say WHICH of four is missing,
		# and the missing one is the whole question when something 502s.
		#
		# Asked with -a so a container that exited is listed as exited instead
		# of vanishing -- a stack that died is exactly what you are looking for
		# here, and an absent row reads as "no such service".
		#
		# Membership comes from compose rather than from a label match on the
		# project name: compose derives that name from the directory and
		# normalises it, so an app under a custom --app-dir would not match its
		# own containers.
		#
		# ONE compose call, not two. The running count used to come from a
		# second 'ps -q' beside this, and a compose invocation is the slow part
		# of this script -- so a box with six apps paid for six round trips it
		# could answer from the states it had already fetched.
		# Two passes over the buffers, not five.
		#
		# This loop used to run 'printf | awk' four separate times over the same
		# two buffers -- once for the timestamps, once for the pid, once for the
		# state, once to emit the row -- and then a fifth to emit the cstat. Five
		# pipelines, ten processes, per container, per poll. The expensive docker
		# calls above are hoisted for exactly this reason and the cheap-looking
		# shell inside the loop was never given the same treatment: on a box with
		# six apps of five containers that was several hundred processes every
		# five seconds, for a page that is usually just left open.
		#
		# The two buffers are concatenated with a \034 (FS) record between them,
		# which nothing in docker's output can contain, so awk tells them apart
		# without depending on how many fields each happens to have -- a field
		# count would break the moment one of these formats gains a column.
		cinfo() {
			{ printf '%s\n' "$allc"; printf '\034\n'; printf '%s\n' "$starts"; }
		}
		for cid in $(docker compose -f "$dir/compose.yml" --project-directory "$dir" ps -aq 2>/dev/null); do
			# Pass one: the two values the /proc reads below need. Defaulted in
			# awk rather than in the shell, so the split that follows always has
			# exactly two fields to find.
			info="$(cinfo | awk -F'\t' -v id="$cid" '
				$0 == "\034" { second = 1; next }
				$1 != id { next }
				!second { st = $3; next }
				{ pid = $5 }
				END { printf "%s %s", (pid == "" ? "0" : pid), (st == "" ? "-" : st) }')"
			cpid="${info%% *}"
			cstate="${info#* }"
			[ "$cstate" = "running" ] && running=$((running + 1))

			cports="$(container_ports "$cpid")"
			# Its own record rather than more fields on the one above. That row is
			# what the container IS and changes when it is redeployed; this is what
			# it is spending and changes every five seconds. Keeping them apart
			# means a reading this could not take leaves the row alone.
			#
			# Two RECORDS, one pass: they are built from the same two lines, and
			# keeping them separate on the wire is the point -- walking those
			# lines twice to do it was not.
			cst="$(container_stat "$cpid")"
			cinfo | awk -F'\t' -v id="$cid" -v app="$app" -v pt="$cports" -v st="$cst" '
				$0 == "\034" { second = 1; next }
				$1 != id { next }
				!second { nm = $2; state = $3; status = $4; svc = $5; img = $6; have = 1; next }
				{ sa = $2; fa = $3; ec = $4 }
				END {
					if (!have) exit
					printf "container\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
						app, svc, nm, state, status, sa, fa, ec, img, pt
					printf "cstat\t%s\t%s\t%s\n", app, svc, st
				}'
		done
	fi
	printf 'app\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$app" "${usr:-?}" "$dir" "${ver:-none}" "$running" "$img" "$kas"

	# The hostnames this app answers on, as it declared them -- one per line in
	# its config image, recorded here by the deploy script.
	#
	# Read from that file rather than from the caddy fragment beside it. The
	# fragment is GENERATED from this, so parsing it back would be reading
	# komizo's own output to learn what the app said: the same answer, one
	# transformation later, and wrong the moment the generator changes.
	#
	# The upstream is not parsed either, for the same reason -- it is always
	# <app>-gate, because that is what the generator writes. Where a request
	# goes after the gate is inside the app now; this cannot see it and does
	# not guess.
	if [ -n "$dir" ] && [ -f "$dir/hostnames" ]; then
		# The NAME only. A line may say which container serves it -- "a.example
		# .com -> api" -- which is for attributing requests, not for display:
		# the routes column lists what the app answers on, and an arrow in it is
		# an implementation detail leaking into the one column that is supposed
		# to read like a list of addresses.
		sites="$(sed 's/#.*//' "$dir/hostnames" | tr -d '\r' |
			awk 'NF { printf "%s%s", sep, $1; sep = "," }')"
		[ -n "$sites" ] && printf 'route\t%s\t%s\t%s-gate\t80\n' "$app" "$sites" "$app"
		# And one record per name WITH what the app said serves it.
		#
		# The line above deliberately drops the annotation, because the app's own
		# row lists what the box answers on and an arrow in that is noise. Here
		# it is the whole point: it is the only thing on this machine that knows
		# which container a hostname reaches, and without it every name lands on
		# the gate -- which is true of the first hop and useless as an answer.
		sed 's/#.*//' "$dir/hostnames" | tr -d '\r' | awk -v a="$app" 'NF {
			svc = ""
			if (NF >= 3 && $2 == "->") svc = $3
			printf "host\t%s\t%s\t%s\n", a, $1, svc
		}'
	fi
done

# The shared reverse proxy, if it is installed. Not an app: no deploy account,
# no config image, nothing from CI ever touches it.
if [ -d /srv/_proxy ]; then
	pstate=stopped
	if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx komizo-proxy; then
		pstate=running
	fi
	pnet="$(sed -n 's/^    name: //p' /srv/_proxy/compose.yml 2>/dev/null | head -n 1)"
	pimg="$(sed -n 's/^    image: //p' /srv/_proxy/compose.yml 2>/dev/null | head -n 1)"
	# Docker's own words for how long it has been up, or why it is not.
	pstatus="$(docker ps -a --filter name=^komizo-proxy$ --format '{{.Status}}' 2>/dev/null | head -n 1)"
	# Same timestamps as an app's containers, so the proxy's row can say how
	# long it has been up in the same words every other row uses.
	pid="$(docker ps -a --filter name=^komizo-proxy$ -q --no-trunc 2>/dev/null | head -n 1)"
	pts="$(printf '%s\n' "$starts" | awk -F'\t' -v id="$pid" '$1 == id { printf "%s\t%s\t%s", $2, $3, $4; exit }')"
	printf 'proxy\t%s\t%s\t%s\t%s\t%s\n' "$pstate" "${pnet:-?}" "${pimg:-?}" "${pstatus:-not created}" "$pts"
	# The on-demand TLS gate, if one is configured. A wildcard hostname needs it,
	# and its absence is the whole explanation for a wildcard deploy that fails.
	# Read the ask URL straight off the Caddyfile; the directive is the only line
	# whose first field is "ask" (comments start with '#').
	if [ -f /srv/_proxy/Caddyfile ]; then
		gate="$(awk '$1 == "ask" { print $2; exit }' /srv/_proxy/Caddyfile 2>/dev/null)"
		[ -n "$gate" ] && printf 'gate\t%s\n' "$gate"
	fi
fi

# The shared network, and -- the point of reporting it at all -- who is actually
# attached and under what alias. Caddy reaches an app by alias, so a container
# that is missing here, or one sharing an alias with another app, is the whole
# explanation for a 502 that nothing else on the box reveals.
net="${pnet:-edge}"
if docker network inspect "$net" >/dev/null 2>&1; then
	printf 'net\t%s\t%s\t%s\n' "$net" \
		"$(docker network inspect "$net" -f '{{.Driver}}' 2>/dev/null)" \
		"$(docker network inspect "$net" -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null)"
	for cid in $(docker network inspect "$net" -f '{{range $k,$v := .Containers}}{{$k}} {{end}}' 2>/dev/null); do
		cname="$(docker inspect "$cid" -f '{{.Name}}' 2>/dev/null | sed 's|^/||')"
		[ -n "$cname" ] || continue
		# Aliases are per-endpoint, so they come from the container rather than
		# from the network. Docker adds the short id as one; harmless here,
		# since it is unique and cannot cause a false collision.
		al="$(docker inspect "$cid" -f "{{range \$n,\$c := .NetworkSettings.Networks}}{{if eq \$n \"$net\"}}{{range \$c.Aliases}}{{.}},{{end}}{{end}}{{end}}" 2>/dev/null | sed 's/,$//')"
		printf 'netmember\t%s\t%s\n' "$cname" "$al"
	done
fi

# Directories with no state file behind them -- usually a removal that did not
# finish. Names starting with "_" are komizo's own and are skipped: they never
# have one, so they would otherwise always look orphaned.
for d in /srv/*/; do
	[ -d "$d" ] || continue
	name="${d%/}"; name="${name##*/}"
	case "$name" in _*) continue ;; esac
	[ -f "/var/lib/komizo/apps/$name.env" ] || printf 'orphan\t%s\n' "$name"
done
