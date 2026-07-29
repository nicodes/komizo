package app

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// inventory runs on the server and emits one tab-separated record per app.
//
// It reads the state file komizo writes per app -- /var/lib/komizo/apps/<app>.env
// -- rather than guessing from directory names or parsing values back out of
// the generated deploy script. That script is code; this is the record. Anything
// in /srv with no state file behind it is reported as an orphan, which is what a
// half-finished removal looks like.
const inventoryScript = `
set -u
` + stateHelper + `
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
	printf 'komizo\t%s\n' "$(head -n 1 /var/lib/komizo/version 2>/dev/null)"
fi
` + systemProbe + `
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
# listens; and EXPOSE is inherited from base images, so a Caddy gateway
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
	for _h in $(awk '$4 == "0A" { split($2, a, ":"); print a[2] }' \
		"/proc/$_pid/net/tcp" "/proc/$_pid/net/tcp6" 2>/dev/null | sort -u); do
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
		for cid in $(docker compose -f "$dir/compose.yml" --project-directory "$dir" ps -aq 2>/dev/null); do
			ts="$(printf '%s\n' "$starts" | awk -F'\t' -v id="$cid" '$1 == id { printf "%s\t%s\t%s", $2, $3, $4; exit }')"
			cpid="$(printf '%s\n' "$starts" | awk -F'\t' -v id="$cid" '$1 == id { print $5; exit }')"
			cports="$(container_ports "$cpid")"
			cstate="$(printf '%s\n' "$allc" | awk -F'\t' -v id="$cid" '$1 == id { print $3; exit }')"
			[ "$cstate" = "running" ] && running=$((running + 1))
			printf '%s\n' "$allc" | awk -F'\t' -v id="$cid" -v app="$app" -v ts="$ts" -v pt="$cports" '
				$1 == id { printf "container\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", app, $5, $2, $3, $4, ts, $6, pt }'
			# Its own record rather than more fields on the one above. That row is
			# what the container IS and changes when it is redeployed; this is what
			# it is spending and changes every five seconds. Keeping them apart
			# means a reading this could not take leaves the row alone.
			cst="$(container_stat "$cpid")"
			printf '%s\n' "$allc" | awk -F'\t' -v id="$cid" -v app="$app" -v st="$cst" '
				$1 == id { printf "cstat\t%s\t%s\t%s\n", app, $5, st }'
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
	# <app>-gateway, because that is what the generator writes. Where a request
	# goes after the gateway is inside the app now; this cannot see it and does
	# not guess.
	if [ -n "$dir" ] && [ -f "$dir/hostnames" ]; then
		# The NAME only. A line may say which container serves it -- "a.example
		# .com -> api" -- which is for attributing requests, not for display:
		# the routes column lists what the app answers on, and an arrow in it is
		# an implementation detail leaking into the one column that is supposed
		# to read like a list of addresses.
		sites="$(sed 's/#.*//' "$dir/hostnames" | tr -d '\r' |
			awk 'NF { printf "%s%s", sep, $1; sep = "," }')"
		[ -n "$sites" ] && printf 'route\t%s\t%s\t%s-gateway\t80\n' "$app" "$sites" "$app"
		# And one record per name WITH what the app said serves it.
		#
		# The line above deliberately drops the annotation, because the app's own
		# row lists what the box answers on and an arrow in that is noise. Here
		# it is the whole point: it is the only thing on this machine that knows
		# which container a hostname reaches, and without it every name lands on
		# the gateway -- which is true of the first hop and useless as an answer.
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
`

// stateHelper reads one value out of an app's state file.
//
// Spliced into every script that needs it rather than written three times: the
// inventory, the sampler's container walk and the volume probe all enumerate
// apps, and all three used to sed the same values back out of the generated
// deploy script -- five readers parsing komizo's own output as a database.
//
// The value is everything after the first "=", so a value containing one
// survives. Comments and blank lines cannot match a KEY= prefix, so they need
// no special case.
const stateHelper = `
komizo_state() {
	sed -n "s/^$2=//p" "$1" 2>/dev/null | head -n 1
}
`

type appRow struct {
	// knownAs is the names CI dials this app by, as recorded on the box. The
	// KOMIZO_KNOWN_HOSTS this app pins is these names against the server's keys --
	// the keys belong to the machine, the names belong to the repo.
	knownAs []string

	name, user, dir, version, running, image string
	containers                               []containerRow
	routes                                   []routeRow
	// hosts is every name this app answers on, with the container the app said
	// serves it. Read for display and for attributing requests; routing uses
	// the name alone, so a wrong arrow mislabels a row and cannot misroute.
	hosts []hostRow
}

// routeRow is what an app publishes: the hostnames it declared, and the gateway
// the shared proxy hands them to.
//
// ONE per app now, not one per site block. Routing within an app happens inside
// that app's own gateway container, which this tool cannot see into and does
// not try to -- so the honest answer to "what serves this hostname" is the app,
// and the app's own logs answer the rest.
type routeRow struct {
	app      string
	sites    string // comma-joined, in the order the app declared them
	upstream string // always <app>-gateway
	port     string // always 80; kept so the record shape is self-describing
}

// hostnames is every name this route answers on.
func (r routeRow) hostnames() []string { return strings.Split(r.sites, ",") }

// routesByContainer pairs each of an app's containers with the hostnames that
// reach it.
//
// Two ways of matching, and the second is not a nicety. The network's alias
// list only covers RUNNING containers, so the moment an app is stopped every
// one of its routes stops resolving -- and the hostnames it serves are exactly
// what you want to see while deciding whether to start it again. Falling back
// to the service name keeps them attached to the row they belong to.
//
// The convention it relies on is compose's own: an alias is <app>-<service>, or
// bare <service>. Both forms are what komizo's docs tell people to write, and a
// fragment naming something else simply matches nothing -- which is the same
// answer the alias lookup gives, arrived at without pretending.
// hostRow is one name the app answers on, and the container the app says serves
// it. The service is empty when the app did not say.
type hostRow struct {
	app, name, service string
}

// routesByContainer is which names reach which container.
//
// From what the APP declared, first. Since every app fronts itself with its own
// gateway, the proxy's upstream is always <app>-gateway -- so matching on that
// puts every hostname on the gateway row, which is true of the first hop and no
// use at all as an answer to "what serves this domain".
//
// The arrow in deploy/hostnames is the only thing on this machine that knows the
// rest, because what happens after the gateway is inside the app, in config
// komizo neither reads nor could parse if the gateway were nginx.
//
// Names with no arrow fall back to the upstream match, which lands them on the
// gateway. That is the honest answer for them: the app did not say, and the
// gateway is genuinely where the request goes.
func (a appRow) routesByContainer(n netRow) map[string][]string {
	byContainer := map[string][]string{}
	byService := map[string]string{}
	for _, c := range a.containers {
		byService[c.service] = c.name
	}
	claimed := map[string]bool{}
	for _, h := range a.hosts {
		if h.service == "" {
			continue
		}
		cn, ok := byService[h.service]
		if !ok {
			// The app named a container it does not have -- a typo, or a
			// service it has since renamed. Left for the fallback rather than
			// dropped, so the name still appears somewhere.
			continue
		}
		byContainer[cn] = append(byContainer[cn], h.name)
		claimed[h.name] = true
	}
	for _, r := range a.routes {
		cn := a.containerFor(r, n)
		if cn == "" {
			continue
		}
		for _, h := range r.hostnames() {
			if !claimed[h] {
				byContainer[cn] = append(byContainer[cn], h)
			}
		}
	}
	return byContainer
}

// containerFor resolves a route's upstream to one of this app's containers,
// or "" when it names nothing here.
func (a appRow) containerFor(r routeRow, n netRow) string {
	mine := map[string]bool{}
	for _, c := range a.containers {
		mine[c.name] = true
	}
	for _, m := range n.members {
		for _, al := range m.aliases {
			if al == r.upstream && mine[m.container] {
				return m.container
			}
		}
	}
	for _, c := range a.containers {
		if r.upstream == c.service ||
			r.upstream == a.name+"-"+c.service ||
			strings.HasSuffix(r.upstream, "-"+c.service) {
			return c.name
		}
	}
	return ""
}

// allRoutes is every hostname the app publishes.
func (a appRow) allRoutes() []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range a.routes {
		for _, h := range r.hostnames() {
			if h != "" && !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	return out
}

// containerRow is one container belonging to an app.
//
// service is the name in compose.yml, and is the one to lead with: it is what
// you wrote, what the shared proxy is pointed at, and what stays stable across
// restarts. The container name is docker's, derived from it.
type containerRow struct {
	app     string
	service string
	name    string
	state   string // running | exited | created ... docker's machine-readable word
	status  string // docker's own prose, e.g. "Up 3 hours", "Exited (1) 2 minutes ago"
	image   string // the reference this container was created from
	// When it last started and last stopped, and the code it stopped with.
	// Timestamps rather than prose, so several of them can be compared and all
	// of them rendered the same way.
	startedAt  time.Time
	finishedAt time.Time
	exitCode   int
	// ports is what this container is LISTENING on, comma-joined, read from its
	// network namespace rather than declared anywhere. Empty for a stopped
	// container, which has no namespace to read.
	ports string
}

// portsText is the listening ports as a cell: ":8090", ":80,:443", or an em
// dash when there are none -- a worker, or a container that is not running.
func (c containerRow) portsText() string {
	if c.ports == "" {
		return "—"
	}
	return c.portsList()
}

// portsList is the same without the em dash, for the places that leave nothing
// out rather than drawing a placeholder.
func (c containerRow) portsList() string {
	if c.ports == "" {
		return ""
	}
	return ":" + strings.ReplaceAll(c.ports, ",", ", :")
}

// imageText is the container's image, trimmed to the part that differs between
// one row and the next.
//
// Two things come off. The tag, when it is simply this app's deployed version:
// every service in a komizo app is pinned to ${APP_VERSION}, so it is the
// commit SHA already shown on the app's row -- sixty characters of column
// saying what the row above it said. A tag that is NOT the version is the
// interesting case, and that one is shown in full: a service left on :latest,
// or an upstream image like caddy:2, is a fact you want to notice.
//
// And the registry and namespace, which are the same for every image in an app
// and usually every app on the host. "ghcr.io/nicodes/ormos-api" and
// "ghcr.io/nicodes/ormos-db" differ in their last four characters and share
// the nineteen in front, so the column reads as a wall with the answer at the
// end of it.
//
// This does lose a distinction: two images with the same final segment on
// different registries now look identical. The full reference is one keypress
// away in the container's logs and in compose.yml, and the case this optimises
// for -- reading down a list of an app's own services -- is the one that
// happens every time the page is opened.
func (c containerRow) imageText(version string) string {
	ref := c.image
	if version != "" && version != "none" {
		if s, ok := strings.CutSuffix(ref, ":"+version); ok {
			ref = s
		}
	}
	// After the tag, so a registry given with a port (localhost:5000/api) is
	// not mistaken for one -- the slash is what separates path from name.
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		ref = ref[i+1:]
	}
	return ref
}

// stateText is how long a container has been in the state it is in.
//
// No word in front of it. The dot beside it already says which state that is,
// and repeating it in text meant the column held two things -- one of them
// redundant -- at three different widths depending on the word.
//
// The exit code is the exception, because it is the one fact neither the dot
// nor the duration carries and the first thing worth knowing when something
// stopped on its own. A clean exit says nothing extra.
func (c containerRow) stateText() string {
	switch c.state {
	case "running", "restarting":
		return since(c.startedAt)
	case "exited":
		if c.exitCode != 0 {
			return fmt.Sprintf("%s  exit %d", since(c.finishedAt), c.exitCode)
		}
		return since(c.finishedAt)
	case "":
		return "—"
	default:
		return since(c.startedAt)
	}
}

func (c containerRow) up() bool { return c.state == "running" }

// up reports whether any of the app's containers are running. The count comes
// from `compose ps -q`, which lists the running ones.
func (a appRow) up() bool { return a.running != "" && a.running != "0" }

// upSince is when the app was last fully up: the moment its most recently
// started container came up.
//
// The latest, not the earliest. An app with one container restarted a minute
// ago has been serving completely for a minute, whatever the other two have
// been doing for a week -- and that minute is the interesting number, because
// it is when whatever went wrong went wrong.
//
// Zero if nothing is running, or if no container reported a start time.
func (a appRow) upSince() time.Time {
	var latest time.Time
	for _, c := range a.containers {
		if c.up() && c.startedAt.After(latest) {
			latest = c.startedAt
		}
	}
	return latest
}

// downSince is when the app last became completely down: the moment its final
// still-running container stopped.
//
// The mirror of upSince, and the latest for the same reason. An app is not down
// because one container exited; it is down once the last one has, and that is
// the moment worth counting from.
func (a appRow) downSince() time.Time {
	var latest time.Time
	for _, c := range a.containers {
		if c.finishedAt.After(latest) {
			latest = c.finishedAt
		}
	}
	return latest
}

// stateText is how long the app has been as it is, running or not.
//
// Containers show their downtime, so an app that shows nothing while stopped is
// the one row on the page that goes blank exactly when you are looking at it --
// which is while it is down.
func (a appRow) stateText() string {
	if len(a.containers) == 0 {
		return "—"
	}
	if a.upSince().IsZero() {
		return since(a.downSince())
	}
	return since(a.upSince())
}

// serverRow is the box itself, before any app is considered.
type serverRow struct {
	state  string // ready | docker-stopped | bare
	docker string
	// os is the distribution the box runs. Not reported by the inventory yet --
	// komizo installs Alpine and nothing else, so there is one answer and osName
	// gives it. The field exists so that reading /etc/os-release on the host is
	// a change to the script and this struct, and not to every place that shows
	// it.
	os string
	// komizo is the stamp of what komizo last installed here, read back from the
	// box. Empty on a server that has never had it, or one set up by a komizo
	// old enough not to have written one.
	komizo   string
	hostKeys [][2]string // {type, base64}
}

// osName is what the box runs, or what komizo puts on it when nothing has said
// otherwise.
func (s serverRow) osName() string {
	if s.os == "" {
		return "alpine"
	}
	return s.os
}

func (s serverRow) ready() bool { return s.state == "ready" }

// proxyRow is the shared reverse proxy. Zero value means it is not installed.
type proxyRow struct {
	installed bool
	state     string // running | stopped
	network   string
	image     string
	status    string // docker's own wording, e.g. "Up 3 hours" / "Exited (0) 5m ago"

	startedAt  time.Time
	finishedAt time.Time
}

func (p proxyRow) running() bool { return p.state == "running" }

// parseStamp reads one of docker's RFC3339 times.
//
// Docker reports a zero time for a container that has never run or has never
// stopped, and that parses perfectly well -- it would simply read as an uptime
// measured from the year 1.
func parseStamp(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.Year() <= 1 {
		return time.Time{}
	}
	return t
}

// netRow is the shared network and everything attached to it.
type netRow struct {
	name, driver, subnet string
	members              []netMember
}

type netMember struct {
	container string
	aliases   []string
}

// duplicateAliases finds names that resolve to more than one container. Compose
// gives every service an alias equal to its service name, so two apps that both
// call a service "web" both answer to "web" here -- and Caddy round-robins
// between them. It fails intermittently rather than outright, which is why it
// is worth surfacing rather than leaving to be discovered.
func (n netRow) duplicateAliases() map[string][]string {
	seen := map[string][]string{}
	for _, m := range n.members {
		for _, a := range m.aliases {
			if a == "" {
				continue
			}
			seen[a] = append(seen[a], m.container)
		}
	}
	dupes := map[string][]string{}
	for a, cs := range seen {
		if len(cs) > 1 {
			dupes[a] = cs
		}
	}
	return dupes
}

func RunList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.Usage = func() { usageList(fs) }
	var host string
	var port int
	var acceptHostKey bool
	fs.StringVar(&host, "host", "", "server to inspect, [user@]HOST")
	fs.IntVar(&port, "port", 22, "SSH port")
	fs.BoolVar(&acceptHostKey, "accept-host-key", false, "trust an unseen server's host key (trust-on-first-use)")
	if err := fs.Parse(args); err != nil {
		return ErrSilent
	}
	tgt, err := resolveTarget(fs, host, port)
	if err != nil {
		return err
	}
	if err := ensureReachable(tgt, acceptHostKey); err != nil {
		return err
	}

	res, err := tgt.runCapture(inventoryScript)
	if err != nil {
		return fmt.Errorf("could not read the server's inventory: %w", err)
	}

	apps, srv, proxy, net, orphans := parseInventory(res)

	if !srv.ready() {
		if srv.state == "docker-stopped" {
			return fmt.Errorf("Docker is installed on %s but not running.\n"+
				"    Try 'rc-service docker start' there, or re-run 'komizo init --host %s'.", tgt.host, host)
		}
		return fmt.Errorf("%s is not set up yet.\n\n    komizo init --host %s\n\n"+
			"    That installs Docker and the shared network. Nothing app-specific.", tgt.host, host)
	}

	if len(apps) == 0 {
		fmt.Printf("No apps set up on %s yet. Add one with:\n\n    komizo add --host %s --app NAME --config REF\n\n",
			tgt.host, host)
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "APP\tACCOUNT\tDIRECTORY\tVERSION\tUP\tROUTES\tCONFIG IMAGE")
	for _, a := range apps {
		routes := strings.Join(a.allRoutes(), ",")
		if routes == "" {
			routes = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			a.name, a.user, a.dir, a.version, a.running, routes, a.image)
		// Indented under their app, so which container serves what is readable
		// without cross-referencing the compose file.
		byContainer := a.routesByContainer(net)
		for _, c := range a.containers {
			fmt.Fprintf(w, "  %s\t%s\t%s\t\t\t%s\t\n",
				c.service, c.name, c.status, strings.Join(byContainer[c.name], ","))
		}
	}
	w.Flush()

	fmt.Println()
	switch {
	case !proxy.installed:
		note("No shared reverse proxy. Apps must publish their own ports.\n" +
			"    Install one with: komizo proxy --host " + host)
	case !proxy.running():
		warn("the reverse proxy is installed but not running -- nothing is being served")
	default:
		note("reverse proxy running on network %q", proxy.network)
	}

	for a, cs := range net.duplicateAliases() {
		warn("%q resolves to %d containers on network %q (%s).\n"+
			"    Traffic to it is split between them at random. Give each app a\n"+
			"    unique alias in its compose.yml.", a, len(cs), net.name, strings.Join(cs, ", "))
	}

	for _, o := range orphans {
		warn("/srv/%s has no deploy script behind it -- left over from a removal?", o)
	}
	return nil
}

// parseInventory turns the server's tab-separated records into rows. Shared by
// `komizo list` and the TUI so both see the same view of a box.
func parseInventory(out string) (apps []appRow, srv serverRow, proxy proxyRow, net netRow, orphans []string) {
	var containers []containerRow
	var routes []routeRow
	var hosts []hostRow
	// Scrubbed once, here, rather than at each of the several dozen places a
	// field ends up on screen. This is the boundary the values cross.
	out = scrub(out)
	for _, ln := range strings.Split(out, "\n") {
		raw := strings.Split(ln, "\t")
		if len(raw) < 2 {
			continue
		}
		// Padded to the width the record is expected to have, rather than
		// matched on an exact count.
		//
		// A field the box could not produce -- the timestamps of a container
		// that has never run, the start time of a proxy that was never created
		// -- used to make the whole row one field short, and an exact-length
		// switch dropped it silently. An installed proxy then reported as no
		// proxy at all, and the interface offered to install the one already
		// there. Absent values now arrive as empty, which is what they are.
		f := func(n int) []string {
			if len(raw) >= n {
				return raw[:n]
			}
			out := make([]string, n)
			copy(out, raw)
			return out
		}
		switch raw[0] {
		case "server":
			g := f(3)
			srv.state, srv.docker = g[1], g[2]
		case "komizo":
			srv.komizo = raw[1]
		case "hostkey":
			g := f(3)
			srv.hostKeys = append(srv.hostKeys, [2]string{g[1], g[2]})
		case "app":
			g := f(8)
			apps = append(apps, appRow{
				name: g[1], user: g[2], dir: g[3], version: g[4],
				running: g[5], image: g[6], knownAs: splitNames(g[7]),
			})
		case "container":
			g := f(11)
			c := containerRow{app: g[1], service: g[2], name: g[3], state: g[4], status: g[5]}
			c.startedAt, c.finishedAt = parseStamp(g[6]), parseStamp(g[7])
			c.exitCode, _ = strconv.Atoi(g[8])
			c.image = g[9]
			c.ports = g[10]
			containers = append(containers, c)
		case "route":
			g := f(5)
			routes = append(routes, routeRow{app: g[1], sites: g[2], upstream: g[3], port: g[4]})
		case "host":
			g := f(4)
			hosts = append(hosts, hostRow{app: g[1], name: g[2], service: g[3]})
		case "proxy":
			g := f(8)
			proxy = proxyRow{installed: true, state: g[1], network: g[2],
				image: g[3], status: g[4]}
			proxy.startedAt, proxy.finishedAt = parseStamp(g[5]), parseStamp(g[6])
		case "net":
			g := f(4)
			net.name, net.driver, net.subnet = g[1], g[2], g[3]
		case "netmember":
			g := f(3)
			var al []string
			for _, a := range strings.Split(g[2], ",") {
				if a != "" {
					al = append(al, a)
				}
			}
			net.members = append(net.members, netMember{container: g[1], aliases: al})
		case "orphan":
			orphans = append(orphans, raw[1])
		}
	}

	// Attached after the loop rather than during it: the container lines for an
	// app are emitted inside that app's own record, so they arrive before the
	// app row is complete only by accident of ordering. Joining here does not
	// depend on that.
	for i := range apps {
		for _, c := range containers {
			if c.app == apps[i].name {
				apps[i].containers = append(apps[i].containers, c)
			}
		}
		for _, r := range routes {
			if r.app == apps[i].name {
				apps[i].routes = append(apps[i].routes, r)
			}
		}
		for _, h := range hosts {
			if h.app == apps[i].name {
				apps[i].hosts = append(apps[i].hosts, h)
			}
		}
	}
	return apps, srv, proxy, net, orphans
}
