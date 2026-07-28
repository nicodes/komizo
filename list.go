package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

// inventory runs on the server and emits one tab-separated record per app.
//
// It reads the generated deploy scripts rather than guessing from directory
// names: those scripts are what actually define an app, and each one carries
// its own APP_DIR and CONFIG_IMAGE. Anything in /srv without a matching script
// is reported as an orphan, which is what a half-finished removal looks like.
const inventoryScript = `
set -u
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
			--format '{{.Id}}	{{.State.StartedAt}}	{{.State.FinishedAt}}	{{.State.ExitCode}}' \
			2>/dev/null || true)"
	fi
fi

for bin in /usr/local/bin/deploy-*; do
	[ -f "$bin" ] || continue
	app="${bin#/usr/local/bin/deploy-}"
	dir="$(sed -n 's/^cd "\(.*\)"$/\1/p' "$bin" | head -n 1)"
	img="$(sed -n 's/^CONFIG_IMAGE="\(.*\)"$/\1/p' "$bin" | head -n 1)"
	ver=""
	[ -n "$dir" ] && [ -f "$dir/.env" ] && ver="$(sed -n 's/^APP_VERSION=//p' "$dir/.env" | head -n 1)"
	usr="$(awk -v b="$bin" '$0 ~ "cmd " b "$" {print $3; exit}' /etc/doas.conf 2>/dev/null)"
	running=0
	if [ -n "$dir" ] && [ -f "$dir/compose.yml" ]; then
		running="$(docker compose -f "$dir/compose.yml" --project-directory "$dir" ps -q 2>/dev/null | grep -c . || true)"
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
		for cid in $(docker compose -f "$dir/compose.yml" --project-directory "$dir" ps -aq 2>/dev/null); do
			ts="$(printf '%s\n' "$starts" | awk -F'\t' -v id="$cid" '$1 == id { printf "%s\t%s\t%s", $2, $3, $4; exit }')"
			printf '%s\n' "$allc" | awk -F'\t' -v id="$cid" -v app="$app" -v ts="$ts" '
				$1 == id { printf "container\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", app, $5, $2, $3, $4, ts, $6 }'
		done
	fi
	printf 'app\t%s\t%s\t%s\t%s\t%s\t%s\n' "$app" "${usr:-?}" "$dir" "${ver:-none}" "$running" "$img"

	# What this app publishes through the shared proxy, and WHERE EACH ROUTE
	# GOES -- the site address paired with the upstream it proxies to.
	#
	# The upstream is the join to a container: it is a network alias, so it
	# resolves through the shared network to exactly one container (or, when
	# two apps claim the same alias, to more than one, which is the clash the
	# server screen already reports).
	#
	# Site addresses alone were enough to list what a box serves. They are not
	# enough to say which container serves what, and that is the question when
	# one hostname 502s while the rest of the app is fine.
	#
	# Depth-tracked rather than matched line by line, because reverse_proxy is
	# routinely nested inside handle{} and the site it belongs to is several
	# lines above it. Comments are stripped first so a commented-out directive
	# does not advertise a route that is not there.
	if [ -n "$dir" ] && [ -f "$dir/caddy/app.caddy" ]; then
		awk -v app="$app" '
			{ line = $0; sub(/#.*/, "", line) }
			depth == 0 {
				if (line ~ /\{[ \t]*$/) {
					sites = line
					sub(/[ \t]*\{[ \t]*$/, "", sites)
					gsub(/[ \t]+/, "", sites)
					if (sites != "") depth = 1
				}
				next
			}
			{
				# A document root: this site block is served off disk, with no
				# container behind it. Emitted so the app list can show it --
				# "there is no container" and "there is nothing here" look
				# identical otherwise, and one of them is fine.
				if (line ~ /^[ \t]*root[ \t]+\*[ \t]/) {
					r = line
					sub(/^[ \t]*root[ \t]+\*[ \t]+/, "", r)
					sub(/[ \t]+$/, "", r)
					if (r != "") printf "static\t%s\t%s\t%s\n", app, sites, r
				}
				if (line ~ /reverse_proxy/) {
					i = index(line, "reverse_proxy")
					rest = substr(line, i + 13)
					n = split(rest, tok, /[ \t]+/)
					for (j = 1; j <= n; j++) {
						u = tok[j]
						# Skip the block form "reverse_proxy {", flags, and the
						# placeholders a dynamic upstream uses.
						if (u == "" || u ~ /^[{}]/ || u ~ /^-/) continue
						sub(/^https?:\/\//, "", u)
						sub(/:[0-9]*$/, "", u)
						if (u != "") printf "route\t%s\t%s\t%s\n", app, sites, u
					}
				}
				o = gsub(/\{/, "{", line); c = gsub(/\}/, "}", line)
				depth += o - c
				if (depth < 1) depth = 0
			}
		' "$dir/caddy/app.caddy" 2>/dev/null || true
	fi
done

# The shared reverse proxy, if it is installed. Not an app: no deploy account,
# no config image, nothing from CI ever touches it.
if [ -d /srv/_proxy ]; then
	pstate=stopped
	if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx komizo-caddy; then
		pstate=running
	fi
	pnet="$(sed -n 's/^    name: //p' /srv/_proxy/compose.yml 2>/dev/null | head -n 1)"
	pimg="$(sed -n 's/^    image: //p' /srv/_proxy/compose.yml 2>/dev/null | head -n 1)"
	# Docker's own words for how long it has been up, or why it is not.
	pstatus="$(docker ps -a --filter name=^komizo-caddy$ --format '{{.Status}}' 2>/dev/null | head -n 1)"
	# Same timestamps as an app's containers, so the proxy's row can say how
	# long it has been up in the same words every other row uses.
	pid="$(docker ps -a --filter name=^komizo-caddy$ -q --no-trunc 2>/dev/null | head -n 1)"
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

# Directories with no deploy script behind them -- usually a removal that did
# not finish. Names starting with "_" are komizo's own and are skipped: they
# never have a deploy script, so they would otherwise always look orphaned.
for d in /srv/*/; do
	[ -d "$d" ] || continue
	name="${d%/}"; name="${name##*/}"
	case "$name" in _*) continue ;; esac
	[ -f "/usr/local/bin/deploy-$name" ] || printf 'orphan\t%s\n' "$name"
done
`

type appRow struct {
	name, user, dir, version, running, image string
	containers                               []containerRow
	routes                                   []routeRow
	statics                                  []staticRow
}

// staticRow is a site block served straight off disk: the hostnames it answers
// on, and the directory they come from.
//
// It has no container, so it has no state and no uptime -- which is exactly why
// it needs its own row. Without one, a hostname that works looks identical to a
// hostname nothing serves.
type staticRow struct {
	app   string
	sites string
	root  string
}

func (r staticRow) hostnames() []string { return strings.Split(r.sites, ",") }

// label is what to call this root on screen: the last path segment, which is
// the name the app gave it -- public/www, public/app.
func (r staticRow) label() string {
	if i := strings.LastIndex(strings.TrimRight(r.root, "/"), "/"); i >= 0 {
		return strings.TrimRight(r.root, "/")[i+1:]
	}
	return r.root
}

// routeRow is one site block in an app's caddy fragment: the hostnames it
// answers on, and the upstream it forwards to.
//
// The upstream is a network alias, which is what makes this joinable to a
// container -- and what makes a route with no container behind it visible
// rather than a 502 with no explanation on the box.
type routeRow struct {
	app      string
	sites    string // comma-joined, as written in the fragment
	upstream string
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
func (a appRow) routesByContainer(n netRow) map[string][]string {
	alias := map[string]string{}
	for _, m := range n.members {
		for _, al := range m.aliases {
			alias[al] = m.container
		}
	}
	mine := map[string]bool{}
	for _, c := range a.containers {
		mine[c.name] = true
	}

	byContainer := map[string][]string{}
	for _, r := range a.routes {
		if cn, ok := alias[r.upstream]; ok && mine[cn] {
			byContainer[cn] = append(byContainer[cn], r.hostnames()...)
			continue
		}
		for _, c := range a.containers {
			if r.upstream == c.service ||
				r.upstream == a.name+"-"+c.service ||
				strings.HasSuffix(r.upstream, "-"+c.service) {
				byContainer[c.name] = append(byContainer[c.name], r.hostnames()...)
				break
			}
		}
	}
	return byContainer
}

// allRoutes is every hostname the app publishes, for the places that want one
// flat list rather than the per-container breakdown.
func (a appRow) allRoutes() []string {
	var out []string
	seen := map[string]bool{}
	add := func(hosts []string) {
		for _, h := range hosts {
			if h != "" && !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	for _, r := range a.routes {
		add(r.hostnames())
	}
	// Served off disk, but published just the same -- and just as gone if the
	// app is removed.
	for _, r := range a.statics {
		add(r.hostnames())
	}
	return out
}

// containerRow is one container belonging to an app.
//
// service is the name in compose.yml, and is the one to lead with: it is what
// you wrote, what the caddy fragment points at, and what stays stable across
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
	state    string // ready | docker-stopped | bare
	docker   string
	hostKeys [][2]string // {type, base64}
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

func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.Usage = func() { usageList(fs) }
	var host string
	var port int
	var acceptHostKey bool
	fs.StringVar(&host, "host", "", "server to inspect, [user@]HOST")
	fs.IntVar(&port, "port", 22, "SSH port")
	fs.BoolVar(&acceptHostKey, "accept-host-key", false, "trust an unseen server's host key (trust-on-first-use)")
	if err := fs.Parse(args); err != nil {
		return errSilent
	}
	if host == "" {
		return fmt.Errorf("--host is required, e.g. --host root@myapp.example.com")
	}

	tgt, err := parseTarget(host)
	if err != nil {
		return err
	}
	tgt.port = port
	tgt.portExplicit = portWasSet(fs)
	tgt.resolvePort()
	if err := validateHost(tgt.host); err != nil {
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
	var statics []staticRow
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Split(ln, "\t")
		switch {
		case len(f) == 3 && f[0] == "server":
			srv.state, srv.docker = f[1], f[2]
		case len(f) == 3 && f[0] == "hostkey":
			srv.hostKeys = append(srv.hostKeys, [2]string{f[1], f[2]})
		case len(f) == 7 && f[0] == "app":
			apps = append(apps, appRow{
				name: f[1], user: f[2], dir: f[3], version: f[4],
				running: f[5], image: f[6],
			})
		case len(f) == 10 && f[0] == "container":
			c := containerRow{app: f[1], service: f[2], name: f[3], state: f[4], status: f[5]}
			c.startedAt, c.finishedAt = parseStamp(f[6]), parseStamp(f[7])
			fmt.Sscanf(f[8], "%d", &c.exitCode)
			c.image = f[9]
			containers = append(containers, c)
		case len(f) == 4 && f[0] == "route":
			routes = append(routes, routeRow{app: f[1], sites: f[2], upstream: f[3]})
		case len(f) == 4 && f[0] == "static":
			statics = append(statics, staticRow{app: f[1], sites: f[2], root: f[3]})
		case len(f) == 8 && f[0] == "proxy":
			proxy = proxyRow{installed: true, state: f[1], network: f[2],
				image: f[3], status: f[4]}
			proxy.startedAt, proxy.finishedAt = parseStamp(f[5]), parseStamp(f[6])
		case len(f) == 4 && f[0] == "net":
			net.name, net.driver, net.subnet = f[1], f[2], f[3]
		case len(f) == 3 && f[0] == "netmember":
			var al []string
			for _, a := range strings.Split(f[2], ",") {
				if a != "" {
					al = append(al, a)
				}
			}
			net.members = append(net.members, netMember{container: f[1], aliases: al})
		case len(f) == 2 && f[0] == "orphan":
			orphans = append(orphans, f[1])
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
		for _, r := range statics {
			if r.app == apps[i].name {
				apps[i].statics = append(apps[i].statics, r)
			}
		}
	}
	return apps, srv, proxy, net, orphans
}
