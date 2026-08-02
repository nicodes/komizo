package app

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

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

// routeRow is what an app publishes: the hostnames it declared, and the gate
// the shared proxy hands them to.
//
// ONE per app now, not one per site block. Routing within an app happens inside
// that app's own gate container, which this tool cannot see into and does
// not try to -- so the honest answer to "what serves this hostname" is the app,
// and the app's own logs answer the rest.
type routeRow struct {
	app      string
	sites    string // comma-joined, in the order the app declared them
	upstream string // always <app>-gate
	port     string // always 80; kept so the record shape is self-describing
}

// hostnames is every name this route answers on.
func (r routeRow) hostnames() []string { return strings.Split(r.sites, ",") }

// hasWildcard reports whether the app declares any wildcard hostname. A wildcard
// can only get a certificate via on-demand TLS, which needs the proxy's ask
// gate -- so this is what decides whether a missing gate is a problem for it.
func (a appRow) hasWildcard() bool {
	for _, r := range a.routes {
		for _, h := range r.hostnames() {
			if strings.HasPrefix(strings.TrimSpace(h), "*.") {
				return true
			}
		}
	}
	return false
}

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
// gate, the proxy's upstream is always <app>-gate -- so matching on that
// puts every hostname on the gate row, which is true of the first hop and no
// use at all as an answer to "what serves this domain".
//
// The arrow in deploy/hostnames is the only thing on this machine that knows the
// rest, because what happens after the gate is inside the app, in config
// komizo neither reads nor could parse if the gate were nginx.
//
// Names with no arrow fall back to the upstream match, which lands them on the
// gate. That is the honest answer for them: the app did not say, and the
// gate is genuinely where the request goes.
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
	// os is the distribution as it names itself: PRETTY_NAME out of the box's
	// /etc/os-release. Empty on a box whose shell never got that far, which
	// osName papers over with what komizo installs.
	os string
	// komizo is the stamp of what komizo last installed here, read back from the
	// box. Empty on a server that has never had it, or one set up by a komizo
	// old enough not to have written one.
	komizo string
	// komizoVersion is the komizo RELEASE that set this box up -- the first line
	// of the version file, shown beside the CLI's own. Empty on a box set up by a
	// komizo old enough to have written only the stamp; komizoInstalled tells
	// that box apart from one that was never set up at all.
	komizoVersion   string
	komizoInstalled bool
	hostKeys        [][2]string // {type, base64}
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
	tlsAsk    string // on-demand-TLS ask endpoint, empty when no gate is configured

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
		// Distinct containers, not distinct mentions. A container can hold the
		// same alias twice -- the proxy does, because its compose service name
		// and its container_name are both "komizo-proxy" and docker records
		// each as an alias -- and counting mentions reported that as a clash
		// with itself: "komizo-proxy resolves to 2 containers (komizo-proxy,
		// komizo-proxy)". One name, one container, no ambiguity, and a warning
		// about traffic splitting at random that could not happen.
		//
		// The real fault this exists for is two DIFFERENT containers claiming
		// one name on the shared network, which does split traffic and did take
		// an app down once.
		claimed := map[string]bool{}
		for _, a := range m.aliases {
			if a == "" || claimed[a] {
				continue
			}
			claimed[a] = true
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
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q -- every input is a flag", fs.Arg(0))
	}
	tgt, err := resolveTarget(fs, host, port)
	if err != nil {
		return err
	}
	if err := ensureReachable(tgt, acceptHostKey); err != nil {
		return err
	}

	rep, err := fetchReport(tgt)
	if err != nil {
		if _, missing := err.(errNoAgent); missing {
			return err
		}
		return fmt.Errorf("could not read the server's inventory: %w", err)
	}

	inv := inventoryFromReport(rep)
	apps, srv, proxy, net, orphans := inv.apps, inv.srv, inv.proxy, inv.net, inv.orphans

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

	// The on-demand TLS gate, and the warning that would have named a missing one
	// before a wildcard deploy failed for it.
	if proxy.installed {
		anyWildcard := false
		var wildApps []string
		for _, a := range apps {
			if a.hasWildcard() {
				anyWildcard = true
				wildApps = append(wildApps, a.name)
			}
		}
		switch {
		case proxy.tlsAsk != "":
			note("on-demand TLS gate: %s", proxy.tlsAsk)
		case anyWildcard:
			warn("%s use a wildcard hostname, but no on-demand TLS gate is set --\n"+
				"    their certificates will fail. Configure one with:\n"+
				"    komizo proxy --host %s --tls-ask <url>", strings.Join(wildApps, ", "), host)
		}
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

// inventory is everything one read of a box says about it.
//
// A struct rather than five positional returns. Every caller took them in the
// same order and most wanted two of them, so the call sites were a row of
// blanks -- `_, _, proxy, _, _ :=` -- in which a field inserted anywhere but
// the end silently rebinds the wrong value at seventeen places, and the two
// that matter compile either way because serverRow and proxyRow are both
// structs. Naming them makes that a compile error instead of a wrong screen.
type inventory struct {
	apps    []appRow
	srv     serverRow
	proxy   proxyRow
	net     netRow
	orphans []string
}
