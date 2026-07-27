package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
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
	fi
	# Hostnames this app publishes through the shared proxy, read out of its
	# caddy fragment. A site address is a line at column zero ending in "{".
	routes=""
	if [ -n "$dir" ] && [ -d "$dir/caddy" ]; then
		routes="$(cat "$dir"/caddy/app.caddy 2>/dev/null \
			| awk '/^[^ \t#].*\{[ \t]*$/ { sub(/[ \t]*\{[ \t]*$/, ""); gsub(/,[ \t]*/, ","); print }' \
			| paste -sd, - 2>/dev/null || true)"
	fi
	printf 'app\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$app" "${usr:-?}" "$dir" "${ver:-none}" "$running" "$img" "$routes"
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
	printf 'proxy\t%s\t%s\t%s\t%s\n' "$pstate" "${pnet:-?}" "${pimg:-?}" "${pstatus:-not created}"
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
	routes                                   string // hostnames served through the shared proxy
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
}

func (p proxyRow) running() bool { return p.state == "running" }

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
	fs.StringVar(&host, "host", "", "server to inspect, [user@]HOST")
	fs.IntVar(&port, "port", 22, "SSH port")
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
	if r := tgt.probe(); !r.ok() {
		return r.explain(tgt)
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
		routes := a.routes
		if routes == "" {
			routes = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			a.name, a.user, a.dir, a.version, a.running, routes, a.image)
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
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Split(ln, "\t")
		switch {
		case len(f) == 3 && f[0] == "server":
			srv.state, srv.docker = f[1], f[2]
		case len(f) == 3 && f[0] == "hostkey":
			srv.hostKeys = append(srv.hostKeys, [2]string{f[1], f[2]})
		case len(f) == 8 && f[0] == "app":
			apps = append(apps, appRow{f[1], f[2], f[3], f[4], f[5], f[6], f[7]})
		case len(f) == 5 && f[0] == "proxy":
			proxy = proxyRow{installed: true, state: f[1], network: f[2],
				image: f[3], status: f[4]}
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
	return apps, srv, proxy, net, orphans
}
