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
for bin in /usr/local/bin/deploy /usr/local/bin/deploy-*; do
	[ -f "$bin" ] || continue
	case "$bin" in
		/usr/local/bin/deploy)   app=app ;;
		*)                       app="${bin#/usr/local/bin/deploy-}" ;;
	esac
	dir="$(sed -n 's/^cd "\(.*\)"$/\1/p' "$bin" | head -n 1)"
	img="$(sed -n 's/^CONFIG_IMAGE="\(.*\)"$/\1/p' "$bin" | head -n 1)"
	ver=""
	[ -n "$dir" ] && [ -f "$dir/.env" ] && ver="$(sed -n 's/^APP_VERSION=//p' "$dir/.env" | head -n 1)"
	usr="$(awk -v b="$bin" '$0 ~ "cmd " b "$" {print $3; exit}' /etc/doas.conf 2>/dev/null)"
	running=0
	if [ -n "$dir" ] && [ -f "$dir/compose.yml" ]; then
		running="$(docker compose -f "$dir/compose.yml" --project-directory "$dir" ps -q 2>/dev/null | grep -c . || true)"
	fi
	printf 'app\t%s\t%s\t%s\t%s\t%s\t%s\n' "$app" "${usr:-?}" "$dir" "${ver:-none}" "$running" "$img"
done

# Directories with no deploy script behind them -- usually a removal that did
# not finish.
for d in /srv/*/; do
	[ -d "$d" ] || continue
	name="${d%/}"; name="${name##*/}"
	if [ "$name" = app ]; then bin=/usr/local/bin/deploy; else bin="/usr/local/bin/deploy-$name"; fi
	[ -f "$bin" ] || printf 'orphan\t%s\n' "$name"
done
`

type appRow struct {
	name, user, dir, version, running, image string
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
	if !tgt.reachable() {
		return fmt.Errorf("cannot SSH in as %s without a password", tgt.user)
	}

	res, err := tgt.runCapture(inventoryScript)
	if err != nil {
		return fmt.Errorf("could not read the server's inventory: %w", err)
	}

	var apps []appRow
	var orphans []string
	for _, ln := range strings.Split(res, "\n") {
		f := strings.Split(ln, "\t")
		switch {
		case len(f) == 7 && f[0] == "app":
			apps = append(apps, appRow{f[1], f[2], f[3], f[4], f[5], f[6]})
		case len(f) == 2 && f[0] == "orphan":
			orphans = append(orphans, f[1])
		}
	}

	if len(apps) == 0 {
		fmt.Printf("No apps set up on %s yet. Add one with:\n\n    ncicd add --host %s --app NAME --config REF\n\n",
			tgt.host, host)
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "APP\tACCOUNT\tDIRECTORY\tVERSION\tUP\tCONFIG IMAGE")
	for _, a := range apps {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", a.name, a.user, a.dir, a.version, a.running, a.image)
	}
	w.Flush()

	for _, o := range orphans {
		warn("/srv/%s has no deploy script behind it -- left over from a removal?", o)
	}
	return nil
}
