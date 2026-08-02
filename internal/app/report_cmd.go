package app

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nicodes/komizo/internal/box"
)

// `komizo report` -- one reading of a box, as the box itself describes it.
//
// The plainest possible use of the agent, and deliberately so. It answers "is
// this server all right" in one screen with no interface to drive, it is what
// you paste into an issue, and --json is what anything else reads.
//
// It exists before any of the service does, and is useful without it. That is
// the whole argument for building v0 first -- see design/appify.md §11.

func RunReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.Usage = func() { usageReport(fs) }
	var host string
	var port int
	var acceptHostKey, asJSON, cached bool
	fs.StringVar(&host, "host", "", "server to read, [user@]HOST")
	fs.IntVar(&port, "port", 22, "SSH port")
	fs.BoolVar(&acceptHostKey, "accept-host-key", false, "trust an unseen server's host key (trust-on-first-use)")
	fs.BoolVar(&asJSON, "json", false, "print the report as the box produced it")
	fs.BoolVar(&cached, "cached", false, "print the last report the agent wrote, rather than measuring now")
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

	args2 := []string{"report"}
	if cached {
		args2 = append(args2, "--cached")
	}

	// --json prints what the BOX said, byte for byte, rather than this binary's
	// re-encoding of it. The difference matters the moment the two disagree,
	// which is exactly when somebody would be asking for the raw document -- so
	// it deliberately skips the decode as well.
	if asJSON {
		raw, err := askBox(tgt, args2...)
		if err != nil {
			return err
		}
		fmt.Println(string(raw))
		return nil
	}

	r, err := fetchBox[box.Report](tgt, args2...)
	if err != nil {
		return err
	}
	printReport(r, tgt.host, cached)
	return nil
}

// printReport is the report as a person reads it.
//
// Problems FIRST, before the inventory. Everything below them is context for
// whatever is wrong, and a page that makes you scroll past forty healthy rows
// to find the broken one has buried the only thing you opened it for.
func printReport(r box.Report, host string, cached bool) {
	fmt.Printf("%s -- %s, %s\n", host, r.Server.OSName(), r.Server.State)
	if r.Server.Komizo.Installed {
		fmt.Printf("  komizo %s, agent %s\n",
			dashIfEmpty(r.Server.Komizo.Version), dashIfEmpty(r.Server.Komizo.Agent))
	}
	fmt.Println()

	// Only --cached can be stale: without it the box measures on the spot. Said
	// before anything else, because every line below is a claim about a moment
	// that may have passed -- and a stale report of a healthy box is exactly
	// what a box that died five minutes ago looks like.
	if cached && r.Stale(time.Now(), staleAfter) {
		warn("this reading is %s old -- the agent may not be running.\n"+
			"    Check with: rc-service komizo-rootd status",
			time.Since(r.At).Round(time.Second))
		fmt.Println()
	}

	if len(r.Problems) == 0 {
		note("nothing wrong that komizo can see.")
	}
	for _, p := range r.Problems {
		warn("%s", p.Detail)
	}
	if len(r.Problems) > 0 {
		fmt.Println()
	}

	if !r.Server.Ready() {
		return
	}

	if len(r.Apps) == 0 {
		fmt.Printf("No apps set up on %s yet.\n", host)
	} else {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "APP\tVERSION\tUP\tROUTES")
		for _, a := range r.Apps {
			state := fmt.Sprintf("%d/%d", a.Running(), len(a.Containers))
			if a.Stopped {
				// Said in the one column that would otherwise read as a fault.
				// Down and stopped look identical from outside the box, which is
				// the whole reason the box records the difference.
				state += " stopped"
			}
			routes := strings.Join(a.Routes(), ",")
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", a.Name, dashIfEmpty(a.Version), state, dashIfEmpty(routes))
		}
		w.Flush()
	}

	fmt.Println()
	if r.Proxy == nil {
		note("no shared reverse proxy. Apps must publish their own ports.")
	} else if r.Proxy.Running() {
		note("reverse proxy running on network %q", r.Proxy.Network)
	}

	// The resources, as one line rather than a chart. The monitor draws these
	// over time; here they are only worth the space they take when something is
	// close to full.
	s := r.System
	var parts []string
	if s.Mem != nil && s.Mem.Total > 0 {
		parts = append(parts, fmt.Sprintf("memory %s/%s", bytesText(s.Mem.Used), bytesText(s.Mem.Total)))
	}
	for _, d := range s.Disks {
		parts = append(parts, fmt.Sprintf("disk %s %s/%s", d.Mount, bytesText(d.Used), bytesText(d.Size)))
	}
	if len(parts) > 0 {
		note("%s", strings.Join(parts, ", "))
	}
}

// staleAfter is how old a cached reading may be before it is worth saying so.
//
// Three intervals rather than one. The agent writes every minute, so a report
// one interval old is the normal case and two is an unlucky moment; three means
// something actually stopped.
const staleAfter = 3 * time.Minute

func dashIfEmpty(s string) string {
	if s == "" || s == "none" {
		return "—"
	}
	return s
}

func usageReport(fs *flag.FlagSet) {
	fmt.Fprint(os.Stderr, `komizo report -- what a server says about itself

  komizo report --host root@server
  komizo report --host root@server --json

Reads the box through the komizo agent. Install one with 'komizo init'.

Flags:
`)
	fs.PrintDefaults()
}
