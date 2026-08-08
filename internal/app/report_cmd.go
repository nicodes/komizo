package app

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nicodes/komizo/box"
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
	var acceptHostKey, asJSON, cached, volumes, usage, knownHosts bool
	fs.StringVar(&host, "host", "", "server to read, [user@]HOST")
	fs.IntVar(&port, "port", 22, "SSH port")
	fs.BoolVar(&acceptHostKey, "accept-host-key", false, "trust an unseen server's host key (trust-on-first-use)")
	fs.BoolVar(&asJSON, "json", false, "print the report as the box produced it")
	fs.BoolVar(&cached, "cached", false, "print the last report the agent wrote, rather than measuring now")
	// THREE CLASSES OF INFORMATION THE INTERFACE HAD AND NO COMMAND DID.
	//
	// Review 1 on nicodes/komizo-be#55 found them by walking the deleted
	// screens rather than the diff: an app's volume sizes, whether the box is
	// busy, and how many requests each app served and how many failed. The
	// decoders for all three survived -- volumesFromBox, samplesFrom,
	// metricsFromBox -- and became unreachable, which is why the source still
	// looked like it could answer.
	//
	// Behind flags rather than always, because each costs something the plain
	// report does not: --volumes walks every volume on the box, and --usage is
	// a second call over the same connection.
	fs.BoolVar(&volumes, "volumes", false, "also measure volume sizes (slow: walks every volume)")
	fs.BoolVar(&usage, "usage", false, "also read the last hours' processor use and request counts")
	// READING IT MUST NOT COST A KEY ROTATION, which is what it did.
	//
	// Review 1 on nicodes/komizo-be#55: the interface copied this value for the
	// selected app and touched nothing. Afterwards formatKnownHosts was
	// reachable only from `komizo add`, so somebody who lost the secret had to
	// re-provision the app to get it back -- and that reissued the deploy key.
	// --json gave server.host_keys, which is the ingredients rather than the
	// value CI pins, and is not scoped to the app's own names.
	fs.BoolVar(&knownHosts, "known-hosts", false, "print the KOMIZO_KNOWN_HOSTS value each app's CI pins")
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
	if volumes {
		args2 = append(args2, "--volumes")
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

	if knownHosts {
		printKnownHosts(r, tgt)
	}

	// A SECOND CALL, AND ONLY WHEN ASKED. The counts and the past readings are
	// not in the report -- the box keeps them in its history and its access log
	// -- so this is `komizo-box monitor`, which returns both in one document.
	//
	// A failure here does NOT fail the command: everything above it is already
	// on the screen and is the answer to "is this server all right". A box too
	// old to have the mode, or one whose history has not been written yet, must
	// not turn a working report into an error.
	if usage {
		if err := printUsage(tgt); err != nil {
			warn("could not read this box's usage: %v", err)
		}
	}
	return nil
}

// printKnownHosts is the secret each repo pins, per app.
//
// PER APP rather than per box, because known_hosts matches the exact string the
// client dialled: each repo dials one name, so the value it pins should name
// that one and not every name every app on this box answers to.
func printKnownHosts(r box.Report, tgt target) {
	keys := make([][2]string, 0, len(r.Server.HostKeys))
	for _, k := range r.Server.HostKeys {
		keys = append(keys, [2]string{scrub(k.Type), scrub(k.Key)})
	}
	if len(keys) == 0 {
		warn("this box reported no host keys, so there is no value to pin.")
		return
	}
	for _, a := range r.Apps {
		step("KOMIZO_KNOWN_HOSTS for %s", a.Name)
		fmt.Println(formatKnownHosts(tgt.namedFor(a.KnownAs), keys))
	}
	if len(r.Apps) == 0 {
		note("no apps on this box, so nothing pins a known_hosts value yet.")
	}
}

// printUsage is what the box has been doing, as opposed to what it is.
//
// THE WINDOW IS defaultWindow, which is what makes that constant load-bearing
// again rather than a leftover -- Review 1's non-blocking (b) was right that
// nothing resolved a range after the interface went.
func printUsage(tgt target) error {
	now := time.Now()
	from := now.Add(-time.Duration(defaultWindow) * time.Minute).Unix()
	m, err := fetchBox[box.Monitor](tgt, "monitor",
		"--from", strconv.FormatInt(from, 10),
		"--to", strconv.FormatInt(now.Unix(), 10))
	if err != nil {
		return err
	}

	fmt.Println()
	// THE PROCESSOR NEEDS TWO READINGS AND THERE IS NO OTHER WAY TO GET ONE.
	// System.CPU is cumulative jiffies, so a single reading is a total since
	// boot rather than a rate -- which is why this asks for history at all and
	// why "the report already has System" was not the answer.
	samples := samplesFrom(m.History)
	if len(samples) >= 2 {
		if v, ok := boxCPUAt(samples[len(samples)-2], samples[len(samples)-1]); ok {
			note("processor %s over the last %s", pctText(v),
				durText(samples[len(samples)-1].at.Sub(samples[len(samples)-2].at)))
		}
	} else {
		note("not enough readings yet to say whether this box is busy.")
	}

	rows := metricsFromBox(m.Metrics)
	span, haveSpan := metricSpanFrom(m.Metrics)
	if len(rows) == 0 {
		if haveSpan {
			note("no requests recorded between %s and %s.",
				stampText(time.Unix(span.from, 0), now), stampText(time.Unix(span.to, 0), now))
		} else {
			// SAID APART from "nothing was served". A box whose proxy keeps no
			// access log for a route answers exactly the same as a box nobody
			// asked for anything, and the two want different actions.
			note("this box has no request record to read.")
		}
		return nil
	}

	// PER APP, and failures separately. "Is anything reaching this" and "is any
	// of it failing" are different questions and one total answers neither.
	fmt.Println()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "APP\tREQUESTS\t5XX")
	for _, name := range appsIn(rows) {
		s := seriesFor(rows, name, from, now.Unix())
		fmt.Fprintf(w, "%s\t%d\t%d\n", name, sum(s.total), sum(s.errors))
	}
	w.Flush()
	return nil
}

// appsIn is every app the counts name, in a stable order.
func appsIn(rows []metricRow) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rows {
		if r.app == "" || seen[r.app] {
			continue
		}
		seen[r.app] = true
		out = append(out, r.app)
	}
	sort.Strings(out)
	return out
}

func sum(v []float64) int {
	t := 0.0
	for _, x := range v {
		t += x
	}
	return int(t)
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
	// WHETHER THAT VERSION IS BEHIND THIS ONE, which is a different question
	// from what it is and the only one anybody acts on.
	//
	// The interface answered it and this command did not: it printed the box's
	// version and left the comparison to the reader, who would have to know
	// what this komizo's own version is to make it. Deleting the interface
	// (nicodes/komizo-be#55) without moving this would have deleted the answer,
	// which is exactly what the parity rule forbids -- the CLI can do
	// everything, and "everything" includes the things only the interface knew.
	if s, remedy := agentBehind(r.Server.Komizo, host); s != "" {
		warn("%s\n\n    %s", s, remedy)
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

	// AND THE VOLUMES, when the box was asked to measure them.
	//
	// Only present on a --volumes run: measuring costs a walk of every volume
	// on the box, so the plain report does not pay for it. Absent is therefore
	// "not asked", not "none" -- and printing a zero here would say the second
	// about a box that was never asked the first.
	if len(s.Volumes) > 0 {
		fmt.Println()
		rows := volumesFromBox(s.Volumes)
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "APP\tVOLUMES")
		for _, a := range r.Apps {
			// SHARED VOLUMES COUNTED ONCE. Two services of one app mounting the
			// same volume is one volume; volTotal de-duplicates by name, which
			// is why this asks it rather than summing the rows.
			if n, ok := volTotal(rows, a.Name, ""); ok {
				fmt.Fprintf(w, "%s\t%s\n", a.Name, bytesText(n))
			}
		}
		w.Flush()
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

// agentBehind is whether running `komizo update` against this box would change
// anything on it, and what to run if so. An empty first return means the box is
// current, and nothing is printed at all.
//
// EITHER SIGNAL IS ENOUGH, and each catches what the other misses:
//
//   - a different content STAMP means the agent this komizo would write differs
//     from the one on the box. The version alone misses this the whole time a
//     build calls itself "dev".
//   - a different release VERSION means something else komizo installs changed
//     between releases -- a script, a doas rule, a service file. The stamp
//     alone misses that whenever the changed thing is not the agent.
//
// Ported from the interface's server row, where it was three cases of a
// styled-string switch. The rules are unchanged; what they produce is a
// sentence rather than a colour and a keystroke.
func agentBehind(k box.KomizoInstall, host string) (string, string) {
	update := "komizo update --host " + host
	switch {
	case !k.Installed:
		return "no komizo agent on this box.", "komizo init --host " + host
	case k.Version == "":
		// Installed by a komizo old enough to have recorded only a stamp. There
		// is nothing to compare, and the update is what starts recording a
		// version -- so it is always worth running. The raw stamp is NOT shown
		// in its place: it is not a version and reads as noise to anyone
		// deciding whether they are behind.
		return "this box records no komizo version, so it was set up by an older one.", update
	case k.Stamp != komizoStamp():
		return "the agent on this box differs from the one this komizo installs.", update
	case k.Version != versionText():
		return fmt.Sprintf("this box was set up by komizo %s; this is %s.",
			k.Version, versionText()), update
	}
	return "", ""
}
