package app

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/nicodes/komizo/internal/box"
)

// Reading a box through komizo-box rather than by piping shell at it.
//
// The seam is deliberately narrow. Everything below converts a box.Report into
// the row types the interface already draws, and NOTHING else in this package
// knows the report exists. The display types stay as they are -- they have
// several thousand lines of tests behind them, and rewriting the interface was
// never part of replacing how it gets its facts.
//
// The conversion is not free and is worth the price: the report is what the box
// natively produces, and the rows are shaped by what the screens need. Merging
// them would make the wire format follow the layout, which is exactly the kind
// of coupling the version rule in internal/box exists to prevent.
//
// It is also where every string from a server is SCRUBBED, once, on the way in.
// Container names, image references and docker's status prose are all written
// by the far end, and an escape sequence in any of them can move the cursor,
// clear the screen, or write the local clipboard through OSC 52. Doing it here
// rather than at each of the several dozen places a field lands on screen is
// the whole reason this is one function: this is the boundary the values
// cross.

// BoxBin is where init puts the agent.
const BoxBin = "/usr/local/bin/komizo-box"

// errNoAgent is a box komizo has never set up.
//
// A distinct error because it is not a failure, it is a state -- and the only
// state with a specific thing to do about it. Anything else from that command
// is a real problem with the server.
type errNoAgent struct{ host string }

func (e errNoAgent) Error() string {
	return fmt.Sprintf("%s has no komizo agent installed.\n\n    komizo init --host %s\n\n"+
		"    That installs %s, which is how komizo reads a server.",
		e.host, e.host, BoxBin)
}

// askBox runs one komizo-box subcommand on the far end and returns its stdout.
//
// The EXIT CODE decides whether the agent is there. 127 is what a shell reports
// for a command it could not find, and ssh passes the remote status through
// unchanged. Matching on the message instead does not work at all: the message
// goes to the far end's stderr, so the only thing this side holds is "exit
// status 127" -- which is why that check silently never fired.
//
// Stderr is captured rather than passed through. This runs under a full-screen
// interface, and anything written to the terminal behind its back lands in the
// middle of the frame.
func askBox(t target, args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	c := exec.Command("ssh", t.sshArgs(BoxBin+" "+strings.Join(args, " "))...)
	c.Stdout, c.Stderr = &stdout, &stderr
	if err := c.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 127 {
			return nil, errNoAgent{host: t.host}
		}
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, fmt.Errorf("%s: %s", t.host, lastLine(msg))
		}
		return nil, fmt.Errorf("%s: %w", t.host, err)
	}
	return bytes.TrimSpace(stdout.Bytes()), nil
}

// lastLine is the final line of a message.
//
// A failing agent can print a page; the line that says what went wrong is the
// last one, and the rest is context nobody reads in a status bar.
func lastLine(s string) string {
	if i := strings.LastIndexByte(strings.TrimRight(s, "\n"), '\n'); i >= 0 {
		return strings.TrimSpace(s[i+1:])
	}
	return s
}

// fetchBox runs a subcommand and decodes what it said.
//
// Through box.Decode, never a bare Unmarshal, so the schema-version refusal
// happens for every document rather than only for the one somebody remembered.
func fetchBox[T box.Document](t target, args ...string) (T, error) {
	var zero T
	out, err := askBox(t, args...)
	if err != nil {
		return zero, err
	}
	v, err := box.Decode[T](out)
	if err != nil {
		return zero, fmt.Errorf("could not read what %s reported: %w", t.host, err)
	}
	return v, nil
}

// inventoryFromReport maps a report onto the rows the screens draw.
func inventoryFromReport(r box.Report) inventory {
	var inv inventory
	inv.srv = serverRow{
		state:           scrub(r.Server.State),
		docker:          scrub(r.Server.Docker),
		os:              scrub(r.Server.OS),
		komizo:          scrub(r.Server.Komizo.Stamp),
		komizoVersion:   scrub(r.Server.Komizo.Version),
		komizoInstalled: r.Server.Komizo.Installed,
	}
	for _, k := range r.Server.HostKeys {
		inv.srv.hostKeys = append(inv.srv.hostKeys, [2]string{scrub(k.Type), scrub(k.Key)})
	}

	for _, a := range r.Apps {
		row := appRow{
			name:    scrub(a.Name),
			user:    scrub(a.User),
			dir:     scrub(a.Dir),
			version: scrub(a.Version),
			running: strconv.Itoa(a.Running()),
			image:   scrub(a.ConfigImage),
			knownAs: scrubAll(a.KnownAs),
		}
		for _, c := range a.Containers {
			row.containers = append(row.containers, containerRow{
				app:        scrub(a.Name),
				service:    scrub(c.Service),
				name:       scrub(c.Name),
				state:      scrub(c.State),
				status:     scrub(c.Status),
				image:      scrub(c.Image),
				startedAt:  c.StartedAt,
				finishedAt: c.FinishedAt,
				exitCode:   c.ExitCode,
				ports:      joinPorts(c.Ports),
			})
		}
		for _, h := range a.Hosts {
			row.hosts = append(row.hosts, hostRow{app: scrub(a.Name), name: scrub(h.Name), service: scrub(h.Service)})
		}
		// One route per app, as it has been since routing within an app moved
		// inside that app's own gate. The upstream is always <app>-gate because
		// that is what the generator writes.
		if names := scrubAll(a.Routes()); len(names) > 0 {
			row.routes = append(row.routes, routeRow{
				app:      scrub(a.Name),
				sites:    strings.Join(names, ","),
				upstream: scrub(a.Name) + "-gate",
				port:     "80",
			})
		}
		inv.apps = append(inv.apps, row)
	}

	if r.Proxy != nil {
		inv.proxy = proxyRow{
			installed:  true,
			state:      scrub(r.Proxy.State),
			network:    scrub(r.Proxy.Network),
			image:      scrub(r.Proxy.Image),
			status:     scrub(r.Proxy.Status),
			tlsAsk:     scrub(r.Proxy.TLSAsk),
			startedAt:  r.Proxy.StartedAt,
			finishedAt: r.Proxy.FinishedAt,
		}
	}
	if r.Network != nil {
		inv.net = netRow{name: scrub(r.Network.Name), driver: scrub(r.Network.Driver), subnet: scrub(r.Network.Subnet)}
		for _, m := range r.Network.Members {
			inv.net.members = append(inv.net.members, netMember{container: scrub(m.Container), aliases: scrubAll(m.Aliases)})
		}
	}
	inv.orphans = scrubAll(r.Orphans)
	return inv
}

// scrubAll is scrub over a list.
func scrubAll(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = scrub(s)
	}
	return out
}

// joinPorts renders the listening ports the way the row type holds them.
func joinPorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ",")
}

// metricsFromBox maps request counts onto the chart rows.
func metricsFromBox(m box.Metrics) []metricRow {
	rows := make([]metricRow, 0, len(m.Rows))
	for _, r := range m.Rows {
		rows = append(rows, metricRow{
			minute: r.Minute, app: scrub(r.App), service: scrub(r.Service),
			c2: r.C2, c3: r.C3, c4: r.C4, c5: r.C5,
		})
	}
	return rows
}

// metricSpanFrom is how far back the access log itself reaches.
//
// Not the same as the range asked for, and the difference is what keeps the
// charts from drawing a confident zero over a stretch nobody recorded.
func metricSpanFrom(m box.Metrics) (timeRange, bool) {
	if m.Span == nil {
		return timeRange{}, false
	}
	return timeRange{from: m.Span.From, to: m.Span.To}, true
}

// sysSampleFrom maps one reading onto the resource sample the charts use.
//
// at is passed in rather than taken from the sample, because the live poll
// stamps its readings on ARRIVAL: the interval that matters for a rate is the
// one between two readings landing here, and the two clocks need not agree for
// that to be measured correctly. History passes the box's own time, which is
// the only one it has.
func sysSampleFrom(s box.System, at time.Time) sysSample {
	out := sysSample{at: at, cores: s.Cores}
	if s.CPU != nil {
		out.cpuTotal, out.cpuIdle, out.haveCPU = s.CPU.Total, s.CPU.Idle, true
	}
	if s.Mem != nil {
		out.memTotal, out.memUsed, out.haveMem = s.Mem.Total, s.Mem.Used, true
	}
	for _, d := range s.Disks {
		if d.Size == 0 {
			continue
		}
		out.disks = append(out.disks, diskUse{mount: scrub(d.Mount), dev: d.Dev, used: d.Used, size: d.Size})
	}
	out.csIndex = make(map[string]int, len(s.Containers))
	for _, c := range s.Containers {
		cs := cgroupStat{app: scrub(c.App), service: scrub(c.Service)}
		if c.CPUUsec != nil {
			cs.cpuUsec, cs.haveCPU = *c.CPUUsec, true
		}
		if c.Mem != nil {
			cs.mem, cs.haveMem = *c.Mem, true
		}
		if c.Limit != nil {
			cs.limit, cs.hasLimit = *c.Limit, true
		}
		// Last wins if a box somehow reports the same container twice. An
		// arbitrary rule, but a stated one -- the alternative is a silent
		// duplicate in every lookup that walks the list.
		if i, ok := out.csIndex[cs.key()]; ok {
			out.cs[i] = cs
			continue
		}
		out.csIndex[cs.key()] = len(out.cs)
		out.cs = append(out.cs, cs)
	}
	for _, v := range s.Volumes {
		out.vols = append(out.vols, volRow{app: scrub(v.App), service: scrub(v.Service), name: scrub(v.Name), bytes: v.Bytes})
	}
	return out
}

// volumesFromBox maps volume sizes onto the storage rows.
func volumesFromBox(vs []box.Volume) []volRow {
	out := make([]volRow, 0, len(vs))
	for _, v := range vs {
		out = append(out, volRow{app: scrub(v.App), service: scrub(v.Service), name: scrub(v.Name), bytes: v.Bytes})
	}
	return out
}

// samplesFrom maps the history log onto the series the charts are drawn from.
func samplesFrom(ss []box.Sample) []sysSample {
	out := make([]sysSample, 0, len(ss))
	for _, s := range ss {
		out = append(out, sysSampleFrom(s.System, s.At))
	}
	return out
}
