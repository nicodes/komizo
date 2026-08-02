package app

import (
	"encoding/json"
	"fmt"
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

// BoxBin is where init puts the agent.
const BoxBin = "/usr/local/bin/komizo-box"

// errNoAgent is a box that has not been updated yet.
//
// A distinct error because it is not a failure, it is a state -- and the only
// state with a specific thing to do about it. Anything else from that command
// is a real problem with the server.
type errNoAgent struct{ host string }

func (e errNoAgent) Error() string {
	return fmt.Sprintf("%s has no komizo agent installed.\n\n    komizo init --host %s\n\n"+
		"    That installs %s, which is what komizo reads a server through now.",
		e.host, e.host, BoxBin)
}

// runBox runs one komizo-box subcommand on the far end and decodes its output.
//
// The exit status is not consulted for "is it installed": a shell reports 127
// for a missing command, and so does a great deal else. The message is checked
// instead, and only to turn one specific failure into one specific instruction.
func runBox[T any](t target, args ...string) (T, error) {
	var zero T
	out, err := t.runCapture(BoxBin + " " + strings.Join(args, " "))
	if err != nil {
		if strings.Contains(out, "not found") || strings.Contains(err.Error(), "not found") {
			return zero, errNoAgent{host: t.host}
		}
		return zero, err
	}
	var v T
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &v); err != nil {
		return zero, fmt.Errorf("could not read what %s reported: %w", t.host, err)
	}
	return v, nil
}

// fetchReport reads the current state of a box.
func fetchReport(t target) (box.Report, error) {
	out, err := t.runCapture(BoxBin + " report")
	if err != nil {
		if strings.Contains(out, "not found") || strings.Contains(err.Error(), "not found") {
			return box.Report{}, errNoAgent{host: t.host}
		}
		return box.Report{}, err
	}
	// Decoded through the box package so the schema-version refusal happens in
	// one place, rather than each caller deciding what a newer box means.
	return box.DecodeReport([]byte(strings.TrimSpace(out)))
}

// inventoryFromReport maps a report onto the rows the screens draw.
func inventoryFromReport(r box.Report) inventory {
	var inv inventory
	inv.srv = serverRow{
		state:           r.Server.State,
		docker:          r.Server.Docker,
		os:              r.Server.OS,
		komizo:          r.Server.Komizo.Stamp,
		komizoVersion:   r.Server.Komizo.Version,
		komizoInstalled: r.Server.Komizo.Installed,
	}
	for _, k := range r.Server.HostKeys {
		inv.srv.hostKeys = append(inv.srv.hostKeys, [2]string{k.Type, k.Key})
	}

	for _, a := range r.Apps {
		row := appRow{
			name:    a.Name,
			user:    a.User,
			dir:     a.Dir,
			version: a.Version,
			running: strconv.Itoa(a.Running()),
			image:   a.ConfigImage,
			knownAs: a.KnownAs,
		}
		for _, c := range a.Containers {
			row.containers = append(row.containers, containerRow{
				app:        a.Name,
				service:    c.Service,
				name:       c.Name,
				state:      c.State,
				status:     c.Status,
				image:      c.Image,
				startedAt:  c.StartedAt,
				finishedAt: c.FinishedAt,
				exitCode:   c.ExitCode,
				ports:      joinPorts(c.Ports),
			})
		}
		for _, h := range a.Hosts {
			row.hosts = append(row.hosts, hostRow{app: a.Name, name: h.Name, service: h.Service})
		}
		// One route per app, as it has been since routing within an app moved
		// inside that app's own gate. The upstream is always <app>-gate because
		// that is what the generator writes.
		if names := a.Routes(); len(names) > 0 {
			row.routes = append(row.routes, routeRow{
				app:      a.Name,
				sites:    strings.Join(names, ","),
				upstream: a.Name + "-gate",
				port:     "80",
			})
		}
		inv.apps = append(inv.apps, row)
	}

	if r.Proxy != nil {
		inv.proxy = proxyRow{
			installed:  true,
			state:      r.Proxy.State,
			network:    r.Proxy.Network,
			image:      r.Proxy.Image,
			status:     r.Proxy.Status,
			tlsAsk:     r.Proxy.TLSAsk,
			startedAt:  r.Proxy.StartedAt,
			finishedAt: r.Proxy.FinishedAt,
		}
	}
	if r.Network != nil {
		inv.net = netRow{name: r.Network.Name, driver: r.Network.Driver, subnet: r.Network.Subnet}
		for _, m := range r.Network.Members {
			inv.net.members = append(inv.net.members, netMember{container: m.Container, aliases: m.Aliases})
		}
	}
	inv.orphans = r.Orphans
	return inv
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
			minute: r.Minute, app: r.App, service: r.Service,
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
		out.disks = append(out.disks, diskUse{mount: d.Mount, dev: d.Dev, used: d.Used, size: d.Size})
	}
	out.csIndex = make(map[string]int, len(s.Containers))
	for _, c := range s.Containers {
		cs := cgroupStat{app: c.App, service: c.Service}
		if c.CPUUsec != nil {
			cs.cpuUsec, cs.haveCPU = *c.CPUUsec, true
		}
		if c.Mem != nil {
			cs.mem, cs.haveMem = *c.Mem, true
		}
		if c.Limit != nil {
			cs.limit, cs.hasLimit = *c.Limit, true
		}
		// Last wins, matching what the record-based parser did when a box
		// reported the same container twice.
		if i, ok := out.csIndex[cs.key()]; ok {
			out.cs[i] = cs
			continue
		}
		out.csIndex[cs.key()] = len(out.cs)
		out.cs = append(out.cs, cs)
	}
	for _, v := range s.Volumes {
		out.vols = append(out.vols, volRow{app: v.App, service: v.Service, name: v.Name, bytes: v.Bytes})
	}
	return out
}

// volumesFromBox maps volume sizes onto the storage rows.
func volumesFromBox(vs []box.Volume) []volRow {
	out := make([]volRow, 0, len(vs))
	for _, v := range vs {
		out = append(out, volRow{app: v.App, service: v.Service, name: v.Name, bytes: v.Bytes})
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
