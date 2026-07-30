package app

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// Resources: what the box is spending, on the index page, and what a box, an
// app or a container has been spending over time, on the monitor.
//
// Split that way on purpose. The bars are a glance at the machine as a whole and
// belong beside the other facts about it -- what it runs, what proxies for it,
// what version of Docker it has. The monitor is where you go once a number on
// that glance looks wrong, and it answers with shape over time rather than more
// bars: the level is already stated on the page you came from.

// usageBar is a proportion drawn as a bar, coloured by how close to full it is.
func usageBar(frac float64, w int) string {
	if frac < 0 {
		frac = 0
	}
	// Clamped for DRAWING only -- the number beside it is printed unclamped, so
	// a filesystem somehow over its own size reads what it reads instead of
	// quietly becoming 100%.
	d := frac
	if d > 1 {
		d = 1
	}
	fill := int(d*float64(w) + 0.5)
	style := okStyle
	switch {
	case frac >= usageErr:
		style = errStyle
	case frac >= usageWarn:
		style = warnStyle
	}
	return style.Render(strings.Repeat("█", fill)) +
		dimStyle.Render(strings.Repeat("░", w-fill))
}

// usageRow is one resource: a bar, the proportion, and the absolute figures.
//
// All three, always. The proportion alone cannot tell you whether 80% is 800MB
// or 8GB, and the absolute figures alone make you do the division every time.
func usageRow(label string, frac float64, detail string) string {
	return kv(label, usageBar(frac, 20)+"  "+pad(pctText(frac), 5)+" "+dimStyle.Render(detail))
}

// serverUsage is the bars in their own block below the proxy: processor,
// memory, disk, for the whole machine and nothing smaller.
//
// One set, for the box. Per-app bars were on the monitor and are gone: three
// bars per subject is a lot of ink to say what one number could, and the
// question they answer -- "is this machine in trouble" -- is asked about the
// machine, once, at the top of the page you are already looking at.
//
// Nothing here when the box has not answered yet. An empty bar is a
// measurement, and it says the machine is idle.
func (m model) serverUsage() string {
	if !m.sysHave {
		return ""
	}
	var b strings.Builder
	s := m.sys

	if v, ok := m.nowCPU(); ok {
		cores := ""
		if s.cores > 0 {
			cores = fmt.Sprintf("%d cores", s.cores)
		}
		b.WriteString(usageRow("processor", v, cores))
	}
	if s.haveMem && s.memTotal > 0 {
		b.WriteString(usageRow("memory", float64(s.memUsed)/float64(s.memTotal),
			bytesText(s.memUsed)+" of "+bytesText(s.memTotal)))
	}
	// Every filesystem asked about, because the one that fills is usually not
	// the one being watched: images and volumes go under /var/lib/docker, and a
	// full docker filesystem stops deploys on a box whose / looks fine.
	//
	// The mount rides in the detail, after the sizes, rather than in the label:
	// the label column is sized for one word, and a path there pushed every bar
	// on the page out of line with the others.
	for _, d := range s.disks {
		detail := bytesText(d.used) + " of " + bytesText(d.size)
		if len(s.disks) > 1 {
			detail += "  " + d.mount
		}
		b.WriteString(usageRow("disk", d.frac(), detail))
	}
	return b.String()
}

// viewSystem is the resource half of the monitor: one row per resource, the
// series on the left and its how-unusual chart on the right, then the list of
// what the app is holding on disk.
//
// Two to a row, like the traffic charts above, so every row on the page has
// the same shape: the thing, then how far from normal the thing is. The
// resources with no how-unusual chart -- disk and storage -- pair with each
// other, which suits them: they are the two disk questions, easy to confuse
// and worth reading side by side.
func (m model) viewSystem() string {
	hist, sampledHere := m.resourceHistory()
	panels := m.systemPanels(hist, sampledHere)
	if len(panels) == 0 {
		return m.storageList()
	}
	var b strings.Builder
	// No "System" heading above the charts, for the same reason there is no
	// "Network" one: each panel names itself on its own line, and a section
	// title above that made two lines of heading text reading as one title split
	// in half. The blank line between the rows does the grouping.
	b.WriteString("\n")
	if note := m.provenanceNote(sampledHere); note != "" {
		b.WriteString(gutter + dimStyle.Render(cut(note, m.width-len(gutter))) + "\n")
	}
	b.WriteString(m.grid(panels, 2, chartHeight))
	b.WriteString(m.storageList())
	return b.String()
}

// systemPanels is processor, memory, and whatever "disk" means for this
// subject: the filesystems for the box, the volumes for an app.
func (m model) systemPanels(hist []sysSample, sampledHere bool) []panel {
	var out []panel

	if cpu := cpuSeries(hist, m.monitorOf, m.monitorSvc); cpu.any() {
		out = append(out, panel{
			title:  "Processor",
			scored: !sampledHere,
			// Autoscaled, not pinned to 0-100. The absolute level is stated
			// exactly, as a bar and a percentage, on the index page one keypress
			// away; what a chart adds is SHAPE, and a service that lives at 3%
			// would be a flat line along the floor of a chart drawn to 100 --
			// unreadable precisely when the question is whether it just moved.
			sub:  "% of the machine",
			draw: func(w, h int) string { return m.plainChart(cpu, w, h, keyStyle, 0) },
		})
		out = m.appendSigma(out, "Processor", cpu, sampledHere)
	}
	if mem := memSeries(hist, m.monitorOf, m.monitorSvc); mem.any() {
		out = append(out, panel{
			title:  "Memory",
			scored: !sampledHere,
			sub:    "MB",
			draw:   func(w, h int) string { return m.plainChart(mem, w, h, keyStyle, 0) },
		})
		out = m.appendSigma(out, "Memory", mem, sampledHere)
	}
	out = append(out, m.diskPanels(hist)...)
	return out
}

// appendSigma adds a resource's how-unusual chart beside it, when the history
// can support one.
//
// The box's own record only: a session-sampled history is minutes old, and a
// trailing baseline needs half an hour BEFORE each point. The value chart
// simply has no partner then, which reads as what it is.
//
// The score swings BOTH ways, like requests. A service that suddenly stops
// using processor has stalled, and memory that falls off a cliff was restarted
// or killed -- both are events, and both sit below the reference line where a
// chart that only looked up would miss them.
func (m model) appendSigma(out []panel, title string, r resSeries, sampledHere bool) []panel {
	if sampledHere {
		return out
	}
	return append(out, unusualPanel(title, func(w, h int) string {
		return m.sigmaChart(m.monitorRange.orDefault(), r.times, trailingBaseline(r.vals), w, h)
	}))
}

// diskPanels is what "disk" means for this subject.
//
// For the box, two different questions that are easy to confuse: how full the
// filesystem is, which is what kills a machine, and how much of it is the apps'
// own data, which is the part anyone can do something about. The gap between
// them is images, logs and everything else, and seeing both is how you tell
// which one is growing.
//
// For an app, only the second: an app has no filesystem of its own, just
// volumes on one it shares with everything else.
//
// Neither carries a how-unusual line. Storage creeps in one direction, so a
// trailing median sits just below every new value and a robust spread collapses
// to nearly nothing: ordinary growth would read as permanently unusual, which is
// how a colour stops meaning anything.
func (m model) diskPanels(hist []sysSample) []panel {
	var out []panel
	if m.monitorOf == "" {
		for _, mount := range mountsIn(hist) {
			r := diskSeries(hist, mount)
			if !r.any() {
				continue
			}
			out = append(out, panel{
				title: "Disk " + mount,
				sub:   "% full",
				// Pinned to 0-100 for the same reason the bar is: on a disk, the
				// distance left to the top is the entire question.
				draw: func(w, h int) string { return m.plainChart(r, w, h, keyStyle, 100) },
			})
		}
	}

	r := m.storageSeriesNow()
	if len(r.times) < 2 {
		// Four measurements an hour, so a short window can still have too few to
		// draw a line between. The list underneath gives the current figure.
		return out
	}
	scaled, unit := scaleStorage(r)
	what := "in volumes"
	if m.monitorOf == "" {
		// Every app added together, and NOT everything on the disk: images,
		// logs and the operating system are not volumes and are not in this.
		// The filesystem chart beside it is the one that counts those.
		what = "in all apps' volumes"
	} else if m.monitorSvc != "" {
		what = "in the volumes it mounts"
	}
	return append(out, panel{
		title: "Storage",
		sub:   unit + " " + what,
		draw:  func(w, h int) string { return m.plainChart(scaled, w, h, keyStyle, 0) },
	})
}

// storageSeriesNow is the rollups, plus the measurement taken when this screen
// was opened.
//
// Always from the box's own record, whatever history the other charts are using.
// Storage is measured by the sampler and by opening this screen, and by nothing
// else -- the five-second poll does not run du -- so falling back to the
// session's readings the way processor and memory do would fall back to a series
// that is always empty.
//
// Opening the monitor runs du for the app being looked at, which is a real
// measurement of the same quantity by the same means -- it is simply the newest
// one, and there is no reason to draw a chart that stops fifteen minutes ago
// while a fresher number sits in the list underneath it.
//
// Not a seam of the kind that would justify keeping them apart: this is one more
// sample of one series, not a second series at another resolution.
func (m model) storageSeriesNow() resSeries {
	r := storageSeries(m.sysLog, m.monitorOf, m.monitorSvc)
	if m.monitorOf == "" || len(m.vols) == 0 {
		return r
	}
	v, ok := volTotal(m.vols, m.monitorOf, m.monitorSvc)
	if !ok {
		return r
	}
	now := time.Now()
	if n := len(r.times); n > 0 && !r.times[n-1].Before(now) {
		return r
	}
	return resSeries{
		times: append(append([]time.Time(nil), r.times...), now),
		vals:  append(append([]float64(nil), r.vals...), float64(v)),
	}
}

// scaleStorage picks units from the numbers rather than fixing them: a chart
// labelled in MB reads 51200 on a 50GB volume, which is five digits of
// precision nobody wants and a wider y gutter than every other chart in the row.
func scaleStorage(r resSeries) (resSeries, string) {
	unit, div := "MB", float64(1024*1024)
	for _, v := range r.vals {
		if v >= 4*1024*1024*1024 {
			unit, div = "GB", float64(1024*1024*1024)
			break
		}
	}
	out := resSeries{times: r.times, vals: make([]float64, len(r.vals))}
	for i, v := range r.vals {
		out.vals[i] = v / div
	}
	return out, unit
}

// storageList is what is holding disk right now: per volume for an app, per app
// for the box.
//
// Under the charts rather than in them. A chart says which way the number is
// going; this says which volume, or which app, is the reason. Without it the
// box's storage line is a number with nothing to do about it.
func (m model) storageList() string {
	if m.monitorOf != "" {
		return section("Volumes") + m.viewStorage(m.monitorOf, m.monitorSvc)
	}
	// The box never runs du of its own -- df already covers the whole disk --
	// so this comes from the newest reading the SAMPLER measured, which is up to
	// a quarter of an hour old. An app's list is measured when the monitor
	// opens and is current; this one is not, and says so.
	rows := m.latestVols()
	if len(rows) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(section("Volumes by app"))
	seen := map[string]bool{}
	for _, r := range rows {
		if seen[r.app] {
			continue
		}
		seen[r.app] = true
		total, _ := volTotal(rows, r.app, "")
		b.WriteString(kv(r.app, bytesText(total)))
	}
	return b.String()
}

// latestVols is the most recent reading that actually measured volumes. Most
// readings did not -- du runs on a slow cadence -- so this is not simply the
// last one.
func (m model) latestVols() []volRow {
	for i := len(m.sysLog) - 1; i >= 0; i-- {
		if len(m.sysLog[i].vols) > 0 {
			return m.sysLog[i].vols
		}
	}
	return nil
}

// viewStorage is what the app is holding on disk.
//
// Volumes, and only volumes. A container's writable layer is not measured: it
// needs `docker ps -s`, which walks every layer of every image and is slow
// enough to be felt, and it should be near nothing anyway -- anything written
// outside a volume is deleted by the next deploy. If that layer is large, the
// app has a bug this screen cannot show and a data-loss problem it would not
// help with either.
//
// No bar, unlike the box's disk. There is nothing honest to draw one against:
// an app's volumes have no size of their own, only whatever is left on the
// filesystem they share with everything else.
func (m model) viewStorage(app, service string) string {
	var b strings.Builder
	total, any := volTotal(m.vols, app, service)
	if !any {
		return kv("disk", dimStyle.Render("no volumes"))
	}
	what := "in volumes"
	if service != "" {
		what = "in the volumes it mounts"
	}
	b.WriteString(kv("disk", bytesText(total)+" "+dimStyle.Render(what)))
	for _, v := range m.vols {
		if v.app != app || (service != "" && v.service != service) {
			continue
		}
		if service == "" && v.service != m.firstMounter(v) {
			// One line per volume for an app, listed under whichever container
			// mounts it first. A volume shared by two containers is one volume
			// and one number, not the same disk counted twice.
			continue
		}
		b.WriteString(kv("", dimStyle.Render(pad(v.name, 34)+" "+bytesText(v.bytes))))
	}
	return b.String()
}

func (m model) firstMounter(v volRow) string {
	for _, r := range m.vols {
		if r.app == v.app && r.name == v.name {
			return r.service
		}
	}
	return v.service
}

// nowCPU is the box's processor use for the bars on the index: the most recent
// interval there is.
//
// From the last two readings of whichever run is fresher. The session's own
// samples are five seconds apart against the sampler's minute, so they win when
// there are two of them; the sampler's are the fallback, which is what makes the
// bars appear within a second of connecting rather than after a second poll.
func (m model) nowCPU() (float64, bool) {
	if n := len(m.sysSamples); n >= 2 {
		return boxCPUAt(m.sysSamples[n-2], m.sysSamples[n-1])
	}
	if n := len(m.sysLog); n >= 2 {
		return boxCPUAt(m.sysLog[n-2], m.sysLog[n-1])
	}
	return 0, false
}

// resourceHistory is what to chart, and where it came from.
//
// The box's own record when there is one: it covers hours, it survives quitting,
// and it was written whether anything was watching or not -- the same standing
// the request charts have. What this session sampled is the FALLBACK, for a box
// set up before the sampler existed, and it is a weaker claim in every way.
//
// Not merged. The two overlap in the recent minutes at different resolutions,
// and stitching them would put a seam in the middle of the chart where the point
// spacing changes for a reason that has nothing to do with the machine.
func (m model) resourceHistory() ([]sysSample, bool) {
	if len(m.sysLog) > 1 {
		return m.sysLog, false
	}
	return m.sysSamples, true
}

// provenanceNote says who recorded what is on screen, when that is not the box.
//
// Only that. The RANGE is stated once at the top of the page and every chart
// shares it, so repeating it here would be the same sentence twice -- and where
// a record starts is already visible as the point where its line begins.
//
// This survives because it is not a fact about the window: a chart of the last
// four hours drawn from what this session happened to watch is a materially
// weaker claim than the same picture off the box's own log, and the two are
// otherwise identical on screen.
func (m model) provenanceNote(sampledHere bool) string {
	if !sampledHere {
		return ""
	}
	return "sampled by this session — update komizo on the box to keep it"
}

// plainChart is one series drawn at the times it was taken, on the page's
// shared axis -- the range being shown, not this series' own extent: a series
// that covers less of it simply stops.
func (m model) plainChart(r resSeries, w, h int, style lipgloss.Style, yMax float64) string {
	return m.seriesChart(m.monitorRange.orDefault(), r.times, r.vals, w, h, style, yMax)
}
