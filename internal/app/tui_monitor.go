package app

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/NimbleMarkets/ntcharts/linechart/timeserieslinechart"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/nicodes/komizo/box"
)

// The one screen that shows a MEASUREMENT rather than a fact.
//
// Everything else in this interface is something you could check by hand: this
// container is running, that hostname is claimed, this port is bound. A request
// rate is none of those. It has a sampling window, gaps where nobody looked, and
// a most-recent bucket that is always incomplete -- so the numbers here are
// hedged in ways the rest of the app never needs to be, and the code says so
// where it does the hedging.

// chartWindow is how far back the monitor screen asks for. The index page's
// sparklines use a shorter one: they ride on the inventory poll, which runs
// every five seconds, and reading four hours of log that often is a waste of the
// box's CPU to move a line by one column.
const (
	chartWindow  = 4 * 60 // minutes
	sparkWindow  = 30     // minutes
	sparkColumns = 16

	// One chart height for the whole page. Braille packs four dots to a cell
	// vertically, so a short chart has very few steps to place a window's
	// range in -- enough to draw a line, not enough to see its shape. These
	// are the thing the screen is for; the page scrolls if they do not fit,
	// which is the frame's job.
	//
	// Twelve is LOAD-BEARING for the how-unusual charts: two rows go to the
	// axis and its labels, and the ten left over span the ten deviations of
	// the sigma axis -- one row per deviation, so every y label is exact.
	// ntcharts labels a row with the value at its top edge, and any height
	// that does not divide the range evenly rounds those labels into small
	// lies: at fourteen rows the zero line sat on a row labelled 1.
	chartHeight = 12

	// How far out the deviation charts draw before clamping, and the top of
	// their axis. Beyond this the exact number stops mattering: five robust
	// deviations from normal is "look at this", and so is forty -- and the
	// first failure after a clean window, which is off the scale rather than
	// on it, draws at the very top for exactly that reason.
	devLimit = 5
)

// openMonitor is the same shape as openLogs: reset, mark not-ready, start the
// fetch, and start the spinner only if one is not already running.
func (m model) openMonitor(app, service string) (tea.Model, tea.Cmd) {
	cmd := m.withSpin(func() {
		m.monitorOf, m.monitorSvc, m.monitorReady, m.monitor = app, service, false, nil
		m.scroll = 0
		m.status, m.statusErr = "", false
		m.scr = screenMonitor
	}, fetchMonitor(m.tgt, app, m.monitorRange.orDefault()))
	return m, cmd
}

type monitorMsg struct {
	app  string
	rows []metricRow
	vols []volRow
	// span is how far back the access log itself reaches, which is not the same
	// as the range asked for.
	span    timeRange
	hasSpan bool
	// hist is the readings the agent has written. Empty on a box that has only just
	// been set up, which the view falls back from rather than treats as an
	// error.
	hist []sysSample
	err  error
}

func fetchMonitor(t target, app string, r timeRange) tea.Cmd {
	return func() tea.Msg {
		args := []string{"monitor",
			"--from", strconv.FormatInt(r.from, 10),
			"--to", strconv.FormatInt(r.to, 10)}
		// Disk is measured for ONE app, here, rather than for every app on the
		// poll: it costs a walk of every volume the app mounts, which is the
		// only number on this screen that cannot be read from a counter.
		//
		// The box itself is not walked at all -- statfs already covers the whole
		// disk, and walking every volume to arrive at a smaller version of a
		// number the kernel hands over instantly would be work done to be less
		// accurate.
		if app != "" {
			args = append(args, "--app", app)
		}
		mon, err := fetchBox[box.Monitor](t, args...)
		if err != nil {
			return monitorMsg{app: app, err: err}
		}
		span, hasSpan := metricSpanFrom(mon.Metrics)
		return monitorMsg{app: app, rows: metricsFromBox(mon.Metrics), vols: volumesFromBox(mon.Volumes),
			hist: samplesFrom(mon.History), span: span, hasSpan: hasSpan}
	}
}

func (m model) handleMonitorKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q":
		return m, tea.Quit
	case "esc":
		m.scr = screenIndex
		m.status, m.statusErr = "", false
		return m, nil

	// The same keys the log window answers to: the page is taller than a
	// terminal -- five rows of charts -- and a page you cannot scroll shows
	// whichever charts happen to fit.
	case "up":
		m.scroll--
	case "down":
		m.scroll++
	case "shift+up":
		m.scroll = 0
	case "shift+down":
		m.scroll = m.maxScroll()

	case "l":
		return m.openSubjectLogs()
	case "r":
		return m.openMonitor(m.monitorOf, m.monitorSvc)
	case "t":
		return m.ask(m.rangePrompt()), nil
	}
	// Unclamped here, like the log window: Update clamps it on the way out,
	// against a viewport this keypress may have just changed the height of.
	return m, nil
}

// openSubjectLogs is the log of what the monitor is looking at, so a shape in
// a chart and the lines behind it are one keypress apart rather than a trip
// back through the list.
//
// For the box that is the proxy's log: it is where this page's box-wide
// numbers come from, and the only box-wide log there is. A box with no proxy
// has no such log, and the key does nothing rather than fetch a log for a
// container that does not exist.
func (m model) openSubjectLogs() (tea.Model, tea.Cmd) {
	switch {
	case m.monitorOf == "":
		if !m.proxy.installed {
			return m, nil
		}
		return m.openLogs(proxyContainer, "proxy", "", "", containerLogCmd(proxyContainer))
	case m.monitorSvc == "":
		for _, a := range m.apps {
			if a.name == m.monitorOf {
				return m.openLogs("app:"+a.name, a.name, a.name, "", stackLogCmd(a))
			}
		}
	default:
		for _, a := range m.apps {
			if a.name != m.monitorOf {
				continue
			}
			for _, c := range a.containers {
				if c.service == m.monitorSvc {
					return m.openLogs(c.name, c.service, c.app, c.service, containerLogCmd(c.name))
				}
			}
		}
	}
	// The subject has left the inventory since this screen opened. Nothing to
	// fetch, and the page itself already shows what is going on.
	return m, nil
}

// rangePrompt is what the charts are looking at, edited in place.
//
// One field rather than two. A start and an end are one thought -- "yesterday
// afternoon" -- and splitting them across two inputs makes you tab between
// halves of it. It is also what you would say out loud: "-2h", "14:00..16:00".
//
// Prefilled with the current range, for the same reason the config image is:
// editing in place means you can see what you are changing it from.
func (m model) rangePrompt() prompt {
	now := time.Now()
	return prompt{
		kind:     promptInput,
		question: "Show which range?",
		detail: "An offset like -2h, or start..end. " +
			"Times are yours: 14:00, or 2006-01-02 14:00. Empty resets it.",
		typed: rangeText(m.monitorRange, now),
		check: func(v string) error {
			_, err := parseRange(v, time.Now())
			return err
		},
		action: func(m *model, v string) tea.Cmd {
			r, err := parseRange(v, time.Now())
			if err != nil {
				// check has already rejected this; belt and braces so a future
				// caller cannot set a range nothing validated.
				m.status, m.statusErr = err.Error(), true
				return nil
			}
			m.monitorRange = r
			return m.reopenMonitor()
		},
	}
}

// reopenMonitor refetches for the range now set, without moving anything else.
func (m *model) reopenMonitor() tea.Cmd {
	return m.withSpin(func() {
		m.monitorReady, m.monitor, m.sysLog = false, nil, nil
		m.scroll = 0
	}, fetchMonitor(m.tgt, m.monitorOf, m.monitorRange.orDefault()))
}

func (m model) monitorKeys() string {
	keys := []string{"↑↓", "scroll", "shift+↑↓", "ends"}
	// The log key is only offered when pressing it would open one: the box's
	// log is the proxy's, and a box with no proxy has nothing to show.
	if m.monitorOf != "" || m.proxy.installed {
		keys = append(keys, "l", "logs")
	}
	keys = append(keys, "t", "range", "r", "refresh")
	keys = append(keys, m.selectKey()...)
	return helpLine(m.width, append(keys, "esc", "back", "q", "quit")...)
}

// sparkFor is the little chart on an app's row: the last half hour of requests,
// with no axis and no scale. It says "busy, quiet, or something changed" and
// nothing more precise, which is all a single row has space to mean.
func (m model) sparkFor(app string) string {
	return spark(m.window(app, ""))
}

// window is the last half hour for a subject, which is what a row has room to
// mean. Always relative to now, whatever range the monitor is showing.
func (m model) window(app, service string) series {
	now := time.Now().Unix()
	if service == "" {
		return seriesFor(m.metrics, app, now-sparkWindow*60, now)
	}
	return seriesForService(m.metrics, app, service, now-sparkWindow*60, now)
}

// spark is the little chart itself: one strip carrying both questions. Each
// minute is a column whose height is every request it served, drawn blue with
// the 5xx share stacked red on top -- blue under red, so the eye reads "how
// busy" along the strip and "is any of it failing" as red arriving at the top.
//
// A terminal cell is one glyph in one foreground on one background, and the
// stack is built from exactly that: a clean minute is a blue block, a minute
// of nothing but failures is a red one, and a mixed minute draws its
// successful share as a blue block against a red background. In that last
// case the red reads to the top of the cell rather than to the bar's own
// height -- overstated on purpose, because the alternative was not drawing the
// stack at all in a one-cell-tall strip. Red still only ever appears on a
// minute in which something actually failed.
//
// Zeros draw the floor: a dim one-eighth baseline, so a quiet minute reads as
// part of one connected strip rather than a hole in it. The dots are the
// "nothing was measured" state, only used when nothing reached the app at all.
func spark(s series) string {
	if !s.any() {
		return dimStyle.Render(strings.Repeat("·", sparkColumns))
	}
	tot := bucketTo(s.total, sparkColumns)
	errs := bucketTo(s.errors, sparkColumns)
	var top float64
	for _, v := range tot {
		if v > top {
			top = v
		}
	}
	var b strings.Builder
	for i, t := range tot {
		g, style := sparkCell(t, errs[i], top)
		b.WriteString(style.Render(g))
	}
	return b.String()
}

// sparkCell is one minute of the strip: which block, in which colouring. Split
// from spark so the stacking arithmetic is testable without reading colours
// back out of a rendered string.
func sparkCell(t, e, top float64) (string, lipgloss.Style) {
	blocks := []rune("▁▂▃▄▅▆▇█")
	if !(t > 0) || top <= 0 {
		// A measured minute with nothing in it draws the FLOOR, not a hole: a
		// blank cell between bars read as a gap in the record, and a mostly
		// quiet strip fell apart into disjointed stubs. Dim, so it reads as
		// the line the bars stand on rather than as a bar -- this only ever
		// draws inside a window that measured something, where zero is a real
		// measurement. "Nothing measured at all" is still dots, and a
		// container nobody can measure is still blank.
		return "▁", dimStyle
	}
	// Ceil, so one request in a busy window is a sliver rather than nothing.
	h := int(math.Ceil(t / top * 8))
	var r int
	if e > 0 {
		// At least one eighth of red for any failure at all -- the strip
		// exists to make failures visible, and rounding one away would hide it
		// exactly where it is rarest. A blue base survives when anything
		// succeeded, except in a one-eighth column, where the failure is the
		// news.
		r = int(math.Round(e / t * float64(h)))
		if r < 1 {
			r = 1
		}
		if r > h {
			r = h
		}
		if e < t && r == h && h > 1 {
			r = h - 1
		}
	}
	switch blue := h - r; {
	case r == 0:
		return string(blocks[h-1]), barStyle
	case blue == 0:
		return string(blocks[h-1]), errStyle
	default:
		return string(blocks[blue-1]), stackedStyle
	}
}

// sparkForService is the same little chart for one container.
//
// Three states, not two, and the third is the reason this is a separate
// function. An app either has traffic or has not; a container can also be
// UNMEASURABLE -- the shared proxy only ever talks to the app's gate, and
// which container answered is decided inside the app, so komizo knows only what
// the app declared in its hostnames file.
//
// A container nobody named there gets an empty cell. Dots would say "measured,
// nothing arrived", which is a claim about the container; blank says nothing,
// which is all that is known. The monitor page explains it in words when you
// press m on the row.
func (m model) sparkForService(app, service string) string {
	if !servesAnyHostname(m.metrics, app, service) {
		return ""
	}
	return spark(m.window(app, service))
}

// bucketTo averages a series down to n points.
//
// Averaged rather than sampled. Picking every kth minute drops the spike that is
// the entire reason anyone looked at this, and does it silently -- a chart that
// is wrong only when something is wrong.
func bucketTo(v []float64, n int) []float64 {
	if len(v) == 0 || n <= 0 {
		return nil
	}
	if len(v) <= n {
		return v
	}
	out := make([]float64, n)
	for i := range out {
		a := i * len(v) / n
		b := (i + 1) * len(v) / n
		if b <= a {
			b = a + 1
		}
		var sum float64
		for _, x := range v[a:min(b, len(v))] {
			sum += x
		}
		out[i] = sum / float64(b-a)
	}
	return out
}

// viewMonitor is the whole page: what is being asked of this thing, then what
// it is spending, laid out as a grid.
//
// Traffic on top. It is what the page is named for and what people open it to
// see; the resources under it are what explains a shape in it.
func (m model) viewMonitor() string {
	if !m.monitorReady {
		return m.loadingPane()
	}
	var b strings.Builder
	b.WriteString(m.rangeLine())
	// No "Network" heading above the charts. Each panel already names itself on
	// its own line, and a section title above that made two lines of heading
	// text that read as one title split in half -- "Network" then "Requests".
	// The blank line between the rows does the grouping a heading was doing.
	b.WriteString("\n")
	if net := m.networkPanels(); len(net) > 0 {
		b.WriteString(m.grid(net, 2, chartHeight))
	} else {
		b.WriteString(m.noTrafficNote())
	}
	b.WriteString(m.viewSystem())
	return b.String()
}

// rangeLine is what the page is showing, once, at the top.
//
// Once rather than per section: it governs every chart below it, and repeating
// it over each would be the same sentence three times. It leads the page because
// every number under it is meaningless without it -- "30/min" and "0 failures"
// are answers to a question that includes when.
//
// It does not report where the records begin. Every chart shares this axis and
// simply stops drawing where its own data does, which says the same thing in the
// place you are already looking.
func (m model) rangeLine() string {
	return gutter + dimStyle.Render(cut(
		"showing "+rangeText(m.monitorRange, time.Now()), m.width-len(gutter))) + "\n"
}

// noTrafficNote is why there is no traffic chart, which is a different
// statement from an empty one and has to be made in words.
func (m model) noTrafficNote() string {
	if m.monitorSvc != "" && !servesAnyHostname(m.monitor, m.monitorOf, m.monitorSvc) {
		return kv("", dimStyle.Render("no hostname declares "+m.monitorSvc)) +
			kv("", dimStyle.Render("requests reach this app's gate and are routed inside it;")) +
			kv("", dimStyle.Render("the shared proxy cannot see which container served them")) +
			kv("", dimStyle.Render("name it in deploy/hostnames to chart it:  api.example.com -> "+m.monitorSvc))
	}
	what := "this app"
	if m.monitorOf == "" {
		what = "this box"
	}
	return kv("", dimStyle.Render("nothing to "+what+" in "+
		rangeText(m.monitorRange, time.Now())))
}

// networkPanels is requests and failures -- each a row of two charts, the
// series and its how-unusual partner -- or nothing at all when there is no
// traffic to draw, which the caller says in words instead.
func (m model) networkPanels() []panel {
	// The full range, on every chart. Data that does not exist is not plotted;
	// the axis is not moved to fit it.
	r := m.monitorRange.orDefault()
	var s series
	switch {
	case m.monitorOf == "":
		// The whole box: every app added together. Not every request -- traffic
		// matching no app is counted for nobody and is missing here too.
		s = seriesForBox(m.monitor, r.from, r.to)
	case m.monitorSvc == "":
		s = seriesFor(m.monitor, m.monitorOf, r.from, r.to)
	default:
		// A container nobody pointed a hostname at is not idle -- it is
		// unmeasurable from here, and a chart of zeros would say the first
		// thing while meaning the second.
		if !servesAnyHostname(m.monitor, m.monitorOf, m.monitorSvc) {
			return nil
		}
		s = seriesForService(m.monitor, m.monitorOf, m.monitorSvc, r.from, r.to)
	}
	if !s.any() {
		return nil
	}
	// Minutes the access log does not reach are unknown rather than zero. It is
	// rotated by size, so a range wider than it holds is answered with what
	// exists -- and the rest is left unplotted rather than drawn along the floor.
	if m.hasSpan {
		s.blankOutside(m.span)
	}
	times := minuteTimes(s.from, len(s.total))
	return []panel{{
		title:  "Requests",
		scored: true,
		sub:    "req/min",
		draw: func(w, h int) string {
			return m.seriesChart(r, times, s.total, w, h, keyStyle, 0)
		},
	}, unusualPanel("Requests", func(w, h int) string {
		return m.sigmaChart(r, times, trailingBaseline(s.total), w, h)
	}), {
		title:  "Failures (5xx)",
		scored: true,
		sub:    "5xx/min",
		draw: func(w, h int) string {
			return m.seriesChart(r, times, s.errors, w, h, keyStyle, 0)
		},
	}, unusualPanel("Failures", func(w, h int) string {
		return m.sigmaChart(r, times, trailingPoisson(s.errors), w, h)
	})}
}

// seriesChart draws one series and nothing else. Its how-unusual chart sits
// beside it on the same row -- the two used to share a canvas, and two lines
// in different units crossing each other read as a relationship they do not
// have.
func (m model) seriesChart(axis timeRange, times []time.Time, vals []float64, w, h int, style lipgloss.Style, fixedMax float64) string {
	if len(times) == 0 {
		return ""
	}
	yMax := fixedMax
	if yMax == 0 {
		for _, v := range vals {
			if !math.IsNaN(v) && v > yMax {
				yMax = v
			}
		}
	}
	if yMax == 0 {
		yMax = 1
	}
	// The axis is the range the page is showing, NOT the extent of this series.
	// Charts of the same moment on different axes is a page you cannot read
	// across, and reading across is why they are on one screen.
	from, to := axis.from, axis.to
	if to <= from {
		to = from + 1
	}
	c := m.newChart(from, to, w, h)
	c.SetYRange(0, yMax)
	c.SetViewYRange(0, yMax)
	c.SetDataSetStyle("series", style)
	for i, v := range vals {
		// A reading that could not be taken is skipped, not drawn. Zero would be
		// a measurement: a dive to the floor, which is what a dead service looks
		// like. The line bridges the gap instead, which claims less.
		if !math.IsNaN(v) {
			c.PushDataSet("series", timeserieslinechart.TimePoint{Time: times[i], Value: v})
		}
	}
	c.DrawBrailleAll()
	return c.View()
}

// sigmaChart is how unusual each point of a series was, on its own canvas to
// the right of the series it scores: a flat dim line where "not unusual" is,
// and the score lifting off it by however far past ordinary the minute went.
//
// Its y axis is deviations, -5 to +5, one chart row per deviation -- see
// chartHeight, which is what makes that arithmetic hold. It has to hold
// EXACTLY: ntcharts labels a row with the value at its top edge, and a range
// that does not divide the rows evenly rounds the labels into small lies --
// an earlier height put the zero line on a row labelled 1, which is worse
// than no label, because it will be believed.
func (m model) sigmaChart(axis timeRange, times []time.Time, base baseline, w, h int) string {
	if len(times) == 0 {
		return ""
	}
	from, to := axis.from, axis.to
	if to <= from {
		to = from + 1
	}
	// Drawn from the quietened score, not the raw one. See quietened: the raw
	// series is correct and reads as noise, because ordinary jitter is about
	// one deviation wide on traffic like this.
	score := quietened(base.score)

	c := m.newChart(from, to, w, h)
	c.SetYRange(-devLimit, devLimit)
	c.SetViewYRange(-devLimit, devLimit)
	c.SetDataSetStyle("normal", dimStyle)

	// Where "not unusual" sits, so the score has a zero to be read against.
	// Without it the line is a shape with no origin. Drawn across the SCORED
	// stretch, not across the axis: the axis is the range the page is showing,
	// and a reference ruled across minutes nothing scored would be the one
	// thing plotted where there is nothing to plot.
	if a, b, ok := extent(score); ok {
		c.PushDataSet("normal", timeserieslinechart.TimePoint{Time: times[a], Value: 0})
		c.PushDataSet("normal", timeserieslinechart.TimePoint{Time: times[b], Value: 0})
	}

	// Each contiguous SCORED stretch is its own data set, numbered as it
	// starts. ntcharts joins every point in a set to the point pushed after
	// it, whatever lies between -- so one set for the whole line would rule a
	// bridge straight across any unscored gap in it.
	run, runs := "", 0
	for i, d := range score {
		if math.IsNaN(d) {
			// No baseline yet, or a flat one with no scale. Skipped rather than
			// drawn at zero: "we cannot say" and "exactly normal" are different
			// statements and must not share a shape. And the line BREAKS here:
			// bridging would rule a line across a stretch this very point says
			// nothing can be said about.
			run = ""
			continue
		}
		if d > devLimit {
			d = devLimit
		} else if d < -devLimit {
			d = -devLimit
		}
		if run == "" {
			runs++
			run = fmt.Sprintf("unusual.%03d", runs)
			c.SetDataSetStyle(run, okStyle)
		}
		c.PushDataSet(run, timeserieslinechart.TimePoint{Time: times[i], Value: d})
	}
	c.DrawBrailleAll()
	return c.View()
}

// unusualPanel is the how-unusual chart's panel, beside the chart it scores
// and named after it: "Requests σ" says which series and what kind of chart
// in two words. A generic "how unusual" on all four said only the second, and
// left the first to be inferred from position -- which holds on a wide
// terminal and stops holding the moment the pairs zip into one column.
func unusualPanel(of string, draw func(w, h int) string) panel {
	return panel{title: of + " σ", sub: "deviations from normal", draw: draw}
}

func (m model) newChart(from, to int64, w, h int, extra ...timeserieslinechart.Option) timeserieslinechart.Model {
	opts := []timeserieslinechart.Option{
		timeserieslinechart.WithTimeRange(time.Unix(from, 0), time.Unix(to, 0)),
		// Seconds on a short window. The session fallback covers minutes, and
		// every label on it read as the same "17:16" -- an axis saying nothing
		// about where along it you are.
		timeserieslinechart.WithXLabelFormatter(func(_ int, v float64) string {
			if to-from < 30*60 {
				return time.Unix(int64(v), 0).Format("15:04:05")
			}
			return time.Unix(int64(v), 0).Format("15:04")
		}),
		// Fixed width, so every chart on this screen shares an x axis. ntcharts
		// sizes the y gutter to its widest label, so a panel peaking at 4 would
		// be drawn one column left of one peaking at 122 -- and axes that do not
		// line up are charts you cannot read against each other, which is the
		// only reason they are stacked.
		timeserieslinechart.WithYLabelFormatter(func(_ int, v float64) string {
			return fmt.Sprintf("%4.0f", v)
		}),
	}
	return timeserieslinechart.New(w, h, append(opts, extra...)...)
}

// extent is the first and last index that carry a value, so a reference line
// can be drawn across the data rather than across the window.
func extent(vals []float64) (int, int, bool) {
	first, last := -1, -1
	for i, v := range vals {
		if math.IsNaN(v) {
			continue
		}
		if first < 0 {
			first = i
		}
		last = i
	}
	return first, last, first >= 0 && last > first
}

// minuteTimes is the timestamps a per-minute series sits on. The request counts
// are bucketed by the host and arrive as an array; everything charted here
// carries its own times, so they are reconstructed once at the edge rather than
// assumed all the way down.
func minuteTimes(from int64, n int) []time.Time {
	out := make([]time.Time, n)
	for i := range out {
		out[i] = time.Unix(from+int64(i)*60, 0)
	}
	return out
}
