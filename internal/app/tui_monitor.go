package app

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/NimbleMarkets/ntcharts/linechart/timeserieslinechart"
	"github.com/NimbleMarkets/ntcharts/sparkline"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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

	// Braille packs four dots to a cell vertically, so a seven-row chart had
	// twenty-eight steps to place a whole day's range in -- enough to draw a
	// line, not enough to see its shape. These are the thing the screen is for;
	// the page scrolls if they do not fit, which is the frame's job.
	// Chart heights. Braille packs four dots to a cell vertically, so a short
	// chart has very few steps to place a whole window's range in -- enough to
	// draw a line, not enough to see its shape.
	//
	// Traffic gets more of the page than resources: it is what the screen is
	// named for, and there are two of those charts against three of the others.
	netPanelHeight = 14
	sysChartHeight = 11

	// How far out the deviation panel draws before clamping. Beyond this the
	// exact number stops mattering: four robust deviations from normal is
	// "look at this", and so is forty.
	devLimit = 4
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
	// hist is the readings the sampler wrote. Empty on a box whose server setup
	// predates the sampler, which the view falls back from rather than treats
	// as an error.
	hist []sysSample
	err  error
}

func fetchMonitor(t target, app string, r timeRange) tea.Cmd {
	return func() tea.Msg {
		script := metricsScript(r) + "\n" + systemLogScript(r)
		// Disk is measured for ONE app, here, rather than for every app on the
		// poll: it costs a du of every volume the app mounts, which is the only
		// number on this screen that cannot be read from a counter.
		//
		// The box has no du at all -- df already covers the whole disk, and
		// walking every volume to arrive at a smaller version of a number the
		// kernel hands over instantly would be work done to be less accurate.
		if app != "" {
			script += "\n" + storageScript(app)
		}
		out, err := t.runCapture(script)
		if err != nil {
			return monitorMsg{app: app, err: err}
		}
		span, hasSpan := parseMetricSpan(out)
		return monitorMsg{app: app, rows: parseMetrics(out), vols: parseVolumes(out),
			hist: parseSystemLog(out), span: span, hasSpan: hasSpan}
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
	case "r":
		return m.openMonitor(m.monitorOf, m.monitorSvc)
	case "t":
		return m.ask(m.rangePrompt()), nil
	}
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
	keys := append([]string{"t", "range", "r", "refresh"}, m.selectKey()...)
	return helpLine(m.width, append(keys, "esc", "back", "q", "quit")...)
}

// sparkFor is the little chart on an app's row: the last half hour of requests,
// with no axis and no scale. It says "busy, quiet, or something changed" and
// nothing more precise, which is all a single row has space to mean.
func (m model) sparkFor(app string) string {
	return spark(m.window(app, ""), false)
}

// errSparkFor is the same window, failures only.
//
// Its own column beside the requests one, at the same width, so the two line up
// in TIME: a bar in the errors strip sits directly under the traffic it came
// out of. Different widths would put the same minute in two places and make the
// pair unreadable together, which is the only reason to have them side by side.
func (m model) errSparkFor(app string) string {
	return spark(m.window(app, ""), true)
}

func (m model) errSparkForService(app, service string) string {
	if !servesAnyHostname(m.metrics, app, service) {
		return ""
	}
	return spark(m.window(app, service), true)
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

// spark is the little chart itself.
//
// Zeros draw as blanks, which is the sparkline's own encoding rather than a
// special case: a minute with no failures has no bar, exactly as a minute with
// no requests would. So an app serving happily has an empty errors strip, and
// that is a measurement -- the dots are the "nothing was measured" state, and
// they are only used when nothing reached the app at all.
func spark(s series, errsOnly bool) string {
	if !s.any() {
		return dimStyle.Render(strings.Repeat("·", sparkColumns))
	}
	// Blue for traffic, red for failures. The colour is the label here: the two
	// strips sit side by side with nothing between them, and at sixteen columns
	// there is no room to write which is which.
	//
	// A permanently red strip would normally be saying "wrong" about every
	// minute -- but this one is BLANK on a healthy app, because zero draws no
	// bar. Red only ever appears when there is something red to say.
	vals, style := s.total, barStyle
	if errsOnly {
		vals, style = s.errors, errStyle
	}
	sl := sparkline.New(sparkColumns, 1, sparkline.WithStyle(style))
	sl.PushAll(bucketTo(vals, sparkColumns))
	sl.Draw()
	return sl.View()
}

// sparkForService is the same little chart for one container.
//
// Three states, not two, and the third is the reason this is a separate
// function. An app either has traffic or has not; a container can also be
// UNMEASURABLE -- the shared proxy only ever talks to the app's gateway, and
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
	return spark(m.window(app, service), false)
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
		b.WriteString(m.grid(net, 2, netPanelHeight))
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
			kv("", dimStyle.Render("requests reach this app's gateway and are routed inside it;")) +
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

// networkPanels is requests and failures, or nothing at all when there is no
// traffic to draw -- which the caller says in words instead.
// The how-unusual line is not named in any subtitle. It is on nearly every
// chart here, so saying so on each of them is a word repeated four times to
// distinguish nothing -- and its absence is visible without being labelled,
// because a chart that is not scored has ONE line rather than a green one. A
// missing line is not a reassuring line.
//
// What each grading means is in docs/monitor.md: requests and resources are
// graded on size in both directions, failures on the up side only, and storage
// not at all.
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
			return m.combinedChart(r, times, s.total, trailingBaseline(s.total), w, h, keyStyle, bandBothWays, 0)
		},
	}, {
		title: "Failures (5xx)",
		// Up only. Fewer failures than usual is the system working better than
		// it normally does, and an interface that coloured that amber would be
		// calling good news a warning.
		scored: true,
		sub:    "5xx/min",
		draw: func(w, h int) string {
			return m.combinedChart(r, times, s.errors, trailingPoisson(s.errors), w, h, keyStyle, bandUpOnly, 0)
		},
	}}
}

// The bands the how-unusual line is coloured by. Within one deviation is
// ordinary variation; past two is the thing you opened this screen to find.
//
// The numbers are load-bearing. ntcharts draws data sets in sorted name order
// and each one overwrites whole cells -- so where two bands share a cell, the
// one sorting last wins outright. Named plainly, "unusual-ok" sorted after
// "unusual-err" and green painted over red at every crossing, hiding the
// transition into the worst state on a chart whose only job is to show it.
// Numbering makes severity the tiebreak: worse is drawn later and survives.
const (
	bandOK   = "unusual-1-ok"
	bandWarn = "unusual-2-warn"
	bandErr  = "unusual-3-err"
)

// bandBothWays grades on SIZE, ignoring direction. For request volume either
// direction is worth seeing: a flood is an event and so is a sudden silence,
// which is usually the same incident seen from the other side -- nothing is
// reaching you because something in front of it is broken.
func bandBothWays(d float64) string {
	switch a := math.Abs(d); {
	case a <= 1:
		return bandOK
	case a <= 2:
		return bandWarn
	default:
		return bandErr
	}
}

// bandUpOnly grades on the UP side only. For failures the two directions are
// not symmetric: unusually many is the thing you are looking for, and unusually
// few is the system working better than it normally does. Colouring that amber
// would be an interface calling good news a warning.
func bandUpOnly(d float64) string {
	switch {
	case d <= 1:
		return bandOK
	case d <= 2:
		return bandWarn
	default:
		return bandErr
	}
}

// combinedChart draws a series and, over it, how unusual each point was.
//
// The deviation is mapped onto the chart's range so both share one canvas: -4
// sits on the floor, 0 halfway up, +4 at the ceiling. The two series are not
// comparable in value and were never meant to be -- only in shape and in x.
func (m model) combinedChart(axis timeRange, times []time.Time, vals []float64, base baseline, w, h int, style lipgloss.Style, band func(float64) string, fixedMax float64) string {
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
	// Four charts of the same moment on four different axes is a page you cannot
	// read across, and reading across is why they are on one screen.
	from, to := axis.from, axis.to
	if to <= from {
		to = from + 1
	}
	place := func(d float64) float64 { return (d + devLimit) / (2 * devLimit) * yMax }

	var prev *timeserieslinechart.TimePoint
	prevBand := ""

	c := m.newChart(from, to, w, h)
	c.SetYRange(0, yMax)
	c.SetViewYRange(0, yMax)
	c.SetDataSetStyle("normal", dimStyle)
	c.SetDataSetStyle("series", style)
	// The how-unusual line is coloured by how unusual it is, in the three
	// states this interface already uses for everything else: fine, worth a
	// look, wrong. Colour carries meaning here and nothing else, so a line that
	// changes colour is saying something rather than decorating itself.
	c.SetDataSetStyle(bandOK, okStyle)
	c.SetDataSetStyle(bandWarn, warnStyle)
	c.SetDataSetStyle(bandErr, errStyle)

	// Where "not unusual" sits, so the overlaid series has a zero to be read
	// against. Without it that line is a shape with no origin.
	//
	// Drawn across the DATA, not across the axis. The axis is the range the page
	// is showing and can reach back further than this series does; a reference
	// line ruled across the empty part would be the one thing plotted where
	// there is nothing to plot.
	if a, b, ok := extent(vals); ok {
		c.PushDataSet("normal", timeserieslinechart.TimePoint{Time: times[a], Value: place(0)})
		c.PushDataSet("normal", timeserieslinechart.TimePoint{Time: times[b], Value: place(0)})
	}

	for i, v := range vals {
		at := times[i]
		// A reading that could not be taken is skipped, not drawn. Zero would be
		// a measurement: a dive to the floor, which is what a dead service looks
		// like. The line bridges the gap instead, which claims less.
		if !math.IsNaN(v) {
			c.PushDataSet("series", timeserieslinechart.TimePoint{Time: at, Value: v})
		}
		d := base.score[i]
		if math.IsNaN(d) {
			// No baseline yet, or a flat one with no scale. Skipped rather than
			// drawn at zero: "we cannot say" and "exactly normal" are different
			// statements and must not share a shape.
			continue
		}
		if d > devLimit {
			d = devLimit
		} else if d < -devLimit {
			d = -devLimit
		}
		pt := timeserieslinechart.TimePoint{Time: at, Value: place(d)}
		b := band(d)
		// The previous point joins this band too when the band changes, so the
		// segment between them is drawn. Without it a line that crosses 1 or 2
		// breaks at exactly the crossing -- the moment it is describing.
		if prev != nil && b != prevBand {
			c.PushDataSet(b, *prev)
		}
		c.PushDataSet(b, pt)
		prev, prevBand = &pt, b
	}
	c.DrawBrailleAll()
	return c.View()
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

func chartLines(s string) string {
	var b strings.Builder
	for _, ln := range strings.Split(s, "\n") {
		b.WriteString(gutter + ln + "\n")
	}
	return b.String()
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
