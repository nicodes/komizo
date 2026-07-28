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

// chartWindow is how far back the chart screen asks for. The index page's
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
	chartHeight = 16
	panelHeight = 12

	// How far out the deviation panel draws before clamping. Beyond this the
	// exact number stops mattering: four robust deviations from normal is
	// "look at this", and so is forty.
	devLimit = 4
)

// openCharts is the same shape as openLogs: reset, mark not-ready, start the
// fetch, and start the spinner only if one is not already running.
func (m model) openCharts(app, service string) (tea.Model, tea.Cmd) {
	m.chartsOf, m.chartsSvc, m.chartsReady, m.charts = app, service, false, nil
	m.scroll = 0
	m.status, m.statusErr = "", false
	wasSpinning := m.spinning()
	m.scr = screenCharts
	cmds := []tea.Cmd{fetchCharts(m.tgt, app)}
	if !wasSpinning {
		cmds = append(cmds, spinTick())
	}
	return m, tea.Batch(cmds...)
}

type chartsMsg struct {
	app  string
	rows []metricRow
	err  error
}

func fetchCharts(t target, app string) tea.Cmd {
	return func() tea.Msg {
		out, err := t.runCapture(metricsScript(chartWindow))
		if err != nil {
			return chartsMsg{app: app, err: err}
		}
		return chartsMsg{app: app, rows: parseMetrics(out)}
	}
}

func (m model) handleChartsKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q":
		return m, tea.Quit
	case "esc":
		m.scr = screenIndex
		m.status, m.statusErr = "", false
		return m, nil
	case "r":
		return m.openCharts(m.chartsOf, m.chartsSvc)
	}
	return m, nil
}

func (m model) chartsKeys() string {
	return helpLine(m.width, "r", "refresh", "esc", "back", "q", "quit")
}

// sparkFor is the little chart on an app's row: the last half hour of requests,
// with no axis and no scale. It says "busy, quiet, or something changed" and
// nothing more precise, which is all a single row has space to mean.
func (m model) sparkFor(app string) string {
	s := seriesFor(m.metrics, app, time.Now().Unix()-sparkWindow*60, time.Now().Unix())
	if !s.any() {
		return dimStyle.Render(strings.Repeat("·", sparkColumns))
	}
	sl := sparkline.New(sparkColumns, 1, sparkline.WithStyle(dimStyle))
	sl.PushAll(bucketTo(s.total, sparkColumns))
	sl.Draw()
	return sl.View()
}

// rateFor is the numbers beside the sparkline: requests in the last COMPLETE
// minute, and how many of them failed.
func (m model) rateFor(app string) string {
	s := seriesFor(m.metrics, app, time.Now().Unix()-sparkWindow*60, time.Now().Unix())
	if !s.any() {
		return dimStyle.Render("—")
	}
	rate, errs := s.rate()
	out := dimStyle.Render(fmt.Sprintf("%d/min", rate))
	if errs > 0 {
		out += "  " + errStyle.Render(fmt.Sprintf("%d err", errs))
	}
	return out
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// viewCharts is the full-window version: requests and failures over hours,
// stacked, sharing an x axis.
func (m model) viewCharts() string {
	if !m.chartsReady {
		return m.loadingPane()
	}
	now := time.Now().Unix()
	var s series
	if m.chartsSvc == "" {
		s = seriesFor(m.charts, m.chartsOf, now-chartWindow*60, now)
	} else {
		// A container nobody pointed a hostname at is not idle -- it is
		// unmeasurable from here, and a chart of zeros would say the first
		// thing while meaning the second.
		if !servesAnyHostname(m.charts, m.chartsOf, m.chartsSvc) {
			return m.centred(
				dimStyle.Render("no hostname declares "+m.chartsSvc),
				"",
				dimStyle.Render("requests reach this app's gateway and are routed inside it;"),
				dimStyle.Render("the shared proxy cannot see which container served them"),
				"",
				dimStyle.Render("name it in deploy/hostnames to chart it:  api.example.com -> "+m.chartsSvc))
		}
		s = seriesForService(m.charts, m.chartsOf, m.chartsSvc, now-chartWindow*60, now)
	}
	if !s.any() {
		return m.centred(
			dimStyle.Render("no requests in the last "+fmt.Sprintf("%dh", chartWindow/60)),
			"",
			dimStyle.Render("nothing has reached this app, or nothing has reached the box"))
	}

	// Built against m.width, not left to wrap: the frame CLIPS long rows rather
	// than folding them, so a chart wider than the window loses its right-hand
	// edge silently -- and the right-hand edge is now.
	w := m.width - len(gutter)*2 - 8 // 8 for the y-axis labels ntcharts draws
	if w < 20 {
		w = 20
	}

	base := trailingBaseline(s.total)

	var b strings.Builder
	// One chart, both series. Reading "busy" and "unusually busy" off the same
	// x position is the point -- in two stacked panels the eye has to walk
	// between them and hold a column position while it does.
	//
	// No second axis. The deviation is scaled onto the chart's range and its
	// zero drawn as a flat line, which is the only reference it needs: this
	// series is read for SHAPE -- where it crosses, how far it swings -- and a
	// column of numbers down the right would be four more characters of width
	// for a precision nobody acts on.
	b.WriteString(section(fmt.Sprintf(
		"Requests   \u00b7   how unusual  (\u00b1%d\u03c3, flat line is normal)", devLimit)))
	b.WriteString(m.combinedChart(s.total, base, s.from, s.to, w, chartHeight, keyStyle))

	// Failures get the same overlay, against a baseline of their own. See
	// trailingPoisson: a median has no scale on a series of zeros, so the line
	// would never draw at all.
	b.WriteString(section(fmt.Sprintf(
		"Failures (5xx)   \u00b7   how unusual  (\u00b1%d\u03c3, flat line is normal)", devLimit)))
	b.WriteString(m.combinedChart(s.errors, trailingPoisson(s.errors), s.from, s.to, w, panelHeight, errStyle))

	rate, errs := s.rate()
	b.WriteString(section("Now"))
	b.WriteString(kv("requests", dimStyle.Render(fmt.Sprintf("%d in the last full minute", rate))))
	b.WriteString(kv("failures", dimStyle.Render(fmt.Sprintf("%d in the last full minute", errs))))
	// Said out loud because every other number on this screen is exact, and
	// somebody will otherwise read this one as exact too.
	b.WriteString(kv("window", dimStyle.Render(
		fmt.Sprintf("%dh, as far back as the proxy's log still goes", chartWindow/60))))
	return b.String()
}

func (m model) chartBlock(vals []float64, from, to int64, w, h int, style lipgloss.Style) string {
	c := m.newChart(from, to, w, h)
	c.SetStyle(style)
	for i, v := range vals {
		c.Push(timeserieslinechart.TimePoint{Time: time.Unix(from+int64(i)*60, 0), Value: v})
	}
	c.DrawBraille()
	var b strings.Builder
	for _, ln := range strings.Split(c.View(), "\n") {
		b.WriteString(gutter + ln + "\n")
	}
	return b.String()
}

// combinedChart draws requests and, over them, how unusual each minute was.
//
// The deviation is mapped onto the chart's range so both share one canvas: -4
// sits on the floor, 0 halfway up, +4 at the ceiling. The two series are not
// comparable in value and were never meant to be -- only in shape and in x.
func (m model) combinedChart(vals []float64, base baseline, from, to int64, w, h int, style lipgloss.Style) string {
	yMax := 0.0
	for _, v := range vals {
		if v > yMax {
			yMax = v
		}
	}
	if yMax == 0 {
		yMax = 1
	}
	place := func(d float64) float64 { return (d + devLimit) / (2 * devLimit) * yMax }

	c := m.newChart(from, to, w, h)
	c.SetYRange(0, yMax)
	c.SetViewYRange(0, yMax)
	c.SetDataSetStyle("normal", dimStyle)
	c.SetDataSetStyle("series", style)
	c.SetDataSetStyle("unusual", warnStyle)

	// Where "not unusual" sits, so the second series has a zero to be read
	// against. Without it the right-hand line is a shape with no origin.
	c.PushDataSet("normal", timeserieslinechart.TimePoint{Time: time.Unix(from, 0), Value: place(0)})
	c.PushDataSet("normal", timeserieslinechart.TimePoint{Time: time.Unix(to, 0), Value: place(0)})

	for i, v := range vals {
		at := time.Unix(from+int64(i)*60, 0)
		c.PushDataSet("series", timeserieslinechart.TimePoint{Time: at, Value: v})
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
		c.PushDataSet("unusual", timeserieslinechart.TimePoint{Time: at, Value: place(d)})
	}
	c.DrawBrailleAll()
	return chartLines(c.View())
}

func (m model) newChart(from, to int64, w, h int, extra ...timeserieslinechart.Option) timeserieslinechart.Model {
	opts := []timeserieslinechart.Option{
		timeserieslinechart.WithTimeRange(time.Unix(from, 0), time.Unix(to, 0)),
		timeserieslinechart.WithXLabelFormatter(func(_ int, v float64) string {
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
