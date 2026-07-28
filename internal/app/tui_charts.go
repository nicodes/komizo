package app

import (
	"fmt"
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

// chartWindow is how far back the chart screen asks for. The monitor's
// sparklines use a shorter one: they ride on the inventory poll, which runs
// every five seconds, and reading four hours of log that often is a waste of the
// box's CPU to move a line by one column.
const (
	chartWindow  = 4 * 60 // minutes
	sparkWindow  = 30     // minutes
	sparkColumns = 16
)

// openCharts is the same shape as openLogs: reset, mark not-ready, start the
// fetch, and start the spinner only if one is not already running.
func (m model) openCharts(app string) (tea.Model, tea.Cmd) {
	m.chartsOf, m.chartsReady, m.charts = app, false, nil
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
		m.scr = screenMonitor
		m.status, m.statusErr = "", false
		return m, nil
	case "r":
		return m.openCharts(m.chartsOf)
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
	s := seriesFor(m.charts, m.chartsOf, now-chartWindow*60, now)
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

	var b strings.Builder
	b.WriteString(section("Requests"))
	b.WriteString(m.chartBlock(s.total, s.from, s.to, w, 7, keyStyle))
	b.WriteString(section("Failures (5xx)"))
	b.WriteString(m.chartBlock(s.errors, s.from, s.to, w, 5, errStyle))

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
	c := timeserieslinechart.New(w, h,
		timeserieslinechart.WithTimeRange(time.Unix(from, 0), time.Unix(to, 0)),
		timeserieslinechart.WithStyle(style),
		timeserieslinechart.WithXLabelFormatter(func(_ int, v float64) string {
			return time.Unix(int64(v), 0).Format("15:04")
		}),
		// Fixed width, so the two charts on this screen share an x axis.
		// ntcharts sizes the y gutter to its widest label, so a chart peaking
		// at 9 is drawn one column further left than one peaking at 53 -- and
		// two time axes that do not line up are two charts you cannot read
		// against each other, which is the only reason they are stacked.
		timeserieslinechart.WithYLabelFormatter(func(_ int, v float64) string {
			return fmt.Sprintf("%4.0f", v)
		}),
	)
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
