package app

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/scripts"
)

func TestARangeIsAnOffsetOrTwoMoments(t *testing.T) {
	now := time.Date(2026, 7, 28, 13, 30, 0, 0, time.Local)
	for _, c := range []struct {
		in         string
		from, to   time.Time
		wantsError bool
	}{
		// The common case: one offset, meaning "from then until now". This is
		// the whole of what a preset list would have offered.
		{in: "-30m", from: now.Add(-30 * time.Minute), to: now},
		{in: "-2h", from: now.Add(-2 * time.Hour), to: now},
		{in: "-3d", from: now.AddDate(0, 0, -3), to: now},
		{in: "-1w", from: now.AddDate(0, 0, -7), to: now},
		// Both ends.
		{in: "-2h..-1h", from: now.Add(-2 * time.Hour), to: now.Add(-time.Hour)},
		{in: "-2h..", from: now.Add(-2 * time.Hour), to: now},
		// Absolute, in the reader's own timezone.
		{in: "2026-07-28 09:00..2026-07-28 11:00",
			from: time.Date(2026, 7, 28, 9, 0, 0, 0, time.Local),
			to:   time.Date(2026, 7, 28, 11, 0, 0, 0, time.Local)},
		// A bare clock time is today...
		{in: "09:00..11:00",
			from: time.Date(2026, 7, 28, 9, 0, 0, 0, time.Local),
			to:   time.Date(2026, 7, 28, 11, 0, 0, 0, time.Local)},
		// ...unless today's is still to come. At 13:30, "23:00" is last night's,
		// not the one nine hours away.
		{in: "23:00..23:30",
			from: time.Date(2026, 7, 27, 23, 0, 0, 0, time.Local),
			to:   time.Date(2026, 7, 27, 23, 30, 0, 0, time.Local)},

		{in: "bogus", wantsError: true},
		{in: "-1h..-2h", wantsError: true}, // backwards
		// Unsigned means backwards: every range here looks into the past, so
		// making people type a minus to say the only thing the field can mean
		// is a papercut with no upside.
		{in: "12h", from: now.Add(-12 * time.Hour), to: now},
		{in: "90m", from: now.Add(-90 * time.Minute), to: now},
	} {
		got, err := parseRange(c.in, now)
		if c.wantsError {
			if err == nil {
				t.Errorf("%q should have been rejected", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if c.from.IsZero() {
			continue
		}
		if got.from != c.from.Unix() || got.to != c.to.Unix() {
			t.Errorf("%q = %s..%s, want %s..%s", c.in,
				time.Unix(got.from, 0), time.Unix(got.to, 0), c.from, c.to)
		}
	}
}

// An empty field resets to the default, which is the last few hours -- and the
// default has to be resolved on every read, or it stops meaning "the last four
// hours" the moment the page has been open for a while.
func TestTheDefaultRangeMovesAndAChosenOneDoesNot(t *testing.T) {
	r, err := parseRange("", time.Now())
	if err != nil || !r.empty() {
		t.Fatalf("an empty range should reset to the default, got %+v %v", r, err)
	}
	a := r.orDefault()
	time.Sleep(1100 * time.Millisecond)
	b := r.orDefault()
	if b.to <= a.to {
		t.Error("the default window should follow the clock")
	}

	chosen := timeRange{from: 1000, to: 2000}
	if chosen.orDefault() != chosen {
		t.Error("a range somebody chose must stay where they put it")
	}
}

// What it prints is what you would type to get it back, which is the only
// reason to prefill the field with it.
func TestARangeReadsBackAsSomethingYouCouldType(t *testing.T) {
	now := time.Date(2026, 7, 28, 13, 30, 0, 0, time.Local)
	r, _ := parseRange("-2h", now)
	if got := rangeText(r, now); got != "-2h" {
		t.Errorf("rangeText = %q, want -2h", got)
	}
	// Once the end is pinned to a past moment, the relative form would be a lie.
	r2, _ := parseRange("-2h..-1h", now)
	if got := rangeText(r2, now); !strings.Contains(got, "..") {
		t.Errorf("a fixed range should print both ends, got %q", got)
	}
	// And it parses back to the same thing.
	back, err := parseRange(rangeText(r2, now), now)
	if err != nil || back != r2 {
		t.Errorf("round trip: %q -> %+v (want %+v), %v", rangeText(r2, now), back, r2, err)
	}
}

// A range wider than the record keeps its axis and loses its data. Every chart
// on the page shares one x axis -- four charts of the same moment on four
// different axes is a page you cannot read across -- so the range stays put and
// the minutes nobody recorded are simply not plotted.
func TestMinutesWithNoRecordAreNotPlotted(t *testing.T) {
	// A ten-minute range, with counts for only the last five.
	from := int64(1700000000) / 60 * 60
	to := from + 9*60
	var rows []metricRow
	for i := 5; i < 10; i++ {
		rows = append(rows, metricRow{minute: from + int64(i)*60, app: "blog", c2: 3})
	}
	s := seriesFor(rows, "blog", from, to)
	s.blankOutside(timeRange{from: from + 5*60, to: to})

	if len(s.total) != 10 {
		t.Fatalf("the series should still span the whole range, got %d minutes", len(s.total))
	}
	for i := 0; i < 5; i++ {
		if !math.IsNaN(s.total[i]) {
			t.Errorf("minute %d is %v, want no point at all", i, s.total[i])
		}
	}
	for i := 5; i < 10; i++ {
		if s.total[i] != 3 {
			t.Errorf("minute %d is %v, want the 3 that was recorded", i, s.total[i])
		}
	}

	// And a quiet minute INSIDE the record is a real zero, not a gap: the log
	// covers it and nothing arrived.
	quiet := seriesFor(nil, "blog", from, to)
	quiet.blankOutside(timeRange{from: from, to: to})
	for i := range quiet.total {
		if math.IsNaN(quiet.total[i]) {
			t.Errorf("minute %d inside the record should chart as zero", i)
		}
	}
}

// The host filters by the range, so the answer stays small however wide a range
// is asked for and however big the logs have grown.
func TestTheRangeIsAppliedOnTheHost(t *testing.T) {
	r := timeRange{from: 1700000000, to: 1700003600}
	for _, script := range []string{scripts.Metrics(r.from, r.to), scripts.SystemLogRange(r.from, r.to)} {
		if !strings.Contains(script, "1700000000") || !strings.Contains(script, "1700003600") {
			t.Errorf("the range is not in the script:\n%s", script)
		}
	}
	// And the access log's own coverage comes back with the counts.
	if !strings.Contains(scripts.Metrics(r.from, r.to), "mspan") {
		t.Error("the counts do not report how far back the log reaches")
	}
	span, ok := parseMetricSpan("mspan\t1699000000\t1700000000\n")
	if !ok || span.from != 1699000000 {
		t.Errorf("span = %+v ok=%v", span, ok)
	}
}

// t opens the picker, and accepting it refetches for the new range.
func TestTheRangeKeyRefetches(t *testing.T) {
	m := rollupModel("blog", "api")
	m.width, m.height = 110, 40
	next, _ := sendCmd(m, "t")
	if next.prompt == nil || !strings.Contains(next.prompt.question, "range") {
		t.Fatalf("t should open the range picker, got %+v", next.prompt)
	}
	// Prefilled with what is showing, so you can see what you are changing.
	if next.prompt.typed == "" {
		t.Error("the field should be prefilled with the current range")
	}
	if err := next.prompt.check("-2h"); err != nil {
		t.Fatalf("-2h should be accepted: %v", err)
	}
	cmd := next.prompt.action(&next, "-2h")
	if cmd == nil {
		t.Error("choosing a range should refetch")
	}
	if next.monitorRange.empty() || next.monitorRange.span() != 2*time.Hour {
		t.Errorf("range = %+v, want two hours", next.monitorRange)
	}
	if next.monitorReady {
		t.Error("the page should be waiting for the new range, not showing the old one")
	}
	// The footer offers it.
	if !strings.Contains(stripANSI(m.monitorKeys()), "range") {
		t.Error("the key is not advertised")
	}
}

// The sparkline on a row is "the last half hour" and has to stay that whatever
// range the monitor is showing -- they are different questions on different
// pages, and the poll serves every row at once.
func TestTheIndexSparklineIgnoresTheMonitorRange(t *testing.T) {
	m := rollupModel("blog", "api")
	m.monitorRange = timeRange{from: 1000, to: 2000}
	// fetch() builds its own window from the clock; assert on the script it
	// would send rather than on the model.
	now := time.Now().Unix()
	script := scripts.Metrics(now-sparkWindow*60, now)
	if strings.Contains(script, "\t1000\t") {
		t.Error("the poll should not inherit the monitor's range")
	}
}
