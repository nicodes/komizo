package app

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The window the monitor is looking at.
//
// A start and an end rather than a list of presets. Presets answer "the last
// four hours" and nothing else, and the question that brings anyone to this
// screen is usually "what happened around three o'clock" -- which a fixed
// window can only approximate by being large enough to contain it, at which
// point the thing you are looking for is four pixels wide.
//
// Both ends take an offset or a time, so the presets are still one thing to
// type: "-30m" is the last half hour, "-2d..-1d" is yesterday.

// timeRange is inclusive of both ends, in unix seconds.
type timeRange struct{ from, to int64 }

func (r timeRange) empty() bool { return r.from == 0 && r.to == 0 }

func (r timeRange) span() time.Duration {
	return time.Duration(r.to-r.from) * time.Second
}

// defaultWindow is how far back a range with no explicit start reaches.
//
// Four hours: long enough that a deploy an hour ago is still on it, short
// enough that a minute is still a distinguishable unit of it.
//
// Named for the chart it opened when the interface owned this default. The
// interface is gone (nicodes/komizo-be#55); the default is not, because
// `komizo report` and every signed read still resolve one.
const defaultWindow = 4 * 60 // minutes

// orDefault is the last defaultWindow minutes, which is what a caller that
// named no range asked for.
//
// Resolved at READ time, not when the screen opened. A default window is "the
// last four hours" and has to still mean that after the page has been open for
// twenty minutes; a range the user actually chose is fixed, because they chose
// it.
func (r timeRange) orDefault() timeRange {
	if r.empty() {
		now := time.Now().Unix()
		return timeRange{from: now - defaultWindow*60, to: now}
	}
	return r
}

// parseRange reads "start..end", or a single value meaning "from then until
// now".
//
// The single-value form is the common one: "-2h" is the last two hours, which
// is the whole of what a preset list would have offered, in three keystrokes.
func parseRange(s string, now time.Time) (timeRange, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return timeRange{}, nil // back to the default
	}
	from, to := s, "now"
	if i := strings.Index(s, ".."); i >= 0 {
		from, to = strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+2:])
		if to == "" {
			to = "now"
		}
	}
	f, err := parseMoment(from, now)
	if err != nil {
		return timeRange{}, err
	}
	t, err := parseMoment(to, now)
	if err != nil {
		return timeRange{}, err
	}
	if !t.After(f) {
		return timeRange{}, fmt.Errorf("the end has to come after the start")
	}
	return timeRange{from: f.Unix(), to: t.Unix()}, nil
}

// parseMoment reads one end of a range: an offset from now, or a time.
//
// Local time throughout, deliberately. The clock on the wall is the one being
// compared against a memory of when something broke, and asking someone to do
// UTC arithmetic to look at their own server is a way of getting the wrong hour.
func parseMoment(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	switch strings.ToLower(s) {
	case "", "now":
		return now, nil
	}
	if d, ok := parseOffset(s); ok {
		return now.Add(d), nil
	}
	// Longest first: "15:04" would otherwise match the front of a date and
	// silently read the year as an hour.
	for _, layout := range []string{
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
		"2006-01-02",
		"15:04:05",
		"15:04",
	} {
		t, err := time.ParseInLocation(layout, s, now.Location())
		if err != nil {
			continue
		}
		if !strings.ContainsAny(s, "-/") {
			// A bare clock time means today. If that is in the future it means
			// yesterday: at 00:30, "23:00" is the one forty minutes ago, not
			// the one twenty-three hours away.
			t = time.Date(now.Year(), now.Month(), now.Day(),
				t.Hour(), t.Minute(), t.Second(), 0, now.Location())
			if t.After(now) {
				t = t.AddDate(0, 0, -1)
			}
		}
		return t, nil
	}
	return time.Time{}, fmt.Errorf("%q is not a time or an offset like -2h", s)
}

// parseOffset reads "-90m", "2h", "3d", "1w". Minutes, hours, days, weeks.
//
// Unsigned means backwards. Every range on this screen looks into the past --
// there is nothing recorded ahead of now -- so "12h" can only sensibly mean the
// last twelve hours, and making people type a minus sign to say the only thing
// the field can mean is a papercut with no upside. "+2h" still goes forward, for
// the one person who wants an empty chart.
//
// No month unit. "m" is already minutes, and "mo" beside "m" is a footgun in a
// field where a typo silently asks for a window thirty thousand times too big --
// "30d" says the same thing without the ambiguity.
func parseOffset(s string) (time.Duration, bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	fwd := strings.HasPrefix(s, "+")
	s = strings.TrimPrefix(strings.TrimPrefix(s, "-"), "+")
	if len(s) < 2 {
		return 0, false
	}
	unit := s[len(s)-1]
	n, err := strconv.ParseFloat(s[:len(s)-1], 64)
	if err != nil || n < 0 {
		return 0, false
	}
	var d time.Duration
	switch unit {
	case 'm':
		d = time.Duration(n * float64(time.Minute))
	case 'h':
		d = time.Duration(n * float64(time.Hour))
	case 'd':
		d = time.Duration(n * 24 * float64(time.Hour))
	case 'w':
		d = time.Duration(n * 7 * 24 * float64(time.Hour))
	default:
		return 0, false
	}
	if !fwd {
		d = -d
	}
	return d, true
}

// rangeText is a range as something to read, and as something to edit.
//
// The relative form is kept when it is still true -- a range ending now reads
// "-4h", which is both shorter and what you would type to get it back. Once the
// end is pinned to a past moment the relative form would be a lie, so it prints
// the times.
func rangeText(r timeRange, now time.Time) string {
	if r.empty() {
		return fmt.Sprintf("-%dh", defaultWindow/60)
	}
	end := time.Unix(r.to, 0)
	if now.Sub(end) < time.Minute && now.Sub(end) > -time.Minute {
		return "-" + durText(r.span())
	}
	return stampText(time.Unix(r.from, 0), now) + ".." + stampText(end, now)
}

// stampText drops the date when it is today, which is most of the time and is
// half the width.
func stampText(t, now time.Time) string {
	if t.YearDay() == now.YearDay() && t.Year() == now.Year() {
		return t.Format("15:04")
	}
	return t.Format("2006-01-02 15:04")
}

func durText(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		if m := int(d.Minutes()) % 60; m != 0 {
			return fmt.Sprintf("%dh%02dm", int(d.Hours()), m)
		}
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
