package app

import (
	"math"
	"sort"
)

// Request counts, read off the shared proxy's access log and attributed to apps.
//
// The proxy is the one place on the box that sees every request, and it is
// komizo's own component rather than anything an app ships -- so this needs
// nothing from apps and works the same for an app running nginx as for one
// running Caddy. The join is the hostname: every app declares the names it
// answers on, and the deploy script records them at /srv/<app>/hostnames.
//
// Counts, never lines. The host does the totalling and sends back one record per
// minute per app; raw log lines -- which carry client IPs and request paths --
// stay on the box.

// metricRow is one minute of one app's traffic, split by status class.
//
// Split rather than totalled because the two questions are different: "is
// anything reaching this" and "is any of it failing". A single number answers
// neither on its own.
type metricRow struct {
	minute int64 // unix seconds, truncated to the minute
	app    string
	// service is the container the app said serves the hostname these counts
	// came from, or empty when it said nothing. komizo cannot work this out --
	// the shared proxy only ever talks to the app's gate, and what happens
	// after that is inside the app.
	service string
	c2      int // 2xx
	c3      int // 3xx
	c4      int // 4xx
	c5      int // 5xx
}

func (r metricRow) total() int { return r.c2 + r.c3 + r.c4 + r.c5 }

// blankOutside marks the minutes the record does not cover as unknown.
//
// NOT narrowed to them, which was the first attempt. Every chart on the page
// shares one x axis -- the range you asked for -- because four charts of the
// same moment on four different axes is a page you cannot read across, and
// reading across is the entire reason they are on one screen.
//
// So the axis stays put and the DATA stops. A minute inside the log with no
// requests is a real zero and charts as one; a minute before the log begins is
// not plotted at all. The difference matters: a flat line along zero says
// "nothing was served", and the truth there is "nobody wrote it down".
func (s *series) blankOutside(have timeRange) {
	for i := range s.total {
		at := s.from + int64(i)*60
		if at < have.from || at > have.to {
			s.total[i] = math.NaN()
			s.errors[i] = math.NaN()
		}
	}
}

// series is one app's counts over a window, as two parallel slices ready to
// chart: one value per minute, with quiet minutes as zero.
//
// Gaps are filled deliberately. A minute with no traffic produces no record --
// there is nothing to count -- but charting that as a missing point draws a line
// straight across an outage, which is the one shape that must not be smoothed
// away.
type series struct {
	from, to int64 // inclusive minute bounds
	total    []float64
	errors   []float64 // 5xx only: the ones that are this box's fault
}

// seriesWhere totals the rows a predicate accepts, one bucket per minute.
//
// One body, three callers. The subject -- an app, a container, the whole box --
// is the only thing that differs, and it differs by which rows count. Written
// three times it was three copies of the same minute arithmetic, and the
// windowing header had already been fixed twice in two places.
//
// Deliberately NOT one function taking an app and a service with "" meaning
// "any": "" is a real service value -- the app declared a hostname and did not
// say what serves it -- so a sentinel that collides with real data would be a
// bug waiting for the first app that ships an unannotated name. A predicate
// cannot collide with anything.
func seriesWhere(rows []metricRow, from, to int64, keep func(metricRow) bool) series {
	from, to = from/60*60, to/60*60
	if to < from {
		to = from
	}
	n := int((to-from)/60) + 1
	s := series{from: from, to: to, total: make([]float64, n), errors: make([]float64, n)}
	for _, r := range rows {
		if r.minute < from || r.minute > to || !keep(r) {
			continue
		}
		i := int((r.minute - from) / 60)
		s.total[i] += float64(r.total())
		s.errors[i] += float64(r.c5)
	}
	return s
}

// seriesFor totals an app, over every container.
func seriesFor(rows []metricRow, app string, from, to int64) series {
	return seriesWhere(rows, from, to, func(r metricRow) bool { return r.app == app })
}

// seriesForBox totals every app on the machine.
//
// Every APP -- not every request. Traffic whose hostname matches no app is
// counted for nobody and is missing from this too, which is the honest limit of
// a number built by attribution: a scanner on the raw IP, or somebody else's
// DNS pointed here, never appears.
func seriesForBox(rows []metricRow, from, to int64) series {
	return seriesWhere(rows, from, to, func(metricRow) bool { return true })
}

// seriesForService narrows to one container.
func seriesForService(rows []metricRow, app, service string, from, to int64) series {
	return seriesWhere(rows, from, to, func(r metricRow) bool {
		return r.app == app && r.service == service
	})
}

// servesAnyHostname reports whether the app ever declared a hostname pointing at
// this container. Distinguishes "nothing reaches it" from "nobody said", which
// must not both render as an empty chart.
func servesAnyHostname(rows []metricRow, app, service string) bool {
	for _, r := range rows {
		if r.app == app && r.service == service {
			return true
		}
	}
	return false
}

// any reports whether this window saw a single request, so the view can say
// "nothing yet" rather than draw a flat line along zero and imply silence is a
// measurement.
func (s series) any() bool {
	for _, v := range s.total {
		if v > 0 {
			return true
		}
	}
	return false
}

// baseline is what "normal" looked like at each minute, computed from the
// minutes BEFORE it and nothing after.
//
// Trailing on purpose. A baseline taken over the whole window puts an incident
// inside its own average -- it inflates the centre and the spread, which
// suppresses its own score -- and every past point silently moves as new data
// arrives, so the chart you looked at this morning is not the chart you look at
// now. Trailing fixes both: a point's score is final the moment it is computed.
//
// Median and MAD rather than mean and standard deviation. A spike barely moves a
// median, so it does not corrupt the baseline for the minutes that follow it; a
// mean carries the spike forward and makes the tail of an incident look ordinary.
//
// What it still cannot do, and the chart should not be read as doing: a SUSTAINED
// outage eventually becomes its own normal, because the trailing window fills
// with it. This flags the onset sharply and then fades. It is an edge detector,
// not a severity meter.
type baseline struct {
	// centre and score are per minute, aligned with the series they came from.
	// score is in robust deviations; both are NaN for minutes with no baseline
	// yet, which the chart must skip rather than draw as zero.
	centre []float64
	spread []float64
	score  []float64
}

// baselineWindow is how many previous minutes make up "normal". Half an hour:
// long enough that one quiet minute is not an event, short enough to follow the
// shape of a day rather than averaging it flat.
const baselineWindow = 30

// madScale converts a median absolute deviation into something comparable to a
// standard deviation, for a normal distribution. Only so the numbers read at a
// familiar scale -- "about two" meaning unusual, "about three" meaning notable.
const madScale = 1.4826

func trailingBaseline(v []float64) baseline {
	b := baseline{
		centre: make([]float64, len(v)),
		spread: make([]float64, len(v)),
		score:  make([]float64, len(v)),
	}
	nan := math.NaN()
	for i := range v {
		if i < baselineWindow || math.IsNaN(v[i]) {
			b.centre[i], b.spread[i], b.score[i] = nan, nan, nan
			continue
		}
		// Minutes with no reading are dropped from the window rather than
		// treated as values. Requests never produce one -- a quiet minute is a
		// real zero -- but a resource series can: nothing was sampled, which is
		// not the same as nothing was happening, and a NaN sorted into a median
		// would poison the baseline for the next half hour rather than for the
		// one minute it belongs to.
		win := make([]float64, 0, baselineWindow)
		for _, x := range v[i-baselineWindow : i] {
			if !math.IsNaN(x) {
				win = append(win, x)
			}
		}
		if len(win) < baselineWindow/2 {
			// Too little of the window survived to call anything normal.
			b.centre[i], b.spread[i], b.score[i] = nan, nan, nan
			continue
		}
		med := medianOf(win)
		dev := make([]float64, len(win))
		for j, x := range win {
			dev[j] = math.Abs(x - med)
		}
		mad := medianOf(dev) * madScale
		b.centre[i], b.spread[i] = med, mad
		switch {
		case mad > 0:
			b.score[i] = (v[i] - med) / mad
		case v[i] == med:
			b.score[i] = 0
		default:
			// A flat baseline has no scale, so there is no honest number of
			// deviations to report -- dividing by zero would invent one. Left
			// unscored rather than clamped to something invented.
			b.score[i] = nan
		}
	}
	return b
}

// quietened turns a score series into something worth drawing.
//
// The raw scores are correct and unreadable. On perfectly ordinary traffic --
// a few dozen requests a minute, jittering by a few -- the median absolute
// deviation is about the size of the jitter, so routine noise scores a whole
// sigma and the line swings across the chart every minute. Measured on quiet
// data with no incident in it: 86 of 90 minutes off the reference line. A line
// that is always off its reference is not a signal, it is a texture.
//
// Two things fix it, and only together.
//
// A median of three kills the single-minute spike, which is the shape most of
// the noise takes. On its own it is nearly useless.
//
// The DEAD ZONE does the work. Inside one deviation the line is pinned to the
// reference: ordinary variation draws as flat, because ordinary variation is
// not news. Past that the line lifts off by however far it has gone beyond it.
// Quiet data draws dead flat; an incident still peaks above twenty deviations,
// which is the number that matters.
//
// The cost, stated plainly: the line reads one deviation low. It lifts off
// past one deviation rather than at it. That is a stricter reading than the
// raw score, deliberately -- drawn raw, the line was off the reference nearly
// every minute on data with nothing wrong with it.
func quietened(score []float64) []float64 {
	out := make([]float64, len(score))
	copy(out, score)
	// Median of three, over the two minutes before each point. Trailing like
	// everything else here: a centred window would let a minute be smoothed by
	// one that has not happened yet, and every past point would move as new
	// data arrived.
	for i := 2; i < len(score); i++ {
		a, b, c := score[i-2], score[i-1], score[i]
		if math.IsNaN(a) || math.IsNaN(b) || math.IsNaN(c) {
			continue
		}
		out[i] = medianOf([]float64{a, b, c})
	}
	for i, v := range out {
		switch {
		case math.IsNaN(v):
		case v > 1:
			out[i] = v - 1
		case v < -1:
			out[i] = v + 1
		default:
			out[i] = 0
		}
	}
	return out
}

func medianOf(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// trailingPoisson is the same idea as trailingBaseline, for counts that are
// usually zero.
//
// Failures need their own baseline because median and MAD have nothing to work
// with here. 5xx is zero almost every minute, so the trailing median is zero AND
// the trailing MAD is zero -- no scale at all, so trailingBaseline correctly
// declines to score and the line never draws. Correct, and useless.
//
// Counts have a natural spread that a median does not capture: for a Poisson
// process the variance equals the mean, so the unit is sqrt(mean). That is the
// right yardstick for "three errors in a minute that normally sees one".
//
// And when the mean is genuinely zero, a single error is not some number of
// deviations from it -- the question has no answer. It is OFF the scale, which
// is a different statement from "very far up it", and the chart draws it at the
// ceiling for exactly that reason rather than because a formula produced a
// number there.
func trailingPoisson(v []float64) baseline {
	b := baseline{
		centre: make([]float64, len(v)),
		spread: make([]float64, len(v)),
		score:  make([]float64, len(v)),
	}
	nan := math.NaN()
	for i := range v {
		if i < baselineWindow {
			b.centre[i], b.spread[i], b.score[i] = nan, nan, nan
			continue
		}
		var sum float64
		for _, x := range v[i-baselineWindow : i] {
			sum += x
		}
		mean := sum / float64(baselineWindow)
		b.centre[i], b.spread[i] = mean, math.Sqrt(mean)
		switch {
		case mean > 0:
			b.score[i] = (v[i] - mean) / math.Sqrt(mean)
		case v[i] == 0:
			b.score[i] = 0
		default:
			// Nothing has failed in the whole window and now something has.
			// Off the scale rather than at some point on it.
			b.score[i] = devLimit
		}
	}
	return b
}
