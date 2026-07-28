package app

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
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

// accessLog is where the generated site blocks write. See alpine.sh.
const accessLog = "/srv/_proxy/logs/access.log"

// metricsScript totals the last `minutes` minutes of requests, per app.
//
// The window is applied on the host so the answer is small and roughly constant
// however big the log has grown. Reading is bounded by BYTES as well: a rolled
// 10MB log must not become a 10MB scan every five seconds, and the tail is the
// end anyone is asking about.
//
// A partial first line from cutting mid-file is not a special case -- none of
// the three patterns match it, so it is skipped like any line that is not a
// request.
func metricsScript(minutes int) string {
	return fmt.Sprintf(`
# --- request counts, per app, per minute ---------------------------------
if [ -f %[1]s ]; then
	# Hostname -> app, from what each app declared. Read first so the awk over
	# the log can attribute as it goes rather than in a second pass.
	#
	# A wildcard entry (*.iframe.ormos.dev) is stored under its suffix, and a
	# hostname that matches nothing is counted for no app -- which is the honest
	# answer for a name pointed at this box by someone else.
	{
		for h in /srv/*/hostnames; do
			[ -f "$h" ] || continue
			a="${h%%/hostnames}"; a="${a##*/}"
			# name [-> service]. The service is what the app says serves that
			# name; blank when it did not say, which is the honest default --
			# nothing on this box can work it out otherwise.
			sed 's/#.*//' "$h" | tr -d '\r' | awk -v a="$a" 'NF {
				svc = ""
				if (NF >= 3 && $2 == "->") svc = $3
				printf "MAP\t%%s\t%%s\t%%s\n", $1, a, svc
			}'
		done
		tail -c 4000000 %[1]s 2>/dev/null
	} | awk -v now="$(date +%%s)" -v win=%[2]d '
		/^MAP\t/ { split($0, m, "\t"); map[m[2]] = m[3]; svc[m[2]] = m[4]; next }

		{
			# The three fields that matter, pulled by pattern rather than by
			# position: this is JSON, and nothing promises key order.
			#
			# Whitespace after the colon is tolerated even though Caddy emits
			# none -- the cost is one character in a pattern, and the failure it
			# prevents is silent: every count reads zero and the chart is simply
			# flat, which looks exactly like no traffic.
			if (!match($0, /"ts":[ ]*[0-9.]+/)) next
			ts = substr($0, RSTART + 5, RLENGTH - 5) + 0
			if (ts < now - win * 60) next

			if (!match($0, /"host":[ ]*"[^"]+"/)) next
			host = substr($0, RSTART, RLENGTH)
			sub(/^"host":[ ]*"/, "", host); sub(/"$/, "", host)

			if (!match($0, /"status":[ ]*[0-9]+/)) next
			st = substr($0, RSTART + 9, RLENGTH - 9) + 0

			app = map[host]
			if (app == "") {
				# Not an exact name. Try the wildcard its parent would have
				# claimed: one label off the front, which is all Caddy allows.
				sub(/^[^.]+\./, "*.", host)
				app = map[host]
			}
			if (app == "") next
			s = svc[host]

			# Keyed by app AND the container the app said serves this name.
			# Summing over the second gives the app; filtering on it gives the
			# container. A name with no annotation lands under "", which is a
			# real bucket meaning "this app, container unstated" rather than a
			# missing one.
			bucket = int(ts / 60) * 60
			k = bucket "\t" app "\t" s
			seen[k] = 1
			if (st >= 500)      c5[k]++
			else if (st >= 400) c4[k]++
			else if (st >= 300) c3[k]++
			else                c2[k]++
		}

		END {
			for (k in seen) {
				split(k, f, "\t")
				printf "metric\t%%s\t%%s\t%%s\t%%d\t%%d\t%%d\t%%d\n",
					f[1], f[2], f[3], c2[k], c3[k], c4[k], c5[k]
			}
		}
	'
fi
`, accessLog, minutes)
}

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
	// the shared proxy only ever talks to the app's gateway, and what happens
	// after that is inside the app.
	service string
	c2      int // 2xx
	c3      int // 3xx
	c4      int // 4xx
	c5      int // 5xx
}

func (r metricRow) total() int { return r.c2 + r.c3 + r.c4 + r.c5 }

// parseMetrics reads the metric records out of a host script's output, ignoring
// everything else -- the same output also carries the inventory.
func parseMetrics(out string) []metricRow {
	var rows []metricRow
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimRight(ln, "\r"), "\t")
		if len(f) != 8 || f[0] != "metric" {
			continue
		}
		min, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			continue
		}
		r := metricRow{minute: min, app: f[2], service: f[3]}
		fmt.Sscanf(f[4], "%d", &r.c2)
		fmt.Sscanf(f[5], "%d", &r.c3)
		fmt.Sscanf(f[6], "%d", &r.c4)
		fmt.Sscanf(f[7], "%d", &r.c5)
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].minute != rows[j].minute {
			return rows[i].minute < rows[j].minute
		}
		if rows[i].app != rows[j].app {
			return rows[i].app < rows[j].app
		}
		return rows[i].service < rows[j].service
	})
	return rows
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

// seriesFor totals an app, over every container. seriesForService narrows to
// one; they are separate functions rather than one with a sentinel because
// "" is a real service value -- the app declared a hostname and did not say
// what serves it -- and a sentinel that collides with real data is a bug
// waiting for the first app that ships an unannotated name.
func seriesFor(rows []metricRow, app string, from, to int64) series {
	from, to = from/60*60, to/60*60
	if to < from {
		to = from
	}
	n := int((to-from)/60) + 1
	s := series{from: from, to: to, total: make([]float64, n), errors: make([]float64, n)}
	for _, r := range rows {
		if r.app != app || r.minute < from || r.minute > to {
			continue
		}
		i := int((r.minute - from) / 60)
		s.total[i] += float64(r.total())
		s.errors[i] += float64(r.c5)
	}
	return s
}

func seriesForService(rows []metricRow, app, service string, from, to int64) series {
	var mine []metricRow
	for _, r := range rows {
		if r.app == app && r.service == service {
			mine = append(mine, r)
		}
	}
	return seriesFor(mine, app, from, to)
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

// rate is the most recent full minute's request count, and errs the 5xx in it.
//
// The LAST bucket is deliberately not used: it is the minute in progress, which
// is always partial and always reads low. A number that dips every time you
// look at it is worse than no number.
func (s series) rate() (rate int, errs int) {
	if len(s.total) < 2 {
		return 0, 0
	}
	i := len(s.total) - 2
	return int(s.total[i]), int(s.errors[i])
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
		if i < baselineWindow {
			b.centre[i], b.spread[i], b.score[i] = nan, nan, nan
			continue
		}
		win := append([]float64(nil), v[i-baselineWindow:i]...)
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
