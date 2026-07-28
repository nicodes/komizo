package app

import (
	"fmt"
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
			sed 's/#.*//' "$h" | tr -d '\r' | while read -r n; do
				[ -n "$n" ] || continue
				printf 'MAP\t%%s\t%%s\n' "$n" "$a"
			done
		done
		tail -c 4000000 %[1]s 2>/dev/null
	} | awk -v now="$(date +%%s)" -v win=%[2]d '
		/^MAP\t/ { split($0, m, "\t"); map[m[2]] = m[3]; next }

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

			bucket = int(ts / 60) * 60
			k = bucket "\t" app
			seen[k] = 1
			if (st >= 500)      c5[k]++
			else if (st >= 400) c4[k]++
			else if (st >= 300) c3[k]++
			else                c2[k]++
		}

		END {
			for (k in seen) {
				split(k, f, "\t")
				printf "metric\t%%s\t%%s\t%%d\t%%d\t%%d\t%%d\n",
					f[1], f[2], c2[k], c3[k], c4[k], c5[k]
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
	c2     int // 2xx
	c3     int // 3xx
	c4     int // 4xx
	c5     int // 5xx
}

func (r metricRow) total() int { return r.c2 + r.c3 + r.c4 + r.c5 }

// parseMetrics reads the metric records out of a host script's output, ignoring
// everything else -- the same output also carries the inventory.
func parseMetrics(out string) []metricRow {
	var rows []metricRow
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimRight(ln, "\r"), "\t")
		if len(f) != 7 || f[0] != "metric" {
			continue
		}
		min, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			continue
		}
		r := metricRow{minute: min, app: f[2]}
		fmt.Sscanf(f[3], "%d", &r.c2)
		fmt.Sscanf(f[4], "%d", &r.c3)
		fmt.Sscanf(f[5], "%d", &r.c4)
		fmt.Sscanf(f[6], "%d", &r.c5)
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].minute != rows[j].minute {
			return rows[i].minute < rows[j].minute
		}
		return rows[i].app < rows[j].app
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
