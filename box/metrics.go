package box

import (
	"encoding/json"
	"os"
)

// MetricsWindow is how much of the access log rootd keeps computed.
//
// An hour, because the app's sparkline asks for half of one and a reader who
// pulls to refresh should not find the window has moved under them. Longer
// would cost nothing to compute -- Metrics reads a bounded tail either way --
// and would cost a larger file for readings nothing asks for.
const MetricsWindow = 60 * 60

// WriteMetrics replaces the served metrics, atomically.
//
// REPLACED WHOLE, like report.json and unlike history.jsonl. Metrics are
// recomputed from the access log's tail on every tick, so each write is the
// whole truth about the window rather than one more reading to append -- and
// appending recomputed buckets would double-count every minute that is still
// inside the window.
func WriteMetrics(path string, m Metrics) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, b, 0o640)
}

// ReadMetrics returns what rootd last computed, narrowed to a window.
//
// A BOX WITH NO METRICS FILE IS NOT A BROKEN BOX. Nothing has been computed
// yet, or no app on it publishes a hostname -- in which case the proxy wrote no
// route for it, no route means no access log, and there is genuinely nothing to
// count. An empty result is the honest answer and the caller says so; an error
// would put a fault on screen about a box that is working.
func ReadMetrics(path string, from, to int64) (Metrics, error) {
	out := Metrics{Rows: []Metric{}}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, err
	}
	var stored Metrics
	if err := json.Unmarshal(b, &stored); err != nil {
		return out, err
	}
	for _, r := range stored.Rows {
		// Minute buckets, so a row is in the window if its minute is.
		if r.Minute >= from && r.Minute <= to {
			out.Rows = append(out.Rows, r)
		}
	}
	if stored.Span != nil {
		out.Span = stored.Span
	}
	return out, nil
}
