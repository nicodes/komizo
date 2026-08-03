package box

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// A Caddy access log line, with the fields this must never carry alongside the
// three it reads.
func logLine(ts float64, host string, status int) string {
	b, _ := json.Marshal(map[string]any{
		"ts":     ts,
		"status": status,
		"request": map[string]any{
			"host":      host,
			"uri":       "/admin/secret-report?token=abc",
			"remote_ip": "203.0.113.7",
			"headers":   map[string]any{"User-Agent": []string{"curl/8.0"}},
			"method":    "GET",
		},
		"duration": 0.012,
	})
	return string(b)
}

// A box with two apps and a wildcard, and a log to read.
func metricsBox(t *testing.T, lines ...string) *fakeBox {
	f := newFakeBox(t)
	f.write("/var/lib/komizo/apps/blog.env", "APP_DIR=/srv/blog\n")
	f.write("/srv/blog/hostnames", "blog.example.com -> web\nwww.example.com\n")
	f.write("/var/lib/komizo/apps/api.env", "APP_DIR=/srv/api\n")
	f.write("/srv/api/hostnames", "*.api.example.com -> gate\n")
	f.write("/srv/_proxy/logs/access.log", strings.Join(lines, "\n")+"\n")
	return f
}

func TestMetricsCountByMinuteAndStatusClass(t *testing.T) {
	const t0 = 1780000020 // mid-minute, so bucketing is actually exercised
	f := metricsBox(t,
		logLine(t0, "blog.example.com", 200),
		logLine(t0+1, "blog.example.com", 204),
		logLine(t0+2, "blog.example.com", 301),
		logLine(t0+3, "blog.example.com", 404),
		logLine(t0+4, "blog.example.com", 503),
	)
	m := f.probe().Metrics(t0-3600, t0+3600)
	if len(m.Rows) != 1 {
		t.Fatalf("rows = %+v, want 1", m.Rows)
	}
	r := m.Rows[0]
	if r.Minute != t0-t0%60 {
		t.Errorf("minute = %d, want it truncated to %d", r.Minute, t0-t0%60)
	}
	if r.App != "blog" || r.Service != "web" {
		t.Errorf("attribution = %q/%q", r.App, r.Service)
	}
	if r.C2 != 2 || r.C3 != 1 || r.C4 != 1 || r.C5 != 1 {
		t.Errorf("counts = %+v, want 2/1/1/1", r)
	}
	if r.Total() != 5 {
		t.Errorf("total = %d", r.Total())
	}
}

func TestMetricsMatchAWildcardByItsParent(t *testing.T) {
	const t0 = 1780000020
	f := metricsBox(t,
		logLine(t0, "customer1.api.example.com", 200),
		logLine(t0, "customer2.api.example.com", 200),
	)
	m := f.probe().Metrics(t0-60, t0+60)
	if len(m.Rows) != 1 || m.Rows[0].App != "api" {
		t.Fatalf("rows = %+v, want one row for api", m.Rows)
	}
	if m.Rows[0].C2 != 2 {
		t.Errorf("both subdomains should land on the wildcard: %+v", m.Rows[0])
	}
	if m.Rows[0].Service != "gate" {
		t.Errorf("service = %q, want gate", m.Rows[0].Service)
	}
}

func TestUnknownHostnamesAreCountedForNoApp(t *testing.T) {
	// A name somebody else pointed at this box.
	const t0 = 1780000020
	f := metricsBox(t, logLine(t0, "someone-elses.example.net", 200))
	if m := f.probe().Metrics(t0-60, t0+60); len(m.Rows) != 0 {
		t.Errorf("rows = %+v, want none", m.Rows)
	}
}

func TestSpanCoversTheWholeLogNotTheRange(t *testing.T) {
	// The difference between "nothing was served in this minute" and "nobody was
	// writing this down yet". Only lines the range EXCLUDES can establish it.
	const t0 = 1780000020
	f := metricsBox(t,
		logLine(t0-7200, "blog.example.com", 200), // long before the range
		logLine(t0, "blog.example.com", 200),
		logLine(t0+7200, "blog.example.com", 200), // long after
	)
	m := f.probe().Metrics(t0-60, t0+60)
	if m.Span == nil {
		t.Fatal("span should be reported")
	}
	if m.Span.From != t0-7200 || m.Span.To != t0+7200 {
		t.Errorf("span = %+v, want the whole log", m.Span)
	}
	if len(m.Rows) != 1 {
		t.Errorf("only the in-range line should be counted: %+v", m.Rows)
	}
}

func TestNoAccessLogIsNotAnError(t *testing.T) {
	f := newFakeBox(t)
	m := f.probe().Metrics(0, 1<<40)
	if m.Span != nil || len(m.Rows) != 0 {
		t.Errorf("a box with no proxy should report nothing: %+v", m)
	}
}

func TestMetricsCarryNoRequestDetail(t *testing.T) {
	// COUNTS, NEVER LINES. The log lines above carry a path with a token in it,
	// a client address and a user agent; none of it may survive into what this
	// returns. The struct has no field for them, and this is the test that says
	// adding one is a decision rather than an accident.
	const t0 = 1780000020
	f := metricsBox(t, logLine(t0, "blog.example.com", 200))
	m := f.probe().Metrics(t0-60, t0+60)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"secret-report", "203.0.113.7", "curl", "token=abc", "/admin"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("metrics leaked %q:\n%s", leak, b)
		}
	}
}

func TestMalformedLinesAreSkippedNotFatal(t *testing.T) {
	const t0 = 1780000020
	f := metricsBox(t,
		"not json at all",
		`{"ts":"not a number"}`,
		`{"ts":`+fmt.Sprint(t0)+`}`, // no host, no status
		logLine(t0, "blog.example.com", 200),
	)
	m := f.probe().Metrics(t0-60, t0+60)
	if len(m.Rows) != 1 || m.Rows[0].C2 != 1 {
		t.Errorf("the one good line should still count: %+v", m.Rows)
	}
}
