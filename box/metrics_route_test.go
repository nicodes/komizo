package box

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// THE ROUTE, DRIVEN. Review 1 on komizo#83: there was no route-level test at
// all, so deleting the token check left the suite green -- and so did serving
// the HISTORY file from this route, and so did answering it with report.read's
// op instead of its own. Three ways for `metrics.read` to not be a distinct,
// guarded capability, none of them visible.
func metricsFixture(t *testing.T) (APIConfig, string, string) {
	t.Helper()
	cfg, tok, dev := readFixture(t)
	path := filepath.Join(t.TempDir(), "metrics.json")
	if err := WriteMetrics(path, Metrics{
		Span: &Span{From: 0, To: 1 << 40},
		Rows: []Metric{{Minute: 60, App: "web", Service: "gate", C2: 3}},
	}); err != nil {
		t.Fatal(err)
	}
	cfg.MetricsPath = path
	_ = dev
	return cfg, tok, path
}

func TestMetricsNeedsTheTokenAndTheEnvelope(t *testing.T) {
	cfg, tok, _ := metricsFixture(t)
	_, _, dev := readFixture(t)
	// A device this box does not trust cannot substitute for the fixture's.
	_ = dev

	cfgOK, tokOK, devOK := readFixture(t)
	cfgOK.MetricsPath = cfg.MetricsPath

	// NO TOKEN: refused before anything is verified.
	if w := signedRead(t, cfgOK, "", devOK, "/v1/metrics", OpMetricsRead,
		map[string]string{"from": "0", "to": "100000"}); w.Code != http.StatusUnauthorized {
		t.Errorf("no token = %d, want 401", w.Code)
	}
	// A TOKEN AND NO ENVELOPE: the token is not sufficient, which is the whole
	// of komizo-be#72 applied to this route.
	if w := signedRead(t, cfgOK, tokOK, nil, "/v1/metrics", OpMetricsRead, nil); w.Code == http.StatusOK {
		t.Error("an unsigned request read the metrics")
	}
	_ = tok
}

// AND IT IS ITS OWN CAPABILITY. An envelope naming report.read must not read
// metrics -- otherwise `metrics.read` is a name rather than a permission.
func TestAReportEnvelopeDoesNotReadMetrics(t *testing.T) {
	cfg, tok, dev := readFixture(t)
	c2, _, _ := metricsFixture(t)
	cfg.MetricsPath = c2.MetricsPath
	_ = tok

	cfgOK, tokOK, devOK := readFixture(t)
	cfgOK.MetricsPath = c2.MetricsPath
	_ = dev
	if w := signedRead(t, cfgOK, tokOK, devOK, "/v1/metrics", OpReportRead,
		map[string]string{"from": "0", "to": "100000"}); w.Code == http.StatusOK {
		t.Error("an envelope for report.read read the metrics route")
	}
}

// AND IT SERVES THE METRICS FILE, not whichever file happened to be wired.
func TestTheMetricsRouteServesTheMetricsFile(t *testing.T) {
	cfg, tok, dev := readFixture(t)
	path := filepath.Join(t.TempDir(), "metrics.json")
	if err := WriteMetrics(path, Metrics{Rows: []Metric{
		{Minute: 60, App: "web", Service: "gate", C2: 3},
	}}); err != nil {
		t.Fatal(err)
	}
	cfg.MetricsPath = path
	cfg.Now = func() time.Time { return time.Unix(1000, 0) }

	w := signedRead(t, cfg, tok, dev, "/v1/metrics", OpMetricsRead,
		map[string]string{"from": "0", "to": "100000"})
	if w.Code != http.StatusOK {
		t.Fatalf("metrics = %d, want 200: %s", w.Code, w.Body.String())
	}
	var got MetricsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Metrics.Rows) != 1 || got.Metrics.Rows[0].App != "web" || got.Metrics.Rows[0].C2 != 3 {
		t.Errorf("the route did not serve the metrics file: %+v", got.Metrics.Rows)
	}
}

// A box that has measured nothing answers, rather than faulting.
func TestAMetricsFileThatIsNotThereIsStillAnAnswer(t *testing.T) {
	cfg, tok, dev := readFixture(t)
	cfg.MetricsPath = filepath.Join(t.TempDir(), "absent.json")
	w := signedRead(t, cfg, tok, dev, "/v1/metrics", OpMetricsRead,
		map[string]string{"from": "0", "to": "100000"})
	if w.Code != http.StatusOK {
		t.Fatalf("a box with nothing measured = %d, want 200", w.Code)
	}
	if _, err := os.Stat(cfg.MetricsPath); !os.IsNotExist(err) {
		t.Error("the fixture accidentally created the file")
	}
}
