package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nicodes/komizo/box"
)

// ROOTD ACTUALLY WRITES THE METRICS, driven through its real tick.
//
// Review 1 on komizo#83's B2: deleting the WriteMetrics call left the suite
// green, and the route then answers 200 with no rows -- a box that served no
// traffic, on screen, indistinguishable from a working one. The not-running
// result reaching production as a 200 is the shape docs/checks.md opens with.
//
// It could not be asserted until --state existed: PrepareStateDir took the
// constant, so one tick demanded /var/lib/komizo. That was komizo#84 and it is
// fixed here, which also gives the report and the history their first tick
// coverage.
func TestRootdLeavesTheMetricsWhereTheApiCanReadThem(t *testing.T) {
	dir := t.TempDir()
	metrics := filepath.Join(dir, "served", "metrics.json")

	if err := runRootd([]string{
		"--once",
		"--state", filepath.Join(dir, "state"),
		"--socket-dir", filepath.Join(dir, "run"),
		"--config", filepath.Join(dir, "agent.json"),
		"--inbox", filepath.Join(dir, "inbox"),
		"--results", filepath.Join(dir, "results"),
		"--logs", filepath.Join(dir, "logs"),
		"--report", filepath.Join(dir, "run", "report.json"),
		"--history", filepath.Join(dir, "served", "history.jsonl"),
		"--metrics", metrics,
		"--volumes-every", "0",
	}); err != nil {
		t.Fatalf("a single tick failed: %v", err)
	}

	b, err := os.ReadFile(metrics)
	if err != nil {
		t.Fatalf("rootd ticked and left no metrics for the API to serve: %v", err)
	}
	// THE SHAPE, not just the presence: a file that decodes to nothing is the
	// same 200-with-no-rows this exists to prevent.
	var m box.Metrics
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("what rootd wrote is not metrics: %v", err)
	}
	if m.Rows == nil {
		t.Error("rows is nil, so a reader ranging over it has to know that")
	}
}

// AND THE WINDOW IT MEASURES IS THE ONE IT KEEPS.
//
// THIS FILE PREVIOUSLY CARRIED A COMMENT SAYING THIS COULD NOT BE ASSERTED --
// that the span is clipped so it reads correctly whatever was measured, and
// that a fake machine yields no rows. Review 1 on komizo-be#166 wrote the test
// anyway, in about sixty lines. The comment was wrong and, being confident and
// detailed, was worse than nothing: the next person would have believed it.
//
// What makes it work is asserting against WALL CLOCK rather than against
// rootd's own `to`. The clip pins Span.From to `to - MetricsWindow`, so a tick
// that measured two days ago reports a span two days back -- clipped relative
// to a `to` that is also two days back. Comparing with now catches it.
func TestRootdMeasuresTheWindowItKeeps(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "machine")
	metrics := filepath.Join(dir, "served", "metrics.json")

	logDir := filepath.Join(root, "srv", "_proxy", "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	line := func(ts int64) string {
		b, _ := json.Marshal(map[string]any{
			"ts": float64(ts), "status": 200,
			"request": map[string]any{"host": "web.example.com"},
		})
		return string(b)
	}
	// One request a minute ago, one two days ago. A tick asking for the last
	// hour sees the first; one asking for two days ago sees the second.
	if err := os.WriteFile(filepath.Join(logDir, "access.log"),
		[]byte(line(now-60)+"\n"+line(now-2*86400)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := runRootd([]string{
		"--once", "--root", root,
		"--state", filepath.Join(dir, "state"),
		"--socket-dir", filepath.Join(dir, "run"),
		"--config", filepath.Join(dir, "agent.json"),
		"--inbox", filepath.Join(dir, "inbox"),
		"--results", filepath.Join(dir, "results"),
		"--logs", filepath.Join(dir, "logs"),
		"--report", filepath.Join(dir, "run", "report.json"),
		"--history", filepath.Join(dir, "served", "history.jsonl"),
		"--metrics", metrics, "--volumes-every", "0",
	}); err != nil {
		t.Fatalf("a single tick failed: %v", err)
	}

	b, err := os.ReadFile(metrics)
	if err != nil {
		t.Fatal(err)
	}
	var m box.Metrics
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.Span == nil {
		t.Fatal("the tick reported no span at all, so which window it measured cannot be told")
	}
	// AGAINST NOW, not against rootd's own `to` -- that is the whole trick.
	if m.Span.From < now-box.MetricsWindow-300 {
		t.Errorf("span starts %ds ago, further back than the %ds window this box keeps -- "+
			"rootd measured a different period from the one it advertises",
			now-m.Span.From, box.MetricsWindow)
	}
	// AND NEVER INVERTED. A quiet box whose newest entry predates the window
	// crossed the endpoints, and ReadMetrics then answered nil for every query.
	if m.Span.From > m.Span.To {
		t.Errorf("span is inverted: from %d to %d", m.Span.From, m.Span.To)
	}
}

func TestTheWindowRootdKeepsIsTheOneItAdvertises(t *testing.T) {
	if box.MetricsWindow != 60*60 {
		t.Errorf("MetricsWindow = %d, want an hour -- the app asks for half of one "+
			"and a reader who refreshes should not find the window moved under them",
			box.MetricsWindow)
	}
}
