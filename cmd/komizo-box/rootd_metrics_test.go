package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

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

// WHAT THIS STILL CANNOT SEE, and it is the same defect one level down.
//
// Making rootd compute YESTERDAY'S window instead of the last hour leaves this
// green: the file is written, decodes, and has no rows either way. Asserting
// which window was asked for needs an access log to have said something, and
// `Probe` reads box.AccessLog -- a CONSTANT, `/srv/_proxy/logs/access.log`, not
// derived from anything a test can point elsewhere.
//
// So it is the same shape as komizo#84, which this change fixed for the state
// and socket directories: a path taken from a constant makes the behaviour that
// depends on it unassertable. Recorded on #84 rather than left as a mutation
// somebody re-runs and wonders about.

// THE WINDOW ROOTD KEEPS IS THE ONE IT ADVERTISES.
//
// Review 1 on komizo#83 showed MetricsWindow 1h -> 1m was green: a tick that
// computes the wrong window still writes a file, still decodes, and still
// serves 200 -- with most of the sparkline missing and nothing saying so.
func TestTheWindowRootdKeepsIsTheOneItAdvertises(t *testing.T) {
	if box.MetricsWindow != 60*60 {
		t.Errorf("MetricsWindow = %d, want an hour -- the app asks for half of one "+
			"and a reader who refreshes should not find the window moved under them",
			box.MetricsWindow)
	}
}
