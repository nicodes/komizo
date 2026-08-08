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

// WHAT IS STILL NOT ASSERTED, WITH THE REASON, because a gap nobody wrote down
// is a gap nobody fixes.
//
// Making rootd compute YESTERDAY'S window instead of the last hour is still
// green here. --root now exists, so the tick can be pointed at a fake machine
// with an access log on it -- that was komizo-be#166's first half and it is
// done. What is missing is the rest of the fixture: Probe.Metrics attributes a
// request to an app by looking up its HOST among the app records, so a machine
// with a log and no apps produces no rows at all, and every assertion about
// which window was measured is vacuous.
//
// Two further things worth knowing before writing it:
//
//   - asserting on Span does NOT work. rootd clips the stored span to the
//     window it keeps, so it reads correctly whatever window was measured. The
//     first version of this test did exactly that and the mutation walked
//     through it.
//   - the assertion has to be on the ROWS, which is what the window selects.
//
// The fixture needed is an app record plus its hostnames under --root, which
// box/access_test.go's newFakeBox already builds for the unit tests. Lifting it
// to a shared helper is the change.
func TestTheWindowRootdKeepsIsTheOneItAdvertises(t *testing.T) {
	if box.MetricsWindow != 60*60 {
		t.Errorf("MetricsWindow = %d, want an hour -- the app asks for half of one "+
			"and a reader who refreshes should not find the window moved under them",
			box.MetricsWindow)
	}
}
