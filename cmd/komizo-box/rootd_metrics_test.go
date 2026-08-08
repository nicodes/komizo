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

	if err := runRootd(rootdArgs(dir)); err != nil {
		t.Fatalf("a single tick failed: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(dir, "served", "metrics.json"))
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

// rootdArgs points every path a tick writes inside dir, so the daemon runs as
// whoever is running the tests rather than demanding /var/lib/komizo.
func rootdArgs(dir string) []string {
	return []string{
		"--once", "--volumes-every", "0",
		"--state", filepath.Join(dir, "state"),
		"--socket-dir", filepath.Join(dir, "run"),
		"--config", filepath.Join(dir, "agent.json"),
		"--inbox", filepath.Join(dir, "inbox"),
		"--results", filepath.Join(dir, "results"),
		"--logs", filepath.Join(dir, "logs"),
		"--report", filepath.Join(dir, "run", "report.json"),
		"--history", filepath.Join(dir, "served", "history.jsonl"),
		"--metrics", filepath.Join(dir, "served", "metrics.json"),
	}
}

// storedMetrics is what the tick left where the API reads it.
func storedMetrics(t *testing.T, dir string) box.Metrics {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "served", "metrics.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m box.Metrics
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// fakeMachine writes the smallest box Probe.Metrics can attribute a request on:
// one app record naming its directory, and that directory's hostnames file.
//
// BOTH ARE NEEDED AND NEITHER IS OPTIONAL. Probe.Metrics builds its host->app
// map from appStates(), so an access log on a machine with no app records
// yields rows=[] -- and then every assertion about which window was measured is
// vacuously true. That is the trap the first version of this file fell into and
// then wrote up as a law.
//
// The log's newest line is `newest` seconds before now and its oldest reaches
// back two days: the shape a quiet box's 4MB tail actually has, and the one the
// clip exists for. The tail being wider than the window is what pins Span.From,
// which is what makes the window assertable at all.
func fakeMachine(t *testing.T, root string, newest int64) {
	t.Helper()
	write := func(p, s string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "var/lib/komizo/apps/blog.env"), "APP_DIR=/srv/blog\n")
	write(filepath.Join(root, "srv/blog/hostnames"), "blog.example.com -> web\n")

	now := time.Now().Unix()
	line := func(ts int64) string {
		b, _ := json.Marshal(map[string]any{
			"ts": float64(ts), "status": 200,
			"request": map[string]any{"host": "blog.example.com"},
		})
		return string(b) + "\n"
	}
	write(filepath.Join(root, "srv/_proxy/logs/access.log"),
		line(now-2*86400)+line(now-86400)+line(now-newest))
}

// AND THE WINDOW IT MEASURES IS THE ONE IT KEEPS.
//
// THIS FILE PREVIOUSLY CARRIED A CONFIDENT PARAGRAPH SAYING THIS COULD NOT BE
// ASSERTED -- that the clip makes the span read correctly whatever was
// measured, and that a fake machine yields no rows. Review 1 on komizo-be#166
// wrote the test anyway, in about sixty lines, red on every mutation the
// paragraph existed to excuse. A wrong lesson recorded in code is worse than no
// lesson: it is written in the register of hard-won knowledge, so the next
// person believes it and stops trying.
//
// WHAT MAKES IT WORK is asserting against WALL CLOCK rather than against
// rootd's own `to`. With a tail wider than the window the clip PINS Span.From
// to `to - MetricsWindow` -- so the stored span encodes `to` exactly, and `to`
// is the thing a wrong-window mutation moves. Comparing against a clock the
// test owns catches it; comparing against rootd's own `to` is circular, which
// is what the first version did. The clip made the window MORE assertable, not
// less.
func TestRootdMeasuresTheWindowItKeeps(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "machine")
	fakeMachine(t, root, 60)

	now := time.Now().Unix()
	if err := runRootdAt(root, rootdArgs(dir)); err != nil {
		t.Fatalf("a single tick failed: %v", err)
	}
	m := storedMetrics(t, dir)

	// THE ROWS FIRST, because they are what proves the machine was read at all.
	// Without them everything below is an assertion about an empty document.
	if len(m.Rows) == 0 {
		t.Fatal("the tick attributed no requests, so it did not read the machine it was given")
	}
	for _, r := range m.Rows {
		if r.Minute < now-box.MetricsWindow-60 {
			t.Errorf("row at %d is %ds old, outside the %ds window rootd keeps",
				r.Minute, now-r.Minute, box.MetricsWindow)
		}
	}

	if m.Span == nil {
		t.Fatal("the tick reported no span, so which window it measured cannot be told")
	}
	// WITHIN SECONDS of now-MetricsWindow, not merely inside it. The tail
	// reaches back two days, so the clip pins Span.From exactly -- and a loose
	// bound here is what let "rootd computes yesterday's window" stay green.
	if d := m.Span.From - (now - box.MetricsWindow); d < -5 || d > 5 {
		t.Errorf("stored span begins at %d, %d seconds away from an hour before now -- "+
			"rootd measured a different period from the one it advertises", m.Span.From, d)
	}
	if m.Span.From > m.Span.To {
		t.Errorf("span is inverted: from %d to %d", m.Span.From, m.Span.To)
	}
}

// A BOX THAT SERVED NOTHING THIS HOUR REPORTS NO SPAN, rather than a crossed one.
//
// Review 1's B1, reproduced. When the newest log entry predates the window, the
// clip moves From forward to to-MetricsWindow and leaves To at that old entry --
// From ends up 7200s AFTER To. ReadMetrics then computes lo = max(from, From)
// and hi = min(to, To), and lo > hi for EVERY window a client can ask about, so
// the route answers Span: nil always, the app blanks nothing, and the chart
// draws confident zeros. The clip reintroduced the exact failure it was written
// to prevent, on exactly the box shape it was aimed at.
//
// nil is the honest answer: nothing was measured across this window, which is
// not the same as having measured zero across it.
func TestRootdWritesNoSpanWhenTheLogPredatesTheWindow(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "machine")
	fakeMachine(t, root, 3*60*60) // newest request three hours ago

	if err := runRootdAt(root, rootdArgs(dir)); err != nil {
		t.Fatalf("a single tick failed: %v", err)
	}
	m := storedMetrics(t, dir)

	if m.Span != nil && m.Span.From > m.Span.To {
		t.Fatalf("stored span is inverted: from %d to %d, crossed by %ds -- "+
			"ReadMetrics then answers nil for every window a client can ask",
			m.Span.From, m.Span.To, m.Span.From-m.Span.To)
	}
	if m.Span != nil {
		t.Errorf("a box whose newest request predates the window stored span %v, "+
			"claiming to have measured a period it holds nothing for", *m.Span)
	}
}

func TestTheWindowRootdKeepsIsTheOneItAdvertises(t *testing.T) {
	if box.MetricsWindow != 60*60 {
		t.Errorf("MetricsWindow = %d, want an hour -- the app asks for half of one "+
			"and a reader who refreshes should not find the window moved under them",
			box.MetricsWindow)
	}
}
