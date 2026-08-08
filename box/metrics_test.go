package box

import (
	"path/filepath"
	"testing"
)

// A BOX WITH NOTHING MEASURED IS NOT A BROKEN BOX.
//
// komizo#80. The normal case, and the one that would otherwise put a fault on
// screen: nothing has been computed yet, or no app on this box publishes a
// hostname -- in which case the proxy wrote no route for it, no route means no
// access log, and there is genuinely nothing to count. That is the state of a
// freshly set up box and of every app reached by IP.
func TestNoMetricsFileIsAnEmptyAnswerNotAnError(t *testing.T) {
	got, err := ReadMetrics(filepath.Join(t.TempDir(), "nothing-here.json"), 0, 1<<40)
	if err != nil {
		t.Fatalf("a box that has measured nothing reported an error: %v", err)
	}
	if got.Rows == nil {
		t.Error("rows is nil, so a caller ranging over it has to know that")
	}
	if len(got.Rows) != 0 {
		t.Errorf("rows = %d, want none", len(got.Rows))
	}
}

// THE WINDOW IS APPLIED, and applied to the minute the row is about.
func TestOnlyTheAskedForMinutesComeBack(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.json")
	if err := WriteMetrics(path, Metrics{Rows: []Metric{
		{Minute: 100, App: "web", Service: "gate"},
		{Minute: 200, App: "web", Service: "gate"},
		{Minute: 300, App: "web", Service: "gate"},
	}}); err != nil {
		t.Fatal(err)
	}

	got, err := ReadMetrics(path, 150, 250)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rows) != 1 || got.Rows[0].Minute != 200 {
		t.Errorf("window 150..250 returned %+v, want only the 200 row", got.Rows)
	}

	// The bounds are inclusive, because a minute bucket labelled `from` is
	// inside the window the caller asked about.
	if all, _ := ReadMetrics(path, 100, 300); len(all.Rows) != 3 {
		t.Errorf("an inclusive window returned %d rows, want 3", len(all.Rows))
	}
}

// A FILE THAT IS THERE AND UNREADABLE IS A FAULT, and told apart from an
// absent one -- otherwise a corrupt file reads as a quiet box.
func TestAnUnparseableMetricsFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.json")
	if err := writeFileAtomic(path, []byte("{not json"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadMetrics(path, 0, 1<<40); err == nil {
		t.Error("a corrupt metrics file was reported as a box with nothing to say")
	}
}

// AND WHAT WAS WRITTEN IS WHAT COMES BACK.
func TestMetricsSurviveTheRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.json")
	want := Metric{Minute: 60, App: "web", Service: "gate", C2: 7, C4: 1}
	if err := WriteMetrics(path, Metrics{Rows: []Metric{want}}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMetrics(path, 0, 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rows) != 1 || got.Rows[0] != want {
		t.Errorf("round trip lost something: %+v", got.Rows)
	}
}
