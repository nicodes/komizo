package box

import (
	"path/filepath"
	"testing"
)

// THE SPAN MAY NOT CLAIM MORE THAN THE ROWS COVER.
//
// Review 1 on komizo#83. `Probe.Metrics` computes Span across the whole tail it
// read; rootd keeps only `MetricsWindow` of rows. Copying Span through unchanged
// answered a six-hour request with a six-hour span and thirty minutes of rows --
// and a client that blanks outside the span draws hours of confident zeros over
// a period nothing measured. That is what Span is for, inverted.
func TestTheSpanNeverOutrunsTheRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.json")
	// Measured across a wide period, kept for a narrow one.
	if err := WriteMetrics(path, Metrics{
		Span: &Span{From: 0, To: 100000},
		Rows: []Metric{{Minute: 500, App: "web"}},
	}); err != nil {
		t.Fatal(err)
	}

	got, err := ReadMetrics(path, 400, 600)
	if err != nil {
		t.Fatal(err)
	}
	if got.Span == nil {
		t.Fatal("a window that overlaps what was measured lost its span")
	}
	if got.Span.From < 400 || got.Span.To > 600 {
		t.Errorf("span %d..%d outruns the window 400..600 the caller asked about",
			got.Span.From, got.Span.To)
	}
}

// AND A WINDOW OUTSIDE WHAT WAS MEASURED CLAIMS NOTHING.
//
// Nil rather than an empty span: nothing was measured across this period, which
// is a different statement from measuring zero traffic there.
func TestAWindowOutsideWhatWasMeasuredHasNoSpan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.json")
	if err := WriteMetrics(path, Metrics{Span: &Span{From: 0, To: 100}, Rows: []Metric{}}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMetrics(path, 5000, 6000)
	if err != nil {
		t.Fatal(err)
	}
	if got.Span != nil {
		t.Errorf("span = %+v for a window nothing was measured in, want none", got.Span)
	}
}
