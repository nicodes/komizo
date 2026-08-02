package box

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReportRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	at := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	want := Report{
		V:      Version,
		At:     at,
		Server: Server{State: "ready", Docker: "29.1.3"},
		Apps:   []App{{Name: "blog", Containers: []Container{{Service: "web", State: "running", StartedAt: at}}}},
		System: System{Cores: 4, CPU: &CPU{Total: 100, Idle: 80}},
	}
	if err := WriteReport(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadReport(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.At.Equal(want.At) || got.Server.State != "ready" || got.System.Cores != 4 {
		t.Errorf("round trip lost data: %+v", got)
	}
	if got.System.CPU == nil || got.System.CPU.Idle != 80 {
		t.Errorf("cpu = %+v", got.System.CPU)
	}
	if len(got.Apps) != 1 || got.Apps[0].Containers[0].Service != "web" {
		t.Errorf("apps = %+v", got.Apps)
	}
}

func TestReportIsWorldReadable(t *testing.T) {
	// This is exactly what lets the reporting account have no privileges at
	// all: root writes it, an unprivileged process reads it. See
	// design/appify.md §3.
	path := filepath.Join(t.TempDir(), "report.json")
	if err := WriteReport(path, Report{V: Version}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, want 0644", fi.Mode().Perm())
	}
}

// A box running a newer binary than the CLI is a normal state, because boxes
// are updated by hand, one at a time. The failure has to be a message about
// versions rather than a screen of plausible zeroes.
//
// Every document, not just the report: the poll and the monitor cross the same
// gap, and the one that skipped the check would be the one that showed a
// plausible screen of nothing.
func TestADocumentFromTheFutureIsRefused(t *testing.T) {
	future := Version + 1
	docs := map[string]func() ([]byte, error){
		"report":  func() ([]byte, error) { return json.Marshal(Report{V: future, Server: Server{State: "ready"}}) },
		"poll":    func() ([]byte, error) { return json.Marshal(Poll{V: future}) },
		"monitor": func() ([]byte, error) { return json.Marshal(Monitor{V: future}) },
	}
	check := map[string]func([]byte) error{
		"report":  func(b []byte) error { _, err := Decode[Report](b); return err },
		"poll":    func(b []byte) error { _, err := Decode[Poll](b); return err },
		"monitor": func(b []byte) error { _, err := Decode[Monitor](b); return err },
	}
	for name, mk := range docs {
		b, err := mk()
		if err != nil {
			t.Fatal(err)
		}
		err = check[name](b)
		if err == nil {
			t.Errorf("%s: want an error for a newer schema", name)
			continue
		}
		if !strings.Contains(err.Error(), "update komizo") {
			t.Errorf("%s: the error should say what to do, got %q", name, err)
		}
	}
}

// A document with no version is not one komizo-box wrote. Refused rather than
// read as v0, because the shapes overlap enough that some other JSON would
// decode into a report full of zeroes and render as a broken server.
func TestADocumentWithNoVersionIsRefused(t *testing.T) {
	if _, err := Decode[Report]([]byte(`{"server":{"state":"ready"}}`)); err == nil {
		t.Error("want an error for a document with no schema version")
	}
}

func TestAnOlderReportStillReads(t *testing.T) {
	// The other direction, which must keep working: fields the old producer
	// never wrote arrive as zeroes, and that is survivable.
	b := []byte(`{"v":1,"at":"2026-08-02T12:00:00Z","server":{"state":"ready"},"apps":[]}`)
	r, err := Decode[Report](b)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Server.Ready() || r.System.Cores != 0 {
		t.Errorf("got %+v", r)
	}
}

func TestStale(t *testing.T) {
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	fresh := Report{At: now.Add(-30 * time.Second)}
	if fresh.Stale(now, time.Minute) {
		t.Error("30s old should not be stale at a 1m threshold")
	}
	old := Report{At: now.Add(-5 * time.Minute)}
	if !old.Stale(now, time.Minute) {
		t.Error("5m old should be stale")
	}
	// A report with no timestamp is not a fresh one.
	if !(Report{}).Stale(now, time.Hour) {
		t.Error("a zero time should read as stale")
	}
}

func TestSamplesAppendAndReadBackByRange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.jsonl")
	base := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	for i := range 10 {
		s := Sample{At: base.Add(time.Duration(i) * time.Minute), System: System{Cores: i}}
		if err := AppendSample(path, s, HistoryMax, HistoryKeep); err != nil {
			t.Fatal(err)
		}
	}
	// The first line is dropped as a likely partial record only when the file
	// was seeked into; a small file is read whole.
	got, err := ReadSamples(path, base.Add(2*time.Minute).Unix(), base.Add(5*time.Minute).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("samples = %d, want 4 (minutes 2..5)", len(got))
	}
	if got[0].System.Cores != 2 || got[3].System.Cores != 5 {
		t.Errorf("wrong window: %+v", got)
	}
}

func TestMissingHistoryIsNotAnError(t *testing.T) {
	// A new box has no history, and its charts are empty because nothing has
	// happened -- which is not a failure to report.
	got, err := ReadSamples(filepath.Join(t.TempDir(), "nope.jsonl"), 0, 1<<40)
	if err != nil || got != nil {
		t.Errorf("got %v, %v", got, err)
	}
}

func TestHistoryTrimsToTheMostRecent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.jsonl")
	base := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	// A max of 1 byte forces a trim on every write; keep 3 means the last three
	// readings survive.
	for i := range 10 {
		s := Sample{At: base.Add(time.Duration(i) * time.Minute), System: System{Cores: i}}
		if err := AppendSample(path, s, 1, 3); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ReadSamples(path, 0, 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("kept %d readings, want 3", len(got))
	}
	// The MOST RECENT three, in order.
	for i, want := range []int{7, 8, 9} {
		if got[i].System.Cores != want {
			t.Errorf("kept[%d] = %d, want %d", i, got[i].System.Cores, want)
		}
	}
}

func TestAtomicWriteLeavesNoPartialFile(t *testing.T) {
	// A reader that caught a half-written document would get a JSON error, and
	// the honest reading of a JSON error from a box is "this server is broken"
	// -- which would be a lie told every interval.
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	if err := WriteReport(path, Report{V: Version, Server: Server{State: "ready"}}); err != nil {
		t.Fatal(err)
	}
	if err := WriteReport(path, Report{V: Version, Server: Server{State: "bare"}}); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("temp files left behind: %v", names)
	}
	r, err := ReadReport(path)
	if err != nil || r.Server.State != "bare" {
		t.Errorf("second write should have replaced the first: %+v %v", r, err)
	}
}
