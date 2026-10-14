package box

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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

// The property the whole design rests on: root writes the report, and an
// account with no privileges at all reads it. See design/appify.md §3.
//
// The mode on the FILE is not that property, and asserting it was how this got
// missed. report.json was 0644 inside /var/lib/komizo, which is 0750 root:root
// because apps/<app>.env names every deploy account -- so nothing could
// traverse to it and the 644 meant nothing. This test passed the whole time.
//
// So: every directory from the root down has to be traversable by others, and
// the file readable by them. That is the real chain, and it is what moved the
// report to /run/komizo.
func TestTheReportIsReachableBySomethingWithNoPrivileges(t *testing.T) {
	// The layout the installer builds: /run/komizo at 0755, holding the report.
	root := t.TempDir()
	dir := filepath.Join(root, "run", "komizo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "report.json")
	if err := WriteReport(path, Report{V: Version}); err != nil {
		t.Fatal(err)
	}
	if err := reachableByOthers(path, root); err != nil {
		t.Error(err)
	}

	// And the check itself has to be able to fail, or it is decoration -- which
	// is exactly what the mode-only assertion this replaces turned out to be.
	// This is the old layout: a 0644 report inside the 0750 state directory.
	shut := filepath.Join(root, "var", "lib", "komizo")
	if err := os.MkdirAll(shut, 0o750); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(shut, "report.json")
	if err := WriteReport(inside, Report{V: Version}); err != nil {
		t.Fatal(err)
	}
	if err := reachableByOthers(inside, root); err == nil {
		t.Error("a 0644 file inside a 0750 directory reported as reachable")
	}
}

// reachableByOthers reports whether a process that is not root and in no
// relevant group could open this path: every directory leading to it needs
// o+x, and the file itself o+r.
//
// Stops at root rather than walking to /, because a test's own fixture
// directory is 0700 by construction -- Go makes t.TempDir() private, and on a
// real box the chain does go all the way up.
func reachableByOthers(path, root string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o004 == 0 {
		return fmt.Errorf("%s is %v -- not readable by others", path, fi.Mode().Perm())
	}
	for d := filepath.Dir(path); d != root && d != filepath.Dir(d); d = filepath.Dir(d) {
		fi, err := os.Stat(d)
		if err != nil {
			return err
		}
		if fi.Mode().Perm()&0o001 == 0 {
			return fmt.Errorf("%s is %v -- others cannot traverse it, so %s is unreachable",
				d, fi.Mode().Perm(), path)
		}
	}
	return nil
}

// The history is the mirror image: it must NOT be reachable. Nothing
// unprivileged needs it -- the agent posts each report as it is written, and
// the service accumulates history at its end.
func TestTheHistoryIsNotWorldReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.jsonl")
	if err := AppendSample(path, Sample{At: time.Now()}, HistoryMax, HistoryKeep); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o004 != 0 {
		t.Errorf("mode = %v, want nothing for others", fi.Mode().Perm())
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
	// Record retention is independent of the byte bound.
	for i := range 10 {
		s := Sample{At: base.Add(time.Duration(i) * time.Minute), System: System{Cores: i}}
		if err := AppendSample(path, s, HistoryMax, HistoryKeep); err != nil {
			t.Fatal(err)
		}
	}
	if err := trimLines(path, 3, HistoryMax); err != nil {
		t.Fatal(err)
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

func TestHistoryRecoversOversizedLegacyFileWithBoundedMemory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriter(f)
	line := []byte(`{"at":"2026-08-02T12:00:00Z","system":{"cores":7},"padding":"` + strings.Repeat("x", 2500) + "\"}\n")
	for range HistoryKeep {
		if _, err := w.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	if before.Size() < 48<<20 {
		t.Fatal("fixture does not reproduce oversized history")
	}
	runtime.GC()
	var initial, final runtime.MemStats
	runtime.ReadMemStats(&initial)
	latest := Sample{At: time.Date(2026, 8, 2, 12, 1, 0, 0, time.UTC), System: System{Cores: 999}}
	if err := AppendSample(path, latest, HistoryMax, HistoryKeep); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&final)
	if allocated := final.TotalAlloc - initial.TotalAlloc; allocated > 8<<20 {
		t.Fatalf("trim allocated %d bytes for oversized history", allocated)
	}
	fi, _ := os.Stat(path)
	if fi.Size() > HistoryMax/2 {
		t.Fatalf("history retained %d bytes", fi.Size())
	}
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v", fi.Mode())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(data, []byte{'\n'}), []byte{'\n'})
	if len(lines) >= HistoryKeep {
		t.Fatal("byte cap did not reduce record retention")
	}
	for _, line := range lines {
		if !json.Valid(line) {
			t.Fatal("partial retained record")
		}
	}
	var last Sample
	if err := json.Unmarshal(lines[len(lines)-1], &last); err != nil {
		t.Fatal(err)
	}
	if last.System.Cores != 999 {
		t.Fatal("newest record lost")
	}
	// The trim leaves enough headroom for ordinary appends.
	if err := AppendSample(path, latest, HistoryMax, HistoryKeep); err != nil {
		t.Fatal(err)
	}
	second, _ := os.Stat(path)
	if second.Size() <= fi.Size() || second.Size() > HistoryMax {
		t.Fatal("subsequent append rewrote or exceeded retained history")
	}
}

func TestHistoryByteBoundaryKeepsWholeNewestRecords(t *testing.T) {
	for _, limit := range []int64{6, 7, 8, 10} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "history.jsonl")
			if err := os.WriteFile(path, []byte("old\nmid\nnew\n"), 0o640); err != nil {
				t.Fatal(err)
			}
			if err := trimLines(path, 20, limit); err != nil {
				t.Fatal(err)
			}
			got, _ := os.ReadFile(path)
			want := "new\n"
			if limit >= 8 {
				want = "mid\nnew\n"
			}
			if string(got) != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
}

func TestHistoryRefusesOversizedSampleBeforeChangingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.jsonl")
	original := []byte("existing\n")
	if err := os.WriteFile(path, original, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := AppendSample(path, Sample{At: time.Now()}, 1, 3); err == nil {
		t.Fatal("oversized sample accepted")
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, original) {
		t.Fatal("refused append changed file")
	}
}

func TestHistoryTrimPreservesCRLFOffsets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.jsonl")
	if err := os.WriteFile(path, []byte("old\r\nmid\r\nnew\r\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := trimLines(path, 2, HistoryMax); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "mid\r\nnew\r\n" {
		t.Fatalf("corrupted offsets: %q", got)
	}
}
