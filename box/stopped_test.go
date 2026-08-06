package box

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The record an app already has, which this must not damage.
//
// It is the only place on the box that says where an app lives and which
// account deploys it -- AppDir reads it, the generated deploy script reads it,
// and alpine.sh's own comment calls it "what komizo knows about this app". A
// write that loses a line here is a box that has forgotten an app, so what is
// being asserted is the whole file rather than the field that changed.
const aRecord = `# Written by komizo. This is what komizo knows about this app; edit with
# 'komizo add' rather than by hand.
APP_NAME=blog
APP_DIR=/srv/blog
CI_USER=komizo-blog
CONFIG_IMAGE=ghcr.io/n/blog-config
KNOWN_AS=blog.example.com
`

func recordFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, AppsDir), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, AppsDir, "blog.env"), []byte(aRecord), 0o640); err != nil {
		t.Fatal(err)
	}
	return root
}

func recordOf(t *testing.T, root string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, AppsDir, "blog.env"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestAStopIsAddedWithoutDisturbingTheRecord(t *testing.T) {
	root := recordFixture(t)
	at := time.Date(2026, 8, 5, 10, 30, 0, 0, time.UTC)
	if err := MarkStopped(root, "blog", StoppedByCLI, at); err != nil {
		t.Fatal(err)
	}

	got := recordOf(t, root)
	if !strings.HasPrefix(got, aRecord) {
		t.Errorf("the record was rewritten rather than added to:\n%s", got)
	}
	for _, want := range []string{"STOPPED=1", "STOPPED_AT=2026-08-05T10:30:00Z", "STOPPED_BY=cli"} {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("record has no %q:\n%s", want, got)
		}
	}
	// And the app is still findable, which is the property that matters more
	// than the bytes: a record this could not resolve is an app komizo can no
	// longer act on at all.
	if dir, err := AppDir(root, "blog"); err != nil || dir != "/srv/blog" {
		t.Errorf("AppDir after a stop = %q, %v", dir, err)
	}
}

// Stopping twice leaves ONE stop.
//
// readState takes the first occurrence of a key and the deploy shell's `sed |
// head -n 1` does too, so a second copy appended below the first is a value
// that is invisible now and becomes live the moment anything removes the one
// above it. An app stopped, started and stopped again is an ordinary week.
func TestStoppingTwiceDoesNotAccumulate(t *testing.T) {
	root := recordFixture(t)
	at := time.Date(2026, 8, 5, 10, 30, 0, 0, time.UTC)
	if err := MarkStopped(root, "blog", StoppedByCLI, at); err != nil {
		t.Fatal(err)
	}
	if err := MarkStopped(root, "blog", "device kmz_dev_AAAAAAAA…BBBBBBBB", at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	got := recordOf(t, root)
	if n := strings.Count(got, "STOPPED_BY="); n != 1 {
		t.Errorf("%d STOPPED_BY lines, want 1:\n%s", n, got)
	}
	if !strings.Contains(got, "STOPPED_AT=2026-08-05T11:30:00Z") || strings.Contains(got, "T10:30:00Z") {
		t.Errorf("the second stop did not replace the first:\n%s", got)
	}
}

// Clearing takes ALL of it off, not just the flag.
//
// A running app whose record still names who stopped it and when is a record
// nobody can read honestly, and it is the state a `start` that only cleared
// STOPPED would leave behind.
func TestStartingClearsEveryPartOfTheStop(t *testing.T) {
	root := recordFixture(t)
	if err := MarkStopped(root, "blog", StoppedByCLI, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := ClearStopped(root, "blog"); err != nil {
		t.Fatal(err)
	}

	if got := recordOf(t, root); got != aRecord {
		t.Errorf("the record did not go back to what it was:\n%s", got)
	}
	// Clearing a stop that is not there is not an error: `komizo start` on an
	// app that was never stopped is an ordinary thing to run.
	if err := ClearStopped(root, "blog"); err != nil {
		t.Errorf("clearing a record with no stop in it = %v", err)
	}
}

// A VALUE MUST NOT BE ABLE TO FORGE THE NEXT KEY.
//
// The record is key=value lines and readState splits on them, so a STOPPED_BY
// carrying a newline writes whatever follows it as a key of its own. APP_DIR is
// the one that matters: it is what resolveSubject hands to `docker compose
// --project-directory`.
//
// It would not take effect immediately, and setStateValues says why at length:
// the managed keys are appended last, and every reader of this file is
// first-wins, so a forged APP_DIR sits below the genuine one and loses. What it
// would be is PERMANENT -- APP_DIR is not a managed key, so ClearStopped leaves
// it there after the stop is over -- and live the moment anything removes or
// reorders the genuine line. This test pins the refusal, not the ordering that
// currently makes the refusal survivable.
//
// Nothing can reach it today either: both callers pass a value from a closed
// set. Which is exactly the condition that makes a check look unnecessary right
// up until a later op carries a label somebody typed.
func TestAStopCannotForgeAnotherKey(t *testing.T) {
	root := recordFixture(t)
	for _, bad := range []string{
		"cli\nAPP_DIR=/srv/theirs",
		"cli\rAPP_DIR=/srv/theirs",
		strings.Repeat("x", maxStateValue+1),
	} {
		if err := MarkStopped(root, "blog", bad, time.Now()); err == nil {
			t.Errorf("MarkStopped accepted %q", bad)
		}
	}
	if got := recordOf(t, root); got != aRecord {
		t.Errorf("a refused stop still changed the record:\n%s", got)
	}
}

// A name is not a path, and an app that does not exist is not created.
//
// The same rule AppDir enforces, asserted through the writer because this one
// JOINS the name into a filename and then writes to it -- a check that only
// exists on the read side is a check the write side does not have.
func TestAStopNamesAnAppThatExists(t *testing.T) {
	root := recordFixture(t)
	for _, bad := range []string{"", "../../etc/passwd", "a/b", "blog.env"} {
		if err := MarkStopped(root, bad, StoppedByCLI, time.Now()); err == nil {
			t.Errorf("MarkStopped accepted the name %q", bad)
		}
	}
	// A well-formed name for an app this box has never heard of. Refused rather
	// than created: a record with no APP_DIR in it is a box mid-removal to
	// every reader of paths.go.
	if err := MarkStopped(root, "nosuchapp", StoppedByCLI, time.Now()); err == nil {
		t.Error("MarkStopped invented a record for an app that does not exist")
	}
	if _, err := os.Stat(filepath.Join(root, AppsDir, "nosuchapp.env")); err == nil {
		t.Error("it wrote the file anyway")
	}
}

// The record stays as closed as alpine.sh made it.
//
// 0640 root:root inside a 0750 directory, because the file names every app's
// deploy account and directory -- paths.go's own reason for the mode on
// StateDir. A rewrite that widened it would be a permission change nobody
// asked for and nothing would say.
func TestTheRecordKeepsItsMode(t *testing.T) {
	root := recordFixture(t)
	path := filepath.Join(root, AppsDir, "blog.env")
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := MarkStopped(root, "blog", StoppedByCLI, time.Now()); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v, want 0640", st.Mode().Perm())
	}
}

// And the report reads back exactly what was written.
//
// The two halves of komizo#48 meeting: this file's format and probe.go's parse
// are the same agreement written twice, and the way that agreement breaks is a
// timestamp layout or a key name that only one side changed. The end-to-end
// version of this lives in cmd/komizo-box, where the stop is run rather than
// called.
func TestWhatIsWrittenIsWhatTheProbeReads(t *testing.T) {
	f := readyBox(t)
	at := time.Date(2026, 8, 5, 10, 30, 0, 0, time.UTC)
	if err := MarkStopped(f.root, "blog", StoppedByCLI, at); err != nil {
		t.Fatal(err)
	}

	a := f.probe().Report(context.Background()).Apps[0]
	if !a.Stopped || a.StoppedBy != StoppedByCLI || !a.StoppedAt.Equal(at) {
		t.Errorf("the probe read %+v back from what MarkStopped wrote", a)
	}
}
