package box

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// AN ID IS THE ONLY THING BETWEEN A SIGNED COMMAND AND AN ARBITRARY WRITE.
//
// The id is chosen by whoever signed and is joined into a path. With this check
// gone, a validly signed command carrying an id of "../../../../tmp/PWNED" made
// root write there. It looks redundant next to a random-id generator, which is
// exactly how a check like this gets simplified away.
func TestAResultCannotBeWrittenOutsideItsDirectory(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()

	rel, err := filepath.Rel(dir, filepath.Join(outside, "PWNED"))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{rel, "../x", "a/b", "a.b", "", strings.Repeat("x", 65)} {
		if err := WriteResult(dir, Result{ID: bad, Op: OpAppStop}); err == nil {
			t.Errorf("a result was written for id %q", bad)
		}
	}
	if _, err := os.Stat(filepath.Join(outside, "PWNED.json")); err == nil {
		t.Fatal("root wrote outside the results directory")
	}

	// And an ordinary id still works, so this is not refusing everything.
	id, err := NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteResult(dir, Result{ID: id, Op: OpAppStop, OK: true}); err != nil {
		t.Fatalf("an ordinary result was refused: %v", err)
	}
	if !Applied(dir, id) {
		t.Error("a result that was written does not read as applied")
	}
}

// A DAMAGED RECORD MUST NOT READ AS "NEVER HAPPENED".
//
// Applied used to parse the file, so a truncated result -- which is what a box
// that lost power mid-write has -- made a command run a second time.
func TestACorruptResultStillCountsAsApplied(t *testing.T) {
	dir := t.TempDir()
	id := "abc123"
	if err := WriteResult(dir, Result{ID: id, Op: OpAppStop, OK: true}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id+".json"), []byte(`{"v":1,"id":"ab`), 0o640); err != nil {
		t.Fatal(err)
	}
	if !Applied(dir, id) {
		t.Error("a corrupt result reads as never applied, so the command would run again")
	}
	// Reading it still fails honestly -- this is about the replay decision, not
	// about pretending the document is readable. And it says so: a damaged
	// record is a fault, not a command that has not finished, and the route
	// tells those two apart.
	r, ok, err := ReadResult(dir, id)
	if ok {
		t.Errorf("a corrupt result was returned as readable: %+v", r)
	}
	if err == nil {
		t.Error("a corrupt result read as 'no result yet', so the app polls it forever")
	}
}

func TestOldResultsAreSweptAndRecentOnesKept(t *testing.T) {
	dir := t.TempDir()
	for _, id := range []string{"keepme", "dropme"} {
		if err := WriteResult(dir, Result{ID: id, Op: OpAppStop, OK: true}); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-2 * ResultKept)
	if err := os.Chtimes(filepath.Join(dir, "dropme.json"), past, past); err != nil {
		t.Fatal(err)
	}
	if err := PruneResults(dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	if Applied(dir, "dropme") {
		t.Error("a result past its keep window survived")
	}
	if !Applied(dir, "keepme") {
		t.Error("a recent result was swept")
	}
}

// 0640, and the group bit is the boundary rather than decoration.
//
// Root writes these and the serving account reads them to hand back; ServedDir
// is setgid to that account, so the file is born in a group that can open it.
// Without the mode this is a result only root can see, and the app polls
// forever.
func TestAResultIsReadableByTheAccountThatServesIt(t *testing.T) {
	dir := t.TempDir()
	id := "abc123"
	if err := WriteResult(dir, Result{ID: id, Op: OpAppStop, OK: true}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o640 {
		t.Errorf("a result is %04o, want 0640 -- the group is what lets it be served", perm)
	}
}

// A DIRECTORY THAT ALREADY EXISTS IS THE CASE THAT MATTERS.
//
// The installer creates this 2750 root:komizo_monitor on the first install and
// never again. Every start after that, rootd finds it there -- and MkdirAll
// leaves an existing directory alone, so whatever this does to one that is
// already present is what a box actually runs with. What it did was chmod 0750,
// which is the correct permissions and the wrong bit.
func TestPreparingAnExistingResultsDirectoryPutsTheSetgidBitBack(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "results")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := PrepareResultsDir(dir); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSetgid == 0 {
		t.Error("a results directory that had lost the setgid bit did not get it back, " +
			"so every result written after an operator or a restore touched it is unreadable")
	}
}

// ABSENT AND UNREADABLE ARE NOT THE SAME ANSWER.
//
// paths.go records the first time these were collapsed: an unreadable history
// read as an empty one, so /v1/history said "no readings" on every box forever
// and nothing anywhere mentioned permission. Results collapsed them again --
// ReadResult returned false for both and the route turned that into 404 -- so
// there was no signal at all: not in the response, not in a log.
func TestAResultThatCannotBeReadIsNotAResultThatIsNotThereYet(t *testing.T) {
	dir := t.TempDir()

	// Nothing written. Absent, and not an error: this is the normal state of
	// every command for the moment between arriving and being applied, and it
	// is what the app is polling to see change.
	if _, ok, err := ReadResult(dir, "neverheard"); ok || err != nil {
		t.Errorf("an unapplied command = (%v, %v), want (false, nil)", ok, err)
	}

	// Present and unopenable. A DIRECTORY where the file should be, because
	// that fails for root as well: a file with mode 0 is still readable by
	// root, so a test built on one asserts nothing wherever the suite runs
	// privileged -- and a check that quietly stops checking is how this class
	// of bug got here in the first place.
	if err := os.Mkdir(filepath.Join(dir, "blocked.json"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := ReadResult(dir, "blocked"); ok || err == nil {
		t.Errorf("an unreadable result = (%v, %v), want it reported as a fault", ok, err)
	}

	// And the real shape of it on the box, when the suite is not root: the file
	// is there, it is a result, and this process may not open it.
	if os.Geteuid() == 0 {
		return
	}
	if err := WriteResult(dir, Result{ID: "closed", Op: OpAppStop, OK: true}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "closed.json"), 0); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := ReadResult(dir, "closed"); ok || err == nil {
		t.Errorf("a result this process cannot open = (%v, %v), want it reported as a fault", ok, err)
	}
}

// THE HAND-OVER IS EXERCISED, not grepped for.
//
// The first version of this test read result.go and looked for the call, on the
// grounds that the serving group does not exist on a test machine so the call
// is a no-op. Review showed why that is not enough: moving the swallowed error
// one level down, into chownToAgentGroup itself, keeps the grepped string,
// breaks the behaviour, and leaves the whole suite green. A test that asserts a
// call exists is not a test of what the call does.
//
// So lookupAgentGroup is a seam, and this drives the real path through it.
func TestAResultIsNotWrittenIfItCannotBeHandedOver(t *testing.T) {
	dir := t.TempDir()

	// The hand-over fails. INJECTED rather than engineered from a hostile gid,
	// because root can chown to any group and a test that picks an impossible
	// one silently stops checking anything the moment CI runs as root.
	restoreLookup := lookupAgentGroup
	lookupAgentGroup = func(string) (*user.Group, error) {
		return &user.Group{Gid: "1001", Name: AgentUser}, nil
	}
	defer func() { lookupAgentGroup = restoreLookup }()
	restoreChown := chownFile
	chownFile = func(string, int, int) error { return errors.New("operation not permitted") }
	defer func() { chownFile = restoreChown }()

	err := WriteResult(dir, Result{ID: "handover", Op: "app.start", OK: true})
	if err == nil {
		t.Fatal("a result that could not be handed to the serving group was written anyway.\n" +
			"    On the box this was found on, every result was born root:root and\n" +
			"    GET /v1/commands/{id} answered \"no result yet\" for ever. See komizo#53.")
	}

	// AND NOTHING LANDED. This is the half that matters more than the error:
	// `Applied` is a stat, so a file left behind by a failed hand-over reads as
	// done for ever -- rootd would refuse to apply the command, correctly, and
	// refuse to apply it again after somebody fixed the permission. A box in
	// that state cannot be repaired without deleting files by hand.
	if _, err := os.Stat(filepath.Join(dir, "handover.json")); !os.IsNotExist(err) {
		t.Errorf("a failed hand-over left the claim on disk (stat = %v), so this command can never be applied", err)
	}
	// And no temp file either.
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		t.Errorf("left behind: %s", e.Name())
	}
}

// And the ordinary path still works with the seam in place, so the test above
// is proving a refusal rather than a broken writer.
func TestAResultIsWrittenWhenTheGroupIsReal(t *testing.T) {
	dir := t.TempDir()
	restore := lookupAgentGroup
	lookupAgentGroup = func(string) (*user.Group, error) {
		return nil, errors.New("no such group")
	}
	defer func() { lookupAgentGroup = restore }()

	if err := WriteResult(dir, Result{ID: "ok", Op: "app.start", OK: true}); err != nil {
		t.Fatalf("WriteResult on a machine with no serving group = %v, want it to work", err)
	}
	if _, ok, err := ReadResult(dir, "ok"); !ok || err != nil {
		t.Errorf("ReadResult = (%v, %v), want it readable", ok, err)
	}
}

// A result's Detail is bounded by the WRITER, not only by each producer.
//
// komizo#68. Every bound used to be at a producer -- runProvision's lastLines,
// composeOut's copy of the same argument -- so the rule was real, written down
// twice, and upheld by convention. `applyOne` sets `res.Detail = err.Error()`
// for ANY error a verb returns, so the next op returning a long error wrote an
// unbounded result file, which rootd puts under ServedDir and the agent posts.
func TestWriteResultBoundsDetail(t *testing.T) {
	dir := t.TempDir()
	// ONE LINE, deliberately. A bound on LINES does not catch this, and that
	// gap is the difference between the producers' trim and this one.
	huge := strings.Repeat("x", DetailMax*4)
	if err := WriteResult(dir, Result{ID: "abc123", Op: "app.stop", Detail: huge}); err != nil {
		t.Fatalf("WriteResult = %v", err)
	}
	got, done, err := ReadResult(dir, "abc123")
	if err != nil || !done {
		t.Fatalf("ReadResult = %v, done = %v", err, done)
	}
	if len(got.Detail) > DetailMax+len("\u2026") {
		t.Errorf("Detail is %d bytes, want at most %d: the writer did not bound it",
			len(got.Detail), DetailMax+len("\u2026"))
	}
	// THE TAIL SURVIVES, for the reason lastLines keeps it: the end is where
	// something says why it stopped. And it marks itself, because a truncated
	// document that does not admit it is one somebody reads as the whole answer.
	if !strings.HasSuffix(got.Detail, "x") || !strings.HasPrefix(got.Detail, "\u2026") {
		t.Errorf("the truncation did not keep the tail and mark itself: %.40q", got.Detail)
	}
}

// And a Detail that fits is not touched at all.
//
// The assertion that stops the bound becoming a mangler: almost every result is
// short, and a marker prepended to those would be a claim of truncation that
// did not happen.
func TestWriteResultLeavesAShortDetailAlone(t *testing.T) {
	dir := t.TempDir()
	const want = "exit status 1\ncompose: no such service"
	if err := WriteResult(dir, Result{ID: "def456", Op: "app.stop", Detail: want}); err != nil {
		t.Fatalf("WriteResult = %v", err)
	}
	got, _, err := ReadResult(dir, "def456")
	if err != nil {
		t.Fatalf("ReadResult = %v", err)
	}
	if got.Detail != want {
		t.Errorf("Detail = %q, want %q", got.Detail, want)
	}
}
