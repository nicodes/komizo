package box

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
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

// AND THE GROUP IT IS BORN IN, which the mode above says nothing about.
//
// This is the test that was missing, and its absence is why the failure reached
// a real box: everything here writes and reads a result as the same user, so a
// result nothing else could open passed the whole suite. On the machine it was
// -rw-r----- root:root, the account serving the API is komizo_monitor and in no
// other group, and every GET /v1/commands/{id} answered 404 "no result yet"
// forever -- after an eleven-minute wait for compose and sixteen for app.add,
// with the operator's next move being to press the button again.
//
// A unit test cannot become a second account. What it can do is assert the
// property that DECIDES whether a second account could read the file: the group
// the result lands in. Any group that is not this process's own stands in for
// komizo_monitor, because the difference on the box was exactly "root's group"
// against "somebody else's".
func TestAResultIsBornInTheGroupOfTheDirectoryItLandsIn(t *testing.T) {
	// IN THE ORDER THE BOX DOES IT: the installer creates the directory and
	// hands it to the serving account's group once, and rootd prepares it again
	// on every start for the rest of the machine's life. It is what the second
	// step leaves behind that decides whether a result is readable.
	dir := filepath.Join(t.TempDir(), "results")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	gid, ok := otherGroup(t)
	if !ok {
		// One group and not root, so there is no second group to stand in for
		// the serving account. Not silently green: the mode assertion below
		// still runs, and it is the one that catches the chmod that caused this.
		t.Log("no second group on this machine, so only the directory's mode is checked")
	} else if err := os.Chown(dir, -1, gid); err != nil {
		t.Fatalf("could not give the results directory to group %d: %v", gid, err)
	}
	if err := PrepareResultsDir(dir); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Setgid, or the group is decoration: root creates the file and it is born
	// in ROOT's group whatever the directory is grouped to. rootd's own
	// PrepareResultsDir chmod'ed this to 0750 on every start, clearing the bit
	// the installer had set, and that one line is the whole of the bug.
	if fi.Mode()&os.ModeSetgid == 0 {
		t.Error("the results directory is not setgid, so every result is born in root's group " +
			"and the account that serves this box cannot open one")
	}
	if perm := fi.Mode().Perm(); perm != 0o750 {
		t.Errorf("the results directory is %04o, want 0750", perm)
	}
	if !ok {
		return
	}

	id := "abc123"
	if err := WriteResult(dir, Result{ID: id, Op: OpAppStop, OK: true}); err != nil {
		t.Fatal(err)
	}
	// The FILE, not the directory. It is written to a temporary and renamed, so
	// it is the temporary that has to be created in here -- a result assembled
	// somewhere else and moved in keeps the group it was born with, which is
	// the same trap the installer records about moving an older box's history.
	if got := statGID(t, filepath.Join(dir, id+".json")); got != gid {
		t.Errorf("a result is in group %d, want %d -- it was born in the writer's group "+
			"rather than the directory's, which is a result only root can read", got, gid)
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

// otherGroup is a group to stand in for the serving account's.
//
// Root may hand a file to any group, and gid 1 is a real group on every system
// this runs on -- daemon, bin or sys depending on the distribution -- so the
// number is enough. Anything else has to use a group it is already in.
func otherGroup(t *testing.T) (int, bool) {
	t.Helper()
	if os.Geteuid() == 0 {
		return 1, true
	}
	gids, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range gids {
		if g != os.Getgid() {
			return g, true
		}
	}
	return 0, false
}

func statGID(t *testing.T, path string) int {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no ownership on %s", path)
	}
	return int(st.Gid)
}

// The chgrp is CALLED, which no other test here can establish.
//
// Every guarantee above is checked by writing a result and looking at what
// landed -- which is the right way round, and which cannot see this one.
// `chownToAgentGroup` returns nil early when the serving group does not exist,
// and it never exists in a test, so the call is a no-op here and deleting it
// leaves every other test in this file green. Verified: removing it from
// WriteResult passes the whole suite.
//
// That matters because the chgrp is the mechanism that fixes the bug this file
// was written for. The setgid bit is the primary one and it is checked
// properly -- but on the box where results were unreadable the bit had been
// CLEARED, so setgid is exactly the mechanism that was already failing. A
// belt-and-braces second mechanism that no test can reach is one somebody
// deletes as dead code.
//
// So this reads the source, which is the same thing parity_setup_test.go does
// for the same reason: a call that cannot be observed in a test is still a
// call somebody can remove.
func TestWriteResultActuallyHandsTheFileOver(t *testing.T) {
	src, err := os.ReadFile("result.go")
	if err != nil {
		t.Fatalf("could not read result.go: %v", err)
	}
	body := funcBody(t, string(src), "WriteResult")
	if !strings.Contains(body, "chownToAgentGroup") {
		t.Error("WriteResult no longer gives the file to the serving group.\n" +
			"    On a box whose ServedDir has lost its setgid bit -- which is the box this\n" +
			"    was found on -- every result is born root:root and GET /v1/commands/{id}\n" +
			"    answers \"no result yet\" forever, for every command. See komizo#53.")
	}
	// And its failure is not swallowed. rootd claims a command by writing a
	// result before it acts, so a result nobody can read must stop the work
	// rather than let it happen unreported.
	if strings.Contains(body, "_ = chownToAgentGroup") {
		t.Error("the chgrp's error is discarded, so a box that cannot hand the file over does the work anyway")
	}
}

// funcBody is the same idiom internal/app/parity_setup_test.go owns, for the
// same purpose: asserting on a call that a test cannot otherwise observe.
func funcBody(t *testing.T, src, name string) string {
	t.Helper()
	re := regexp.MustCompile(`(?m)^func (\([^)]*\) )?` + regexp.QuoteMeta(name) + `\(`)
	loc := re.FindStringIndex(src)
	if loc == nil {
		t.Fatalf("could not find func %s", name)
	}
	rest := src[loc[0]:]
	if end := strings.Index(rest, "\n}\n"); end > 0 {
		return rest[:end]
	}
	return rest
}
