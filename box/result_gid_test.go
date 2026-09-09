//go:build !windows && !plan9

package box

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

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
