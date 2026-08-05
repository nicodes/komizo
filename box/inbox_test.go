package box

import (
	"os"
	"strings"
	"testing"
)

// The inbox is the account writing FOR root, which is the socket directory's
// shape reversed -- and the mode is what makes it so.
//
// There was no test at all: three separate mutations of PrepareInboxDir passed
// a full suite, including dropping setgid entirely and grouping the directory to
// the agent instead of root. The two directories beside it both have mode tests;
// this was the omission.
func TestTheInboxIsWritableByTheAccountAndReadableByRoot(t *testing.T) {
	if InboxDirMode&os.ModeSetgid == 0 {
		t.Error("the inbox is not setgid, so a command is born in the agent's group " +
			"rather than the directory's")
	}
	if perm := InboxDirMode.Perm(); perm&0o700 != 0o700 {
		t.Errorf("the inbox is %04o: the account that must create commands cannot", perm)
	}
	if perm := InboxDirMode.Perm(); perm&0o007 != 0 {
		t.Errorf("the inbox is %04o: anything on the box can drop a command in it", perm)
	}
	// On tmpfs. A command carries an expiry in minutes, and one that outlived a
	// reboot would be a machine acting on something asked for before it died.
	if !strings.HasPrefix(InboxDir, RunDir) {
		t.Errorf("the inbox is at %q, which is not under %q and so survives a reboot", InboxDir, RunDir)
	}
	// And results go the other way, into the directory that survives one --
	// they are the replay record.
	if !strings.HasPrefix(ResultsDir, ServedDir) {
		t.Errorf("results are at %q, not under %q, so the serving account cannot read them",
			ResultsDir, ServedDir)
	}
}
