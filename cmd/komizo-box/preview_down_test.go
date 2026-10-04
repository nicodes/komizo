package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `preview down` is asked to leave nothing behind, so a preview that is not
// recorded is the state it wanted -- not a failure.
//
// This is the normal path, not an edge case. The TTL reaper removes previews
// on its own schedule, so closing a pull request whose preview has already
// expired used to fail the teardown job with
//
//	komizo-box: no preview of ctcalc PR #151 exists
//
// which put a red mark on the close for a box in exactly the right state, on
// every product that has previews.
func TestPreviewDownOnAnAlreadyGonePreviewSucceeds(t *testing.T) {
	root := t.TempDir()
	var failed error
	said := captureStdout(t, func() {
		failed = runPreview([]string{"down", "--app", "ctcalc", "--pr", "151", "--root", root})
	})
	if failed != nil {
		t.Fatalf("down on an absent preview failed: %v", failed)
	}
	if !strings.Contains(said, "nothing to take down") {
		t.Errorf("down said %q, which does not tell an operator the box was already in the wanted state", said)
	}
}

// And it still refuses what it cannot read. "Already gone" is a claim about
// the records; a state root that cannot be listed supports no such claim, and
// reporting it as an absent preview would turn a broken box into a green job.
func TestPreviewDownStillFailsWhenTheRecordsCannotBeRead(t *testing.T) {
	root := t.TempDir()
	previews := filepath.Join(root, "previews")
	if err := os.MkdirAll(previews, 0o750); err != nil {
		t.Fatal(err)
	}
	// Unreadable rather than absent. Skipped for root, which ignores the bit.
	if err := os.Chmod(previews, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(previews, 0o750) })
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits do not deny a read")
	}

	if err := runPreview([]string{"down", "--app", "ctcalc", "--pr", "151", "--root", root}); err == nil {
		t.Fatal("down reported success on a state root it could not read")
	}
}
