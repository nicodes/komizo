package box

import (
	"os"
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
	// about pretending the document is readable.
	if _, ok := ReadResult(dir, id); ok {
		t.Error("a corrupt result was returned as readable")
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
