package box

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// What happened to a command.
//
// komizo-be design/app-only.md §4: "Half of the interaction is finding out
// whether it worked. Fire-and-forget would leave it guessing, and the one thing
// worse than an operation that fails is one that silently might have."
//
// Written by rootd, into ServedDir, so the account that serves the box can read
// it and hand it back. That is the other direction of the same split: the inbox
// is the account writing for root, and this is root writing for the account.
//
// THE RESULT IS ALSO THE REPLAY RECORD. A command's id names its result, so a
// second arrival of an id that already has one is the same command and is
// already done. Keeping that on disk rather than in memory is deliberate: a
// box restarts, and a replay window that resets on restart is not one.

// ResultsDir is the default. Passed explicitly to everything below rather than
// read from here, so a test can point at a temp directory -- the same seam
// Probe.Root and AppDir already are, and the reason the replay check below is
// testable at all.
//
// ResultsDir is where they live. Under ServedDir because the reader is the
// serving account, and that directory is already the one root writes into for
// it -- see PrepareServedDir.
const ResultsDir = ServedDir + "/results"

// ResultVersion is this document's schema, stated for the reason every other
// document here states one: the box and the app are separate releases.
const ResultVersion = 1

// ResultKept is how long a result stays readable.
//
// Long enough that somebody who pressed a button, locked their phone and came
// back can still see what happened; short enough that a box does not accumulate
// a file per command forever. It also bounds the replay record, which is the
// reason this is not simply "until the disk fills": a command's own expiry is
// minutes, so an id can be safely forgotten long before this.
const ResultKept = 24 * time.Hour

// Result is what rootd writes when it has finished with a command.
type Result struct {
	V  int    `json:"v"`
	ID string `json:"id"`
	Op string `json:"op"`
	// At is when it finished, from the box's own clock -- the same choice the
	// report makes, and for the same reason.
	At time.Time `json:"at"`
	OK bool      `json:"ok"`
	// Detail is prose for a person and is empty when it worked. It is the
	// command's own failure, not a diagnosis of the box.
	Detail string `json:"detail,omitempty"`
}

func (r Result) Schema() int { return r.V }

// resultPath is where one lives, and it refuses an id that is not one.
//
// The id comes out of a signed document, which is not the same as being safe to
// join into a path: it is chosen by whoever signed, and a device that has been
// planted can still be a device somebody lost. Checked rather than trusted.
func resultPath(dir, id string) (string, error) {
	if id == "" || len(id) > 64 || strings.ContainsAny(id, "/.") {
		return "", fmt.Errorf("%q is not a command id", id)
	}
	return filepath.Join(dir, id+".json"), nil
}

// WriteResult records the outcome, atomically.
//
// Atomically because the serving account reads these on its own schedule and
// the two are not coordinated -- a reader that caught a half-written document
// would get a JSON error, and the honest reading of a JSON error from a box is
// "this is broken", which would be a lie told every time.
//
// 0640: root writes, the serving account reads. ServedDir is setgid to that
// account, so the file is born in a group that can open it. Same boundary as
// the history, and the mode is load-bearing rather than decorative.
func WriteResult(dir string, r Result) error {
	r.V = ResultVersion
	path, err := resultPath(dir, r.ID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(b, '\n'), 0o640)
}

// ReadResult returns what happened, or false if nothing has.
//
// The absence of a result is not an error: a command that has arrived and not
// been applied yet is the normal state for the moment between the two, and it
// is what the app is polling to see change.
func ReadResult(dir, id string) (Result, bool) {
	path, err := resultPath(dir, id)
	if err != nil {
		return Result{}, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Result{}, false
	}
	var r Result
	if err := json.Unmarshal(b, &r); err != nil {
		return Result{}, false
	}
	return r, true
}

// Applied reports whether this command has already been done.
//
// This is the replay check, and it is a file rather than a set in memory
// because a box restarts. A signed command is valid for minutes; a process that
// forgot every id it had seen would accept every one of them again for the rest
// of that window.
func Applied(dir, id string) bool {
	_, ok := ReadResult(dir, id)
	return ok
}

// PruneResults removes what is older than ResultKept.
//
// Swept rather than expired on read, because nothing would ever read the ones
// that matter here: an id nobody asks about again is exactly the one that
// accumulates.
func PruneResults(dir string, now time.Time) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		// No directory is a box that has been told nothing, not a failure.
		return nil
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) > ResultKept {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
	return nil
}
