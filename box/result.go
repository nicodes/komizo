package box

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
	// ONE definition of what an id may be, shared with the envelope. It used to
	// be only here, which meant an id the envelope accepted and this refused
	// was a command the box could neither record nor recognise a replay of.
	if err := ValidCommandID(id); err != nil {
		return "", err
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
// 0640 AND THE GROUP, both, because the mode alone is not the boundary.
//
// Root writes these and the serving account reads them. A file root creates is
// born root:root, so 0640 on its own is a result only root can open -- which is
// the third time this shape has bitten and the second time it shipped. On a
// real box every result was -rw-r----- root:root, the serving account is
// komizo_monitor and in no other group, and GET /v1/commands/{id} therefore
// answered "no result yet" for every command, forever: the operator watched
// eleven minutes of compose work and sixteen of app.add succeed on the machine
// and be reported as a box that never said what happened.
//
// TWO MECHANISMS, DELIBERATELY. The directory is setgid to the serving account
// -- see PrepareResultsDir -- so the file is born in the right group; and it is
// chgrped afterwards anyway, the same as the credential in WriteAgentConf. The
// setgid bit is one chmod away from being cleared by anything that touches the
// directory, and that is precisely how it was cleared here. The chown is a
// no-op on a box where the bit survived, and is the difference between a result
// and a silence on one where it did not.
// DetailMax bounds what a result may carry, IN BYTES, at the writer.
//
// komizo#68. Every bound on Detail used to be at a producer -- runProvision's
// lastLines, composeOut's copy of the same argument -- so the rule was real,
// written down twice, and upheld by convention. `applyOne` sets
// `res.Detail = err.Error()` for ANY error a verb returns, so the next op that
// returns a long error wrote an unbounded result file, which rootd puts under
// ServedDir and the agent then posts. Nothing in the type, the writer or the
// tests said otherwise.
//
// BOUNDED WHERE IT IS WRITTEN, so a producer that forgets is corrected rather
// than trusted. The producers keep their own trims: those are about choosing
// WHICH lines are worth having, which is a judgement this cannot make, and this
// is about how much may leave the box. Two different questions that happen to
// share a number.
const DetailMax = 4 << 10

// trimDetail keeps the TAIL, for the reason lastLines does: the end is where a
// script says why it stopped. The marker is a character rather than silence,
// because a truncated document that does not admit it is one somebody will read
// as the whole answer.
func trimDetail(s string) string {
	if len(s) <= DetailMax {
		return s
	}
	return "…" + s[len(s)-DetailMax:]
}

func WriteResult(dir string, r Result) error {
	r.V = ResultVersion
	// EVERY RESULT, whatever produced it. See DetailMax.
	r.Detail = trimDetail(r.Detail)
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
	// HANDED OVER BEFORE IT LANDS, which is the difference between a box that
	// refuses to work and a box that can never work again. Renaming first and
	// chgrping after left the file in place when the chgrp failed -- and
	// `Applied` is a stat, so that id read as done for ever: rootd refused to
	// apply the command, correctly, and would refuse to apply it again after
	// somebody fixed the permission.
	//
	// FAILING THE WRITE, not logging and carrying on. rootd claims a command by
	// writing a result before it acts, and treats a failed claim as "do not
	// apply" -- so a box that cannot produce a readable result does nothing,
	// loudly, rather than doing the work and reporting nothing. A result nobody
	// can read is the failure this whole function exists to prevent.
	return writeFileAtomicOwned(path, append(b, '\n'), 0o640)
}

// ReadResult returns what happened, whether there is anything to return, and
// whether this box could not tell.
//
// THREE ANSWERS, NOT TWO, and the third one is the whole of this function's
// history. The absence of a result is not an error: a command that has arrived
// and not been applied yet is the normal state for the moment between the two,
// and it is what the app is polling to see change. A result that EXISTS and
// cannot be opened is nothing like that -- it is a fault on this box, and every
// command on it is already done.
//
// Collapsing the two is what made both of the failures in this shape silent.
// paths.go records the first: ReadSamples treated an unreadable history as an
// empty one, so /v1/history answered "no readings" on every box forever. This
// is the second, one directory along -- results were written root:root, the
// serving account could not open one, and the route turned that into 404 "no
// result yet" for every command anyone sent. Neither said "permission"
// anywhere, because neither had anywhere to say it.
//
// A result that is present and unparseable is a fault too. It is a record of
// work that HAS happened, damaged; answering "not yet" about it would leave the
// caller polling for a change that cannot come.
func ReadResult(dir, id string) (Result, bool, error) {
	path, err := resultPath(dir, id)
	if err != nil {
		return Result{}, false, err
	}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Result{}, false, nil
	case err != nil:
		return Result{}, false, err
	}
	var r Result
	if err := json.Unmarshal(b, &r); err != nil {
		return Result{}, false, fmt.Errorf("%s is not readable as a result: %w", path, err)
	}
	return r, true, nil
}

// Applied reports whether this command has already been done.
//
// This is the replay check, and it is a file rather than a set in memory
// because a box restarts. A signed command is valid for minutes; a process that
// forgot every id it had seen would accept every one of them again for the rest
// of that window.
func Applied(dir, id string) bool {
	path, err := resultPath(dir, id)
	if err != nil {
		return false
	}
	// STAT, not parse. Reading it meant a truncated or corrupt result read as
	// "never applied", so a command whose record was damaged ran a second time
	// -- and a half-written file is exactly what a box that lost power mid-write
	// has.
	_, serr := os.Stat(path)
	return serr == nil
}

// PrepareResultsDir makes the directory rootd writes outcomes into.
//
// PrepareServedDir, because this IS a served directory: root writes it and the
// account that serves the box reads it, which is the only property either end
// of that relationship needs. The logs directory is prepared the same way, and
// for the same reason.
//
// It was its own two lines -- MkdirAll and a chmod to 0750 -- and that chmod is
// the whole bug. The installer creates this directory 2750 root:komizo_monitor,
// correctly; rootd then ran this on every start and cleared the setgid bit,
// leaving a directory the serving account could list and files born in root's
// group that it could not open. So every result was root:root 0640 and every
// GET /v1/commands/{id} answered "no result yet" until the file was swept.
//
// A separate implementation of "root writes here, the agent reads here" is a
// second opinion about a boundary that has now been got wrong five times. There
// is one.
func PrepareResultsDir(path string) error {
	return PrepareServedDir(path)
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
