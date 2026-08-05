package box

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// The route that lets somebody tell this box something.
//
// komizo-be design/app-only.md §4, and the sentence the whole design turns on:
//
//	The API is the TRANSPORT. The signature is the AUTHORITY.
//
// So this route does not act. It writes a signed blob into the inbox and
// answers; rootd verifies it against keys an operator planted with root, and
// applies it. This process runs as komizo_monitor -- no shell, no docker group,
// no doas -- and holds no signing key, so it could not forge a command if it
// were compromised. It is a dropbox.
//
// BOTH, NOT EITHER. The route still requires a registry read token, the same as
// every other route here. The token gates the DOOR and the signature gates the
// ACT, and they answer different questions: without the token, an
// unauthenticated stranger can post blobs at a box until its disk is full, and
// api.go is deliberate that there is no unauthenticated route on this API at
// all, "not even a health check".

// InboxFull is how many commands may be waiting before this route says no.
//
// Below the sweep rootd applies, so the answer to a full inbox is "try again"
// rather than a box quietly discarding work. Bounded because the directory is
// tmpfs, and tmpfs is memory.
const InboxFull = 128

// acceptedResponse is what a caller gets for a command that has been taken.
//
// The ID is what they poll. Nothing here says the command WORKED -- it has not
// run yet, and pretending otherwise would be the fire-and-forget §4 refuses.
type acceptedResponse struct {
	V      int    `json:"v"`
	ID     string `json:"id"`
	Status string `json:"status"`
}

// resultResponse is what happened, once something has.
type resultResponse struct {
	V      int    `json:"v"`
	Result Result `json:"result"`
}

func (r resultResponse) Schema() int { return r.V }

// postCommand takes a signed command and puts it where rootd will find it.
func postCommand(cfg APIConfig, w http.ResponseWriter, r *http.Request) {
	if cfg.InboxDir == "" || cfg.ResultsDir == "" || len(cfg.OperatorKeys) == 0 {
		// A box nobody has given a device to. Said plainly rather than accepted
		// and silently never applied, because "the button did nothing" is the
		// worst version of this.
		http.Error(w, "this box takes orders from nobody", http.StatusConflict)
		return
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxCommandBytes+1))
	if err != nil {
		// A caller that went away mid-body. Not the same as one that sent too
		// much, and answering "too large" would send somebody looking for a
		// size problem they do not have.
		http.Error(w, "could not read that command", http.StatusBadRequest)
		return
	}
	if len(raw) > MaxCommandBytes {
		http.Error(w, "that command is too large", http.StatusRequestEntityTooLarge)
		return
	}

	// Verified HERE TOO, and this is a courtesy rather than the authority.
	//
	// rootd verifies again and its answer is the one that decides anything --
	// this process could be compromised and this check skipped, which is why
	// the same work happens at root. What it buys is that a caller learns
	// immediately that its signature is wrong, instead of polling a result that
	// will never appear; and that the inbox does not fill with things nothing
	// will ever apply.
	//
	// The keys are PUBLIC, so holding them grants nothing. Verifying with a
	// public key is not the same as being able to sign.
	c, _, err := VerifyCommand(cfg.OperatorKeys, raw, cfg.ServerID, cfg.Now())
	if err != nil {
		// A version this box does not speak, or an op it does not know, is NOT a
		// refusal: the signature has already verified, so the caller is a device
		// this box trusts and §4 says it is entitled to a sentence rather than a
		// silence. Collapsing these into the opaque 403 left an app that is
		// ahead of a box unable to tell "wrong key" from "I do not know that",
		// and made rootd's own handling of them unreachable from the app.
		if !errors.Is(err, ErrCommandRefused) {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		// Everything else is one answer, the same as the read routes: which
		// reason it was is not this caller's business.
		http.Error(w, "this box will not act on that", http.StatusForbidden)
		return
	}

	// Already done. Answered from the record rather than queued again, so a
	// retry after a dropped response is idempotent instead of a second stop.
	if res, ok := ReadResult(cfg.ResultsDir, c.ID); ok {
		writeJSON(w, resultResponse{V: ResultVersion, Result: res})
		return
	}

	// COUNTED AND WRITTEN UNDER ONE LOCK. net/http gives every request its own
	// goroutine with no cap, so counting and then writing let concurrent callers
	// all see room and all take it -- four hundred at once put a hundred and
	// fifty-nine files behind a bound of a hundred and twenty-eight. rootd's own
	// sweep pulls that back within half a second, so it was a bounded spike on
	// tmpfs rather than an unbounded one, but the bound should mean what it says.
	//
	// Cheap: the whole of it is one ReadDir and one write, on tmpfs.
	inboxMu.Lock()
	err = takeCommand(cfg.InboxDir, c.ID, raw)
	inboxMu.Unlock()
	switch {
	case errors.Is(err, errInboxFull):
		// 503 and not 500: it is a state that passes. rootd sweeps and applies
		// on its own timer, so the honest answer is "not now".
		http.Error(w, "this box has too many commands waiting", http.StatusServiceUnavailable)
		return
	case err != nil:
		http.Error(w, "this box could not take that command", http.StatusServiceUnavailable)
		return
	}
	writeJSONStatus(w, http.StatusAccepted, acceptedResponse{V: CommandVersion, ID: c.ID, Status: "accepted"})
}

// getResult answers what happened to one command.
func getResult(cfg APIConfig, w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if ValidCommandID(id) != nil {
		// Refused rather than looked up: this is joined into a path, and the
		// same rule the envelope applies is the rule here.
		refuse(w)
		return
	}
	res, ok := ReadResult(cfg.ResultsDir, id)
	if !ok {
		// Not an error. A command that has arrived and not been applied yet is
		// the normal state for the moment between the two, and it is exactly
		// what the caller is polling to see change.
		http.Error(w, "no result yet", http.StatusNotFound)
		return
	}
	writeJSON(w, resultResponse{V: ResultVersion, Result: res})
}

// TempPrefix marks a command that is still being written.
//
// A DOT, and that is the contract with rootd rather than a convention: it reads
// this directory on a timer and must not pick up a file mid-write. It did, and
// the result was a command applied and then removed, so the route's rename
// failed and the caller was told 503 for work that had already happened.
//
// Exported so the reader uses this and not a literal of its own. Two spellings
// of "still being written" is one spelling that stops matching.
const TempPrefix = ".tmp-"

// IsTemporary reports whether a name in the inbox is one of those.
func IsTemporary(name string) bool { return strings.HasPrefix(name, ".") }

// inboxMu serialises the count and the write. See postCommand.
var inboxMu sync.Mutex

// errInboxFull is the bound, reported so the caller can be told to try again
// rather than that something went wrong.
var errInboxFull = errors.New("the inbox is full")

// takeCommand is the bounded write: count, then store, with nothing in between.
func takeCommand(dir, id string, raw []byte) error {
	full, err := inboxFull(dir)
	if err != nil {
		return err
	}
	if full {
		return errInboxFull
	}
	return writeCommand(dir, id, raw)
}

// writeCommand puts the blob where rootd looks, named by its id.
//
// NAMED BY THE ID, which makes arrival idempotent: the same command posted
// twice is one file, so a retry after a dropped response does not queue a
// second stop. The id has already been through ValidCommandID inside
// VerifyCommand, and is checked again here because this is the line that joins
// it to a path.
//
// Written to a temporary name and renamed, so rootd never reads a file that is
// still being written. Rename within one directory is atomic.
//
// That matters more than it looks: rootd REMOVES what it reads, always and
// before it verifies. A half-written command would therefore not merely fail to
// verify -- it would be deleted, and the caller would poll for a result that
// never comes, for a command nothing ever refused out loud. The temporary is
// dot-prefixed and swept by rootd if this process dies between the two steps.
func writeCommand(dir, id string, raw []byte) error {
	if err := ValidCommandID(id); err != nil {
		return err
	}
	final := filepath.Join(dir, id)
	if fi, err := os.Stat(final); err == nil {
		if !fi.Mode().IsRegular() {
			// Something that is not a command is sitting where one would go.
			// Refused rather than treated as "already waiting", which reported
			// success and queued nothing -- the silent kind of failure this
			// route exists to avoid.
			return fmt.Errorf("%s is not a command file", final)
		}
		// Already waiting. Not an error: it is the same command.
		return nil
	}
	tmp, err := os.CreateTemp(dir, TempPrefix+"*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// No chmod: os.CreateTemp already makes it 0600 and a umask can only clear
	// bits further. The line that was here did nothing, and it did it inside the
	// window between writing and renaming -- which is the window rootd was
	// reading in.
	return os.Rename(tmp.Name(), final)
}

// inboxFull reports whether the inbox has reached its bound.
//
// Counted rather than remembered, because rootd drains it and this process does
// not hear about that. Temporaries are counted too -- they occupy the same
// memory.
func inboxFull(dir string) (bool, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	return len(ents) >= InboxFull, nil
}
