package box

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
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
	if cfg.InboxDir == "" || len(cfg.OperatorKeys) == 0 {
		// A box nobody has given a device to. Said plainly rather than accepted
		// and silently never applied, because "the button did nothing" is the
		// worst version of this.
		http.Error(w, "this box takes orders from nobody", http.StatusConflict)
		return
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxCommandBytes+1))
	if err != nil || len(raw) > MaxCommandBytes {
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
	c, _, err := VerifyCommand(cfg.OperatorKeys, raw, cfg.ServerID, cfg.now())
	if err != nil {
		// One answer for every reason, the same as the read routes: which of
		// them it was is not this caller's business. rootd writes the detail
		// where the operator is.
		http.Error(w, "this box will not act on that", http.StatusForbidden)
		return
	}

	// Already done. Answered from the record rather than queued again, so a
	// retry after a dropped response is idempotent instead of a second stop.
	if res, ok := ReadResult(cfg.ResultsDir, c.ID); ok {
		writeJSON(w, resultResponse{V: ResultVersion, Result: res})
		return
	}

	full, err := inboxFull(cfg.InboxDir)
	if err != nil {
		http.Error(w, "this box cannot take a command right now", http.StatusServiceUnavailable)
		return
	}
	if full {
		// 503 and not 500: it is a state that passes. rootd sweeps and applies
		// on its own timer, so the honest answer is "not now".
		http.Error(w, "this box has too many commands waiting", http.StatusServiceUnavailable)
		return
	}

	if err := writeCommand(cfg.InboxDir, c.ID, raw); err != nil {
		http.Error(w, "this box could not take that command", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	writeJSON(w, acceptedResponse{V: CommandVersion, ID: c.ID, Status: "accepted"})
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
	if _, err := os.Stat(final); err == nil {
		// Already waiting. Not an error: it is the same command.
		return nil
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
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
	// 0600: root reads this, and root is not subject to the mode. Nothing else
	// on the box has any business reading what somebody asked this machine to
	// do.
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
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
