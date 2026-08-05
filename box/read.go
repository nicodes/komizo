package box

import (
	"errors"
	"io"
	"net/http"
)

// A read a DEVICE asked for, rather than one a token authorised.
//
// komizo-be design/app-only.md §5 made this argument for logs: a read token
// names a server and an expiry and NO USER, so the ownership check is the
// service's to make -- and whoever holds the registry's signing key could mint
// one for any box in the table. Putting the most sensitive bytes on the machine
// behind that single environment variable was refused.
//
// komizo-be#58 extended the same reasoning to the rest. The report and the
// history were behind the token alone, which meant a breach of the service read
// every enrolled box -- and "komizo cannot read your servers" is the sentence
// the product is built on, so having it be true of two routes out of four was
// not a position worth defending.
//
// THE TOKEN STILL GATES THE DOOR. This is a second check and not a replacement:
// the token says the caller reached a box it was told about, the signature says
// which device is asking. Neither alone is authority to read.
//
// THE ID IS NOT CONSUMED, and that is deliberate here for the reason logs.go
// gives: §4's replay record exists so a command is not APPLIED twice, and
// reading a report twice is reading a report twice. Spending an envelope would
// also let one read deny a later one by using up its id, and would put a write
// on the path of every screen refresh. What bounds a captured read envelope is
// its expiry -- and a caller holding one also needs the token that came with it.

// verifiedRead checks the envelope on a signed read, and answers the caller
// itself when it refuses.
//
// Returns ok=false when it has already written a response, so a handler is
// three lines rather than thirty repeated four times -- which is how the log
// route came to read c.Args["app"] directly while every other path used AppOf.
func verifiedRead(cfg APIConfig, w http.ResponseWriter, r *http.Request, op string) (Command, bool) {
	if len(cfg.OperatorKeys) == 0 {
		// Nobody may read this, because nobody has been given the means to ask.
		// Said plainly rather than answered with an empty document -- this is
		// the state of every box until an operator plants a key, and "your
		// server reports nothing" would send somebody to look at the machine.
		http.Error(w, "this box takes orders from nobody", http.StatusConflict)
		return Command{}, false
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxCommandBytes+1))
	if err != nil {
		http.Error(w, "could not read that request", http.StatusBadRequest)
		return Command{}, false
	}
	if len(raw) > MaxCommandBytes {
		http.Error(w, "that request is too large", http.StatusRequestEntityTooLarge)
		return Command{}, false
	}

	c, _, err := VerifyCommand(cfg.OperatorKeys, raw, cfg.ServerID, cfg.Now())
	switch {
	case err != nil && !errors.Is(err, ErrCommandRefused):
		// A version this box does not speak. The signature already verified, so
		// the caller is a device this box trusts and §4 says it is entitled to a
		// sentence rather than a silence.
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return Command{}, false
	case err != nil || c.Op != op:
		// One answer for every reason, the same as everywhere else here: which
		// of them it was is not this caller's business.
		http.Error(w, "this box will not answer that", http.StatusForbidden)
		return Command{}, false
	}
	return c, true
}
