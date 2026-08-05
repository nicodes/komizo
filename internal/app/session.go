package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Who is running this, held on this machine.
//
// komizo-be design/app-only.md §7: an account REGISTERS a box, it does not
// operate one. registry.md §10 required one for every command; that argument
// held for filing a server under somebody -- so that it appears in the app with
// nothing copied between two surfaces -- and for nothing else.
//
// READ FROM DISK, never checked over the network. That is the constraint the
// same section makes, and it is not a performance argument: the CLI is what
// repairs a broken box. Requiring a reachable service to fix a server is
// requiring it at exactly the moment it may not be there, so a komizo outage
// costs the parts that genuinely need the service -- creating a server,
// enrolling one -- and nothing else.

// Session is what login left behind.
type Session struct {
	// API is the service this credential belongs to, without a trailing slash.
	// Stored beside the token because they are issued together: a token from
	// one service against another is not a login, it is a confusing 401.
	API string `json:"api"`
	// Token authenticates this person to that service. Long-lived, revocable
	// from the app, and useless for reaching any box.
	Token string `json:"token"`
}

func (s Session) valid() bool { return s.API != "" && s.Token != "" }

// sessionPath is where it lives.
//
// Under XDG_CONFIG_HOME when that is set, because a machine that has said where
// configuration goes has said it for everything. ~/.config otherwise, which is
// the same place on the machines that have not.
func sessionPath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("could not find your home directory: %w", err)
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "komizo", "session.json"), nil
}

// readSession loads it, or returns the zero value.
//
// A missing file is not an error: it is somebody who has not signed in, which
// is the normal state of a fresh machine and has its own message at the point
// it matters.
func readSession() (Session, error) {
	path, err := sessionPath()
	if err != nil {
		return Session{}, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Session{}, nil
		}
		return Session{}, err
	}
	var s Session
	if err := json.Unmarshal(b, &s); err != nil {
		return Session{}, fmt.Errorf("%s is not readable as a session: %w", path, err)
	}
	return s, nil
}

// writeSession stores it, readable by nobody else.
//
// 0600 and a 0700 directory. This is a long-lived credential for somebody's
// account, and the machine it lands on is one they share with whatever else
// they run.
func writeSession(s Session) error {
	path, err := sessionPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	// Written to a temp file and moved, so a crash halfway through leaves the
	// previous session rather than a truncated one -- which would read as a
	// corrupt file and send somebody to log in again for no reason.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// clearSession forgets it. A missing file is already the desired state.
func clearSession() error {
	path, err := sessionPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// errNotSignedIn is what every command that needs an account says.
//
// One message, in one place, because the first thing somebody does with a new
// tool is run the wrong command -- and a different wording per command reads as
// a different problem each time.
var errNotSignedIn = fmt.Errorf("you are not signed in.\n\n    komizo login\n\n" +
	"    That shows a code to approve from a device you are already signed in on --\n" +
	"    your phone will do, so this works on a machine with no browser.")

// requireSession is the gate.
// requireSession is a var so the dispatch's gate can be tested on a machine
// whose answer would otherwise decide the result. A test that reads whether the
// person running it happens to be signed in is a test about the environment.
var requireSession = func() (Session, error) {
	s, err := readSession()
	if err != nil {
		return Session{}, err
	}
	if !s.valid() {
		return Session{}, errNotSignedIn
	}
	return s, nil
}
