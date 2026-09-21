package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"
)

// Signing in, from a device that is not this one.
//
// DECOMMISSIONED. This command's whole subject was the komizo service, and
// the service is gone (board decision): the CLI is the whole product, and a
// server is managed from it directly. The command is gated rather than
// ripped out -- it refuses, before the network is touched, with a sentence
// rather than a hang against a dead domain. The machinery below stays until
// the command itself is removed.
//
// This shows a code. Somebody approves it where they are already signed in --
// their phone will do -- and the credential arrives here on the next poll.
// Nothing is typed into this terminal.
//
// That shape is not for elegance. Clerk owns identity, its session tokens live
// sixty seconds, and its client rotates them on a fifty second timer; a command
// that runs for a fifth of a second cannot, and the alternative is komizo
// holding and refreshing somebody else's Clerk session on their laptop. So the
// person authenticates over there, and what lands here is a credential of ours.
//
// It also means a machine with no browser can be signed in, which is most of
// the machines komizo is run from.

func RunLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.Usage = func() { usageLogin(fs) }
	// The flags stay accepted so an old script fails on the refusal below,
	// not on "flag provided but not defined" -- which would read as a typo
	// rather than as the service being gone.
	_ = fs.String("api", "", "unused -- the komizo service is decommissioned")
	_ = fs.Bool("with-token", false, "unused -- the komizo service is decommissioned")
	if err := fs.Parse(args); err != nil {
		return ErrSilent
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q -- every input is a flag", fs.Arg(0))
	}
	// The gate IS the body: every path this command had reached the service,
	// and the service is decommissioned. Nothing below this function is
	// reached; it is kept, unread, for as long as the command is.
	return errServiceDecommissioned
}

// awaitApproval polls until somebody says yes, the code expires, or you give up.
func awaitApproval(ctx context.Context, api string, start deviceStart) (Session, error) {
	every := time.Duration(start.Interval) * time.Second
	if every <= 0 {
		every = 5 * time.Second
	}
	deadline := time.Now().Add(time.Duration(start.ExpiresIn) * time.Second)

	for {
		select {
		case <-ctx.Done():
			return Session{}, errors.New("cancelled")
		case <-time.After(every):
		}
		if time.Now().After(deadline) {
			return Session{}, errors.New("that code expired before it was approved -- run komizo login again")
		}

		res, err := pollSignIn(ctx, api, start.DeviceCode)
		if err != nil {
			// A poll that failed is not a sign-in that failed: this runs for up
			// to fifteen minutes and a dropped connection in the middle of it
			// should cost one interval, not the whole attempt.
			fmt.Print(".")
			continue
		}
		switch res.Status {
		case "approved":
			return Session{API: api, Token: res.Token}, nil
		case "expired":
			return Session{}, errors.New("that code expired before it was approved -- run komizo login again")
		default:
			fmt.Print(".")
		}
	}
}

// loginWithToken is the scripted path: a credential minted in the app, read
// from stdin.
func loginWithToken(api string) error {
	fmt.Fprint(os.Stderr, "Paste the credential (it will not be echoed back): ")
	var tok string
	if _, err := fmt.Fscanln(os.Stdin, &tok); err != nil {
		return fmt.Errorf("could not read a credential from stdin")
	}
	if tok == "" {
		return errors.New("no credential was given")
	}
	if err := writeSession(Session{API: api, Token: tok}); err != nil {
		return err
	}
	note("signed in.")
	return nil
}

func RunLogout(args []string) error {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	fs.Usage = func() { usageLogout(fs) }
	if err := fs.Parse(args); err != nil {
		return ErrSilent
	}
	s, err := readSession()
	if err != nil {
		return err
	}
	if !s.valid() {
		note("you were not signed in.")
		return nil
	}
	if err := clearSession(); err != nil {
		return err
	}
	note("signed out on this machine.")
	note("the service is decommissioned, so the credential this forgets opens nothing.")
	return nil
}

func usageLogin(fs *flag.FlagSet) {
	fmt.Fprint(fs.Output(), `komizo login -- decommissioned with the service

The komizo service this signed a machine in to is gone (board decision), so
this command is no longer available: it refuses, without touching the
network. The CLI is the whole product -- you manage your servers from it
directly, over SSH, with nothing to sign in to. See README.

"komizo logout" still works, and only ever touched this machine: it forgets
the stored session file.

Flags:
`)
	fs.PrintDefaults()
}

func usageLogout(fs *flag.FlagSet) {
	fmt.Fprint(fs.Output(), `komizo logout -- forget the session on this machine

Removes the stored credential. With the service decommissioned there is
nothing left to revoke it with -- it opens nothing either way.

  komizo logout
`)
}
