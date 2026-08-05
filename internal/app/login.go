package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Signing in, from a device that is not this one.
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
	api := fs.String("api", DefaultAPI, "the komizo service")
	token := fs.Bool("with-token", false, "read a credential from stdin instead, for a script")
	if err := fs.Parse(args); err != nil {
		return ErrSilent
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q -- every input is a flag", fs.Arg(0))
	}
	base, err := validateAPI(*api)
	if err != nil {
		return err
	}

	// A credential a script holds, minted in the app. Read from STDIN and never
	// a flag: a long-lived credential on a command line lands in shell history
	// and in the process table of this machine.
	if *token {
		return loginWithToken(base)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	start, err := startSignIn(ctx, base)
	if err != nil {
		return err
	}

	step("Approve this terminal")
	fmt.Printf("\n    Open  %s\n    Enter %s\n\n", start.VerificationURL, start.UserCode)
	note("your phone will do -- it does not have to be this machine.")
	fmt.Print("    Waiting...")

	s, err := awaitApproval(ctx, base, start)
	fmt.Println()
	if err != nil {
		return err
	}
	if err := writeSession(s); err != nil {
		return fmt.Errorf("signed in, but could not store the session: %w", err)
	}
	path, _ := sessionPath()
	note("signed in. The session is in %s and nothing else was written.", path)
	return nil
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
	// Said out loud, because forgetting a credential here does not revoke it.
	// The same distinction komizo enrol --remove makes about a box.
	note("signed out on this machine.")
	note("the credential still exists; revoke it in the app if this machine is not yours.")
	return nil
}

func usageLogin(fs *flag.FlagSet) {
	fmt.Fprint(fs.Output(), `komizo login -- sign this machine in

Shows a code. Approve it from a device you are already signed in on -- your
phone will do -- and this machine is signed in. Nothing is typed here.

  komizo login

For a machine that runs unattended, mint a credential in the app under
"Connect a terminal" and pass it in:

  komizo login --with-token < credential.txt

Flags:
`)
	fs.PrintDefaults()
}

func usageLogout(fs *flag.FlagSet) {
	fmt.Fprint(fs.Output(), `komizo logout -- forget the session on this machine

Removes the stored credential. It does NOT revoke it: do that in the app if
this machine is not yours any more.

  komizo logout
`)
}
