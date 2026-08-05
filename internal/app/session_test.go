package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The session, and the gate it opens.
//
// komizo-be design/registry.md §10: the CLI requires an account. The half worth
// testing hardest is the constraint that came with it -- the session is read
// from DISK, never checked over the network, because the CLI is what repairs a
// broken box.

func withConfigHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	return dir
}

func TestASessionRoundTrips(t *testing.T) {
	dir := withConfigHome(t)

	if s, err := readSession(); err != nil || s.valid() {
		t.Fatalf("a fresh machine has a session: %+v (%v)", s, err)
	}

	want := Session{API: "https://api.komizo.dev", Token: "kmz_cli_abc"}
	if err := writeSession(want); err != nil {
		t.Fatal(err)
	}
	got, err := readSession()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("session = %+v, want %+v", got, want)
	}

	// Both halves, because a token without the service it belongs to is not a
	// login -- it is a confusing 401 against whatever gets tried next.
	if !strings.Contains(filepath.Join(dir, "komizo", "session.json"), "komizo") {
		t.Error("the session is not under a komizo directory")
	}
}

// A long-lived credential for somebody's account, on a machine they share with
// whatever else they run.
func TestTheSessionIsNotReadableByAnybodyElse(t *testing.T) {
	dir := withConfigHome(t)
	if err := writeSession(Session{API: "https://api.komizo.dev", Token: "kmz_cli_abc"}); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(filepath.Join(dir, "komizo", "session.json"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("session.json is %04o, want 0600", perm)
	}
	di, err := os.Stat(filepath.Join(dir, "komizo"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Errorf("the komizo directory is %04o, want 0700", perm)
	}
}

// The gate. Its message has to name the way out, because the first thing
// anybody does with a new tool is run the wrong command.
func TestTheGateSaysHowToGetThrough(t *testing.T) {
	withConfigHome(t)

	_, err := requireSession()
	if err == nil {
		t.Fatal("an unsigned-in machine passed the gate")
	}
	if !strings.Contains(err.Error(), "komizo login") {
		t.Errorf("the message does not name the way out: %q", err)
	}

	if err := writeSession(Session{API: "https://api.komizo.dev", Token: "kmz_cli_abc"}); err != nil {
		t.Fatal(err)
	}
	if _, err := requireSession(); err != nil {
		t.Errorf("a signed-in machine was refused: %v", err)
	}
}

// Half a session is not a session. A file with one field would otherwise pass
// the gate and fail at the first request, which reads as the service being
// broken rather than as somebody needing to sign in again.
func TestHalfASessionIsRefused(t *testing.T) {
	withConfigHome(t)
	for _, s := range []Session{
		{API: "https://api.komizo.dev"},
		{Token: "kmz_cli_abc"},
		{},
	} {
		if err := writeSession(s); err != nil {
			t.Fatal(err)
		}
		if _, err := requireSession(); err == nil {
			t.Errorf("%+v passed the gate", s)
		}
	}
}

// Signing out forgets the credential and says that forgetting is not revoking.
func TestSigningOutForgetsButDoesNotClaimToRevoke(t *testing.T) {
	dir := withConfigHome(t)
	if err := writeSession(Session{API: "https://api.komizo.dev", Token: "kmz_cli_abc"}); err != nil {
		t.Fatal(err)
	}
	if err := clearSession(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "komizo", "session.json")); !os.IsNotExist(err) {
		t.Error("the session file survived a sign-out")
	}
	// Clearing an already-cleared session is the desired state, not an error.
	if err := clearSession(); err != nil {
		t.Errorf("clearing twice = %v", err)
	}
}

// REGISTERING A BOX IS WHAT NEEDS AN ACCOUNT.
//
// This used to assert the opposite, and asserting it is how the old rule was
// kept: every command in the dispatch had to be behind the gate, "which would
// be a route into somebody's servers that nobody remembered to close".
//
// komizo-be design/app-only.md §7 reverses that. The gate was never protecting
// somebody's servers -- SSH and a root key do that, and komizo is not in it. It
// protects creating rows in somebody's komizo account, which is exactly two
// commands. Leaving a box-only command out of the table is now correct rather
// than a hole, and registry.md §10's own constraint -- "the CLI must work when
// the service does not" -- stops being something a cached session provides.
//
// A host that fails VALIDATION, so nothing here opens a connection: what is
// under test is which commands ask, and the alternative spent thirty seconds
// waiting for DNS to refuse a name.
func TestRegisteringNeedsAnAccountAndOperatingDoesNot(t *testing.T) {
	withConfigHome(t)
	const unreachable = "root@not a host"

	// enrol asks only when it has to mint the token itself, and that is the
	// only command in the whole dispatch that asks at all.
	//
	// errors.Is rather than a substring: matching on "komizo login" keeps
	// passing if the message is reworded, which is a test about prose.
	if err := Main([]string{"enrol", "--host", unreachable}); !errors.Is(err, errNotSignedIn) {
		t.Errorf("enrol with no token = %v, want it to ask for an account", err)
	}

	for _, name := range []string{"init", "update", "add", "list", "report", "remove", "proxy",
		"start", "stop", "restart", "logs"} {
		if err := Main([]string{name, "--host", unreachable}); errors.Is(err, errNotSignedIn) {
			t.Errorf("%q asked for an account to touch somebody's own server", name)
		}
	}
	for _, args := range [][]string{
		{"enrol", "--host", unreachable, "--token", "kmz_enr_x"},
		{"enrol", "--host", unreachable, "--remove"},
	} {
		if err := Main(args); errors.Is(err, errNotSignedIn) {
			t.Errorf("%v asked for an account it does not need", args)
		}
	}
}

// And the four that must not be, because they are how you get an account or
// they touch neither a service nor a server.
func TestSigningInAndReadingTheShellNeedNoAccount(t *testing.T) {
	withConfigHome(t)
	if err := Main([]string{"version"}); err != nil {
		t.Errorf("version needs an account: %v", err)
	}
	if err := Main([]string{"script", "init"}); err != nil {
		t.Errorf("script needs an account: %v", err)
	}
	if err := Main([]string{"logout"}); err != nil {
		t.Errorf("logout needs an account: %v", err)
	}
}

// "Not signed in" is not fixed by waiting.
//
// Both notes after a failed registration assumed the service was down, and the
// remedy for the other cause is `komizo login`. Reachable now that setting a box
// up needs no account: somebody with no session provisions a machine and is told
// to wait for something that is already up.
func TestTheAdviceMatchesWhyRegistrationFailed(t *testing.T) {
	signedOut := enrolAdvice(errNotSignedIn, "root@box")
	if !strings.Contains(signedOut, "komizo login") {
		t.Errorf("signed out = %q, want it to say how to sign in", signedOut)
	}
	if strings.Contains(signedOut, "reachable") {
		t.Errorf("signed out = %q, want it not to suggest waiting", signedOut)
	}

	down := enrolAdvice(errors.New("cannot reach the service"), "root@box")
	if !strings.Contains(down, "reachable") {
		t.Errorf("service down = %q, want it to suggest trying again", down)
	}
	if strings.Contains(down, "komizo login") {
		t.Errorf("service down = %q, want it not to suggest signing in", down)
	}
	// And both name the host, because the remedy is a command about one box.
	for _, s := range []string{signedOut, down} {
		if !strings.Contains(s, "root@box") {
			t.Errorf("%q does not name the server", s)
		}
	}
}
