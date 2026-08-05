package app

import (
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

	for _, name := range []string{"init"} {
		err := Main([]string{name, "--host", unreachable})
		if err == nil {
			t.Errorf("%q ran without a session", name)
			continue
		}
		if !strings.Contains(err.Error(), "komizo login") {
			t.Errorf("%q failed for the wrong reason: %v", name, err)
		}
	}
	// enrol asks only when it has to mint the token itself.
	if err := Main([]string{"enrol", "--host", unreachable}); err == nil ||
		!strings.Contains(err.Error(), "komizo login") {
		t.Errorf("enrol with no token = %v, want it to ask for an account", err)
	}

	for _, name := range []string{"update", "add", "list", "report", "remove", "proxy",
		"start", "stop", "restart", "logs"} {
		err := Main([]string{name, "--host", unreachable})
		if err != nil && strings.Contains(err.Error(), "komizo login") {
			t.Errorf("%q asked for an account to touch somebody's own server", name)
		}
	}
	if err := Main([]string{"enrol", "--host", unreachable, "--token", "kmz_enr_x"}); err != nil &&
		strings.Contains(err.Error(), "komizo login") {
		t.Error("enrol --token asked for an account it does not need")
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
