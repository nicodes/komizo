package app

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

// The two surfaces do the same things.
//
// The interface is what most people use, which is exactly why it must not be
// the only way to reach a capability: a TUI-only operation cannot be scripted,
// cannot run in CI, and cannot be the answer when something has gone wrong with
// the interface itself.
//
// `u` on the komizo row was the first one to go missing, and it did visible
// damage -- the row for a box that had failed to poll said "not installed · u
// to install", naming a remedy that existed nowhere else. Whoever read that out
// of a log had nothing to run.

func TestUpdateIsReachableFromTheCommandLine(t *testing.T) {
	// Parsed, not run: this asserts the command exists and takes the flags the
	// interface's own update needs, without touching a server.
	err := RunUpdate([]string{"--help"})
	if err != nil && err != ErrSilent {
		t.Fatalf("komizo update --help = %v", err)
	}
}

func TestUpdateRefusesContradictoryProxyFlags(t *testing.T) {
	err := RunUpdate([]string{"--host", "root@box", "--proxy", "--no-proxy"})
	if err == nil {
		t.Fatal("--proxy and --no-proxy were both accepted")
	}
	if !strings.Contains(err.Error(), "opposite") {
		t.Errorf("error = %q, want it to say the two flags disagree", err)
	}
}

// The help has to name it, or the command exists and nobody finds it.
func TestUpdateUsageNamesTheInterfaceEquivalent(t *testing.T) {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	var buf bytes.Buffer
	fs.SetOutput(&buf)
	fs.Bool("proxy", false, "")
	usageUpdate(fs)

	got := buf.String()
	for _, want := range []string{"komizo update", "agent", `"u"`} {
		if !strings.Contains(got, want) {
			t.Errorf("update usage does not mention %q:\n%s", want, got)
		}
	}
}

// Starting, stopping and reading an app are reachable from the command line.
//
// They were not. Until komizo-be design/app-only.md's step 2 they existed ONLY
// in the interface -- tui_views.go's startStop and tui_server.go's stackLogCmd
// -- which meant deleting the interface would have deleted three capabilities
// with nowhere else to be. That is komizo#26's mistake exactly: a capability
// felt CLI-shaped, and nobody checked.
//
// Parsed rather than run: this asserts the command exists and takes the flags
// the interface's own version needs, without touching a server.
func TestTheAppLifecycleIsReachableFromTheCommandLine(t *testing.T) {
	for name, run := range map[string]func([]string) error{
		"start":   RunStart,
		"stop":    RunStop,
		"restart": RunRestart,
		"logs":    RunLogs,
	} {
		if err := run([]string{"--help"}); err != nil && err != ErrSilent {
			t.Errorf("komizo %s --help = %v", name, err)
		}
		// The MESSAGE, not merely that something failed: with the check deleted
		// these reach ensureReachable and fail on "cannot reach box", which made
		// the first version of this test pass against a missing guard.
		err := run([]string{"--host", "root@box"})
		if err == nil || !strings.Contains(err.Error(), "--app") {
			t.Errorf("komizo %s with no subject = %v, want it to name --app", name, err)
		}
	}
}

// And they refuse a name that would become part of a command.
//
// The value is validated here and quoted again on the way to the box, because
// the two checks answer different questions -- whether komizo will act on a
// name, and what a shell does with it.
func TestTheLifecycleCommandsRefuseANameThatIsNotOne(t *testing.T) {
	for _, bad := range []string{"web; rm -rf /", "../etc", "a b", "$(id)"} {
		err := RunStop([]string{"--host", "root@box", "--app", bad})
		if err == nil || !strings.Contains(err.Error(), "--app must be") {
			t.Errorf("komizo stop --app %q = %v, want it refused as a name", bad, err)
		}
	}

	// A service name that is a FLAG is the one that gets through a charset
	// check: Go's flag package takes the next argument as a value whatever it
	// looks like, so `--service -f` would reach compose as --follow.
	for _, bad := range []string{"-f", "--follow", "--dry-run", "a b", "a;b"} {
		err := RunLogs([]string{"--host", "root@box", "--app", "web", "--service", bad})
		if err == nil || !strings.Contains(err.Error(), "--service") {
			t.Errorf("komizo logs --service %q = %v, want it refused", bad, err)
		}
	}

	// And the tail is bounded here as well as on the box, so an impossible
	// request does not cost a round trip.
	for _, bad := range []string{"0", "-1", "999999"} {
		err := RunLogs([]string{"--host", "root@box", "--app", "web", "--tail", bad})
		if err == nil || !strings.Contains(err.Error(), "--tail") {
			t.Errorf("komizo logs --tail %s = %v", bad, err)
		}
	}
}

// Every one of them is reachable as `komizo <verb>`.
//
// parity_test.go calls the Run* functions directly, so a capability that exists
// and is not wired into the dispatch would pass every other test in this file
// while being unreachable from the command line -- which is the exact failure
// this file exists to prevent.
func TestTheLifecycleVerbsAreWiredIntoTheDispatch(t *testing.T) {
	for _, verb := range []string{"start", "stop", "restart", "logs"} {
		err := Main([]string{verb, "--host", "root@box"})
		if err == nil || !strings.Contains(err.Error(), "--app") {
			t.Errorf("komizo %s = %v, want the command to have run", verb, err)
		}
	}
}

// The remote command line is built by quoting every value, not by trusting that
// validation made quoting unnecessary.
func TestTheRemoteCommandQuotesItsArguments(t *testing.T) {
	got := boxCmd("logs", "--app", "a'b", "--tail", "40")
	if !strings.Contains(got, `'a'\''b'`) {
		t.Errorf("boxCmd = %q, want the app name quoted", got)
	}
	if !strings.HasPrefix(got, "/usr/local/bin/komizo-box app 'logs'") {
		t.Errorf("boxCmd = %q, want it to run the agent's own subcommand", got)
	}
}

// Exactly one subject, and "both" is its own error.
//
// Asserted on the "both" case, because with the check deleted a MISSING subject
// still fails at validateApp with a message naming --app -- so a test written
// that way passes against a guard that is not there.
func TestALifecycleCommandTakesOneSubject(t *testing.T) {
	err := RunStop([]string{"--host", "root@box", "--app", "web", "--proxy"})
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Errorf("--app with --proxy = %v, want it refused as ambiguous", err)
	}
	// And the proxy on its own is a valid subject, so the check is not simply
	// refusing --proxy.
	if err := RunStop([]string{"--host", "root@box", "--proxy", "--service", "-f"}); err == nil ||
		!strings.Contains(err.Error(), "--service") {
		t.Errorf("--proxy alone = %v, want it to reach the service check", err)
	}
}

// Every input is a flag, and a trailing word is refused rather than ignored.
func TestALifecycleCommandRefusesATrailingArgument(t *testing.T) {
	err := RunLogs([]string{"--host", "root@box", "--app", "web", "oops"})
	if err == nil || !strings.Contains(err.Error(), "every input is a flag") {
		t.Errorf("a trailing word = %v, want it refused", err)
	}
}

// LOG OUTPUT IS SCRUBBED ON THE WAY TO THE TERMINAL.
//
// `komizo logs` is the first command-line path whose output is written by
// somebody other than komizo: anyone who can make a request to a hosted app can
// put text in a log line. Rendered raw, an escape sequence can move the cursor,
// clear the screen, retitle the window, or write the local clipboard through
// OSC 52 -- validate.go says exactly this, and the interface has always
// scrubbed what it fetched.
func TestRemoteLogOutputIsScrubbedBeforeItIsPrinted(t *testing.T) {
	var out strings.Builder
	w := &scrubWriter{to: &out}

	// An OSC 52 clipboard write and a screen clear, split across two writes so
	// the line assembly is exercised too.
	if _, err := w.Write([]byte("app: hello \x1b]52;c;ZXZpbA==\x07 world\nnext \x1b[2J")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(" line\n")); err != nil {
		t.Fatal(err)
	}
	w.flush()

	got := out.String()
	if strings.ContainsRune(got, 0x1b) {
		t.Errorf("an escape survived: %q", got)
	}
	if strings.ContainsRune(got, 0x07) {
		t.Errorf("a BEL survived: %q", got)
	}
	// The text itself is kept -- this scrubs, it does not censor.
	for _, want := range []string{"app: hello", "world", "next", "line"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q was lost: %q", want, got)
		}
	}
	// And newlines survive, because logs are lines.
	if strings.Count(got, "\n") != 2 {
		t.Errorf("newlines = %d, want 2: %q", strings.Count(got, "\n"), got)
	}
}

// And logs are the verb that gets it.
//
// The scrubbing is obviously tested; the WIRING is what regresses quietly, so
// which verbs go through it is asserted rather than left to a branch.
func TestOnlyLogOutputIsScrubbed(t *testing.T) {
	if !scrubs("logs") {
		t.Error("log output is printed raw, so a hosted app can write this terminal")
	}
	for _, verb := range []string{"start", "stop", "restart"} {
		if scrubs(verb) {
			t.Errorf("%s output is scrubbed; it is compose's own prose", verb)
		}
	}
}

// A last line with no newline is ordinary in a log, and is printed rather than
// swallowed by the buffer.
func TestAPartialLastLogLineIsNotLost(t *testing.T) {
	var out strings.Builder
	w := &scrubWriter{to: &out}
	if _, err := w.Write([]byte("no trailing newline")); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Error("a partial line was written before it was complete")
	}
	w.flush()
	if !strings.Contains(out.String(), "no trailing newline") {
		t.Errorf("the last line was dropped: %q", out.String())
	}
}
