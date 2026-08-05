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
		// --app is what every one of them acts on, and a missing one has to be
		// refused rather than defaulted to something.
		if err := run([]string{"--host", "root@box"}); err == nil {
			t.Errorf("komizo %s ran with no --app", name)
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
		if err := RunStop([]string{"--host", "root@box", "--app", bad}); err == nil {
			t.Errorf("komizo stop accepted --app %q", bad)
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
