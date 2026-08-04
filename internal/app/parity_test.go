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
