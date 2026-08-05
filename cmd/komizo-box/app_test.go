package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nicodes/komizo/box"
)

// The verbs are a closed set, and an unknown one is refused rather than passed
// to docker.
//
// This is the process a signed command ends in -- app-only.md §4's "op is a
// NAME, and args are structured". A verb that reached `docker compose`
// unchecked would make the signature the thing that authorised whatever was in
// it.
//
// The MESSAGE is asserted, not merely that something failed. Every call here
// also fails later at the app lookup, so "returned an error" would pass with
// the check deleted.
func TestOnlyTheKnownVerbsAreAccepted(t *testing.T) {
	for _, bad := range []string{"rm", "exec", "up", "down", "--version", ""} {
		err := runApp([]string{bad, "--app", "web"})
		if err == nil || !strings.Contains(err.Error(), "not something an app can be told to do") {
			t.Errorf("komizo-box app %q = %v, want it refused as a verb", bad, err)
		}
	}
	if err := runApp(nil); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Errorf("komizo-box app with no verb = %v", err)
	}
}

// Exactly one subject, and never none.
func TestOneSubjectIsRequired(t *testing.T) {
	for _, args := range [][]string{
		{"start"},
		{"start", "--app", "web", "--proxy"},
	} {
		err := runApp(args)
		if err == nil || !strings.Contains(err.Error(), "exactly one") {
			t.Errorf("komizo-box app %v = %v", args, err)
		}
	}
}

// A tail is bounded at both ends.
func TestTheLogTailIsBounded(t *testing.T) {
	for _, n := range []string{"0", "-1", "100000"} {
		err := runApp([]string{"logs", "--app", "web", "--tail", n})
		if err == nil || !strings.Contains(err.Error(), "--tail must be between") {
			t.Errorf("--tail %s = %v, want it refused as a range", n, err)
		}
	}
	// And one inside the range gets past this check, so the test above is not
	// passing because every tail is refused.
	if err := runApp([]string{"logs", "--app", "web", "--tail", "40"}); err != nil &&
		strings.Contains(err.Error(), "--tail") {
		t.Errorf("a tail of 40 was refused: %v", err)
	}
}

// A SERVICE NAME MUST NOT BE A FLAG.
//
// Go's flag package takes the next argument as a value without caring that it
// starts with a dash, so `--service -f` reached `docker compose logs` as
// --follow: unbounded output, blocking until the timeout, and logTailMax
// defeated entirely. `--dry-run` is a persistent flag on every compose
// subcommand, so the same hole makes a stop report success and do nothing.
func TestAServiceNameCannotBeAFlag(t *testing.T) {
	for _, bad := range []string{"-f", "--follow", "--dry-run", "-p", "a b", "a;b", "a/b"} {
		if err := validService(bad); err == nil {
			t.Errorf("%q was accepted as a service name", bad)
		}
	}
	for _, good := range []string{"", "web", "api-1", "db_2", "web.1"} {
		if err := validService(good); err != nil {
			t.Errorf("%q was refused as a service name: %v", good, err)
		}
	}
	// And it is refused through the command, not only by the helper.
	err := runApp([]string{"logs", "--app", "web", "--service", "-f"})
	if err == nil || !strings.Contains(err.Error(), "flag") {
		t.Errorf("komizo-box app logs --service -f = %v", err)
	}
}

// What actually runs, asserted rather than inferred.
//
// Nothing tested this, so `stop` becoming `down` -- which removes containers
// and the network -- and `start` becoming `compose start` -- which brings back
// the OLD image, the exact hazard composeArgs argues against -- both shipped
// green under the previous tests.
func TestWhatEachVerbRuns(t *testing.T) {
	for verb, want := range map[string]string{
		"start":   "up -d",
		"stop":    "stop",
		"restart": "restart",
		"logs":    "logs --tail 40 --no-color",
	} {
		if got := strings.Join(composeArgs(verb, 40, ""), " "); got != want {
			t.Errorf("composeArgs(%q) = %q, want %q", verb, got, want)
		}
	}

	// A service follows a `--`, so it can never be read as a flag of the
	// subcommand before it.
	if got := strings.Join(composeArgs("logs", 10, "api"), " "); got != "logs --tail 10 --no-color -- api" {
		t.Errorf("composeArgs with a service = %q", got)
	}
}

// A trailing word is refused rather than ignored.
//
// Unreachable from boxCmd today, but rootd builds its own arguments from a
// signed envelope, so every check here has to hold for a caller that is not the
// laptop.
func TestATrailingArgumentIsRefused(t *testing.T) {
	err := runApp([]string{"start", "--app", "web", "oops"})
	if err == nil || !strings.Contains(err.Error(), "every input is a flag") {
		t.Errorf("a trailing word = %v, want it refused", err)
	}
}

// A directory that is not absolute never reaches docker, where it becomes a
// flag or a path relative to whatever this process happens to be in.
//
// Reachable only through a hand-edited record, which is why it is checked
// rather than assumed: validateAppDir guarantees the leading slash on the way
// in, and that made the safety of this line a fact about another file.
func TestARelativeAppDirectoryIsRefused(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, box.AppsDir), 0o750); err != nil {
		t.Fatal(err)
	}
	for name, dir := range map[string]string{
		"relative":  "srv/web",
		"a flag":    "--tlsverify",
		"an option": "-H tcp://evil:2375",
	} {
		if err := os.WriteFile(filepath.Join(root, box.AppsDir, "x.env"),
			[]byte("APP_DIR="+dir+"\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		got, err := box.AppDir(root, "x")
		if err != nil {
			continue // refused earlier, which is also fine
		}
		if strings.HasPrefix(got, "/") {
			t.Fatalf("%s: fixture did not take", name)
		}
		// The command has to refuse it; box.AppDir returning it is not enough.
		if err := validDir(got); err == nil {
			t.Errorf("%s (%q) was accepted as a directory", name, got)
		}
	}
	if err := validDir("/srv/web"); err != nil {
		t.Errorf("an absolute directory was refused: %v", err)
	}
}

// The stack is named by BOTH its file and its project directory.
//
// Compose derives a project name from the directory, and an app whose directory
// does not match its name would otherwise be acted on under a project nothing
// else uses -- which looks exactly like a command that worked and did nothing.
func TestTheStackIsNamedTheSameWayTheDeployNamesIt(t *testing.T) {
	got := strings.Join(composeBase("/srv/web", ""), " ")
	if got != "compose -f /srv/web/compose.yml --project-directory /srv/web" {
		t.Errorf("composeBase = %q", got)
	}
	// The proxy is the exception, and it is explicit: alpine-proxy.sh created it
	// under a project name of its own.
	got = strings.Join(composeBase(box.ProxyDir, ProxyProject), " ")
	if !strings.Contains(got, "-p "+ProxyProject) {
		t.Errorf("composeBase for the proxy = %q, want its project named", got)
	}
}

// EXEC WITH A SLICE, NEVER A SHELL.
//
// This is the process the signed-command path ends in. A shell here would make
// every argument a place where a name becomes a command, and the previous tests
// let `sh -c "docker " + strings.Join(args)` pass.
func TestComposeRunsDockerDirectlyAndNotThroughAShell(t *testing.T) {
	var gotName string
	var gotArgs []string
	orig := execCompose
	execCompose = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		gotName, gotArgs = name, args
		// Something that exists and exits 0 wherever these tests run.
		return exec.CommandContext(ctx, "true")
	}
	defer func() { execCompose = orig }()

	if err := compose(context.Background(), "/srv/web", "", "stop"); err != nil {
		t.Fatal(err)
	}
	if gotName != "docker" {
		t.Errorf("ran %q, want docker itself", gotName)
	}
	for _, a := range gotArgs {
		if a == "-c" || strings.Contains(a, "&&") || strings.Contains(a, ";") {
			t.Errorf("an argument looks like shell: %q", a)
		}
	}
	if strings.Join(gotArgs, " ") != "compose -f /srv/web/compose.yml --project-directory /srv/web stop" {
		t.Errorf("args = %v", gotArgs)
	}
}
