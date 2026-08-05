package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/box"
)

// stubCompose replaces the exec seam and records every argv it was given.
func stubCompose(t *testing.T, out string, code int) *[][]string {
	t.Helper()
	var runs [][]string
	orig := execCompose
	execCompose = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		runs = append(runs, append([]string{name}, args...))
		if code != 0 {
			return exec.CommandContext(ctx, "false")
		}
		return exec.CommandContext(ctx, "printf", "%s", out)
	}
	t.Cleanup(func() { execCompose = orig })
	return &runs
}

func appsFixture(t *testing.T, names ...string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, box.AppsDir), 0o750); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(root, box.AppsDir, n+".env"),
			[]byte("APP_NAME="+n+"\nAPP_DIR=/srv/"+n+"\n"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// NOTHING TO SAY IS NOT THE SAME AS SAYING NOTHING.
//
// `docker compose logs` on a project with no containers exits ZERO with empty
// output -- which is what an app mid-deploy and an app that just crashed and was
// recreated both look like. The guard fired only on failure, so the two moments
// somebody is most likely to be watching were the two that wiped the last thing
// the app said.
func TestAnEmptySuccessfulCollectKeepsThePreviousTail(t *testing.T) {
	root := appsFixture(t, "web")
	logs := t.TempDir()
	if err := box.WriteLog(logs, "web", []byte("something it said earlier\n")); err != nil {
		t.Fatal(err)
	}

	// Exit 0, no output: the mid-deploy case.
	stubCompose(t, "", 0)
	collectLogs(context.Background(), root, logs)

	got, err := box.ReadLog(logs, "web", 10)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "something it said earlier") {
		t.Errorf("the previous tail was blanked: %q", got)
	}

	// And whitespace alone counts as nothing.
	stubCompose(t, "\n  \n", 0)
	collectLogs(context.Background(), root, logs)
	if got, _ := box.ReadLog(logs, "web", 10); !strings.Contains(got, "earlier") {
		t.Errorf("whitespace overwrote the tail: %q", got)
	}

	// Real output does replace it, so this is not simply never writing.
	stubCompose(t, "the new line\n", 0)
	collectLogs(context.Background(), root, logs)
	if got, _ := box.ReadLog(logs, "web", 10); !strings.Contains(got, "the new line") {
		t.Errorf("real output was not collected: %q", got)
	}
}

// WHAT IS ACTUALLY RUN.
//
// A stray --follow here is unbounded output poured into a bounded file by a root
// loop, which is the stake validService states on the other path.
func TestWhatTheCollectorRuns(t *testing.T) {
	root := appsFixture(t, "web")
	runs := stubCompose(t, "x\n", 0)
	collectLogs(context.Background(), root, t.TempDir())

	if len(*runs) != 1 {
		t.Fatalf("%d invocations, want 1: %v", len(*runs), *runs)
	}
	got := strings.Join((*runs)[0], " ")
	want := "docker compose -f /srv/web/compose.yml --project-directory /srv/web logs --tail 500 --no-color"
	if got != want {
		t.Errorf("ran %q,\n want %q", got, want)
	}
	// Checked per ARGUMENT, not as substrings of the joined line: "--no-color"
	// contains "-c", and the first version of this failed on its own command.
	for _, a := range (*runs)[0] {
		switch a {
		case "--follow", "-f-", "-c", "sh", "bash", "&&":
			t.Errorf("the command carries %q", a)
		}
	}
	// And it is docker itself rather than a shell, which is what keeps every
	// argument an argument.
	if (*runs)[0][0] != "docker" {
		t.Errorf("ran %q, want docker", (*runs)[0][0])
	}
}

// THE SHARED PROXY IS NOT COLLECTED.
//
// Caddy's error logger writes full requests -- client IP, URI, query string --
// to stdout, so collecting it would put them in a file the internet-facing
// account reads and serves. Found by running Caddy, not by reading the config
// that sends the ACCESS log elsewhere.
func TestTheProxyIsNotCollected(t *testing.T) {
	// A _proxy RECORD, so the guard has something to refuse. Without one the
	// assertion cannot fail however the guard is written, which is what the
	// first version of this did.
	root := appsFixture(t, "web", "_proxy")
	logs := t.TempDir()
	runs := stubCompose(t, "x\n", 0)
	collectLogs(context.Background(), root, logs)

	for _, r := range *runs {
		line := strings.Join(r, " ")
		if strings.Contains(line, box.ProxyDir) || strings.Contains(line, "_proxy") {
			t.Errorf("the proxy was collected: %v", r)
		}
	}
	if _, err := os.Stat(filepath.Join(logs, "_proxy.log")); err == nil {
		t.Error("a proxy log was written")
	}
	// And an app IS collected, so this is not passing because nothing ran.
	if _, err := box.ReadLog(logs, "web", 1); err != nil {
		t.Errorf("nothing was collected at all: %v", err)
	}
}

// One broken app does not stop the pass.
func TestABrokenAppDoesNotStopTheOthers(t *testing.T) {
	root := appsFixture(t, "a", "b", "c")
	logs := t.TempDir()

	orig := execCompose
	execCompose = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if strings.Contains(strings.Join(args, " "), "/srv/b/") {
			return exec.CommandContext(ctx, "false")
		}
		return exec.CommandContext(ctx, "printf", "%s", "line\n")
	}
	defer func() { execCompose = orig }()

	collectLogs(context.Background(), root, logs)
	for _, n := range []string{"a", "c"} {
		if _, err := box.ReadLog(logs, n, 1); err != nil {
			t.Errorf("%s was not collected after another app failed: %v", n, err)
		}
	}
}

// AN UNREADABLE APPS DIRECTORY MUST NOT PRUNE EVERY LOG.
//
// It looks exactly like a box with no apps, and pruning against that would
// delete every log on the machine.
func TestAnUnreadableAppsDirectoryDoesNotPruneEverything(t *testing.T) {
	logs := t.TempDir()
	if err := box.WriteLog(logs, "web", []byte("keep me\n")); err != nil {
		t.Fatal(err)
	}
	stubCompose(t, "x\n", 0)

	// A root with no apps directory at all: enumeration fails.
	collectLogs(context.Background(), t.TempDir(), logs)
	if _, err := box.ReadLog(logs, "web", 1); err != nil {
		t.Error("an unreadable apps directory pruned every log")
	}

	// But a readable one with no apps in it does prune, because that is a box
	// whose apps really are gone.
	collectLogs(context.Background(), appsFixture(t), logs)
	if _, err := box.ReadLog(logs, "web", 1); err == nil {
		t.Error("a genuinely empty box kept a log for an app it does not have")
	}
}

// WHAT ROOT BUFFERS IS BOUNDED IN BYTES, not just in lines.
//
// --tail bounds how many lines docker returns and says nothing about how long
// one is, and how long one is belongs to whatever is running in somebody's
// container. This runs at root on a fifteen-second timer.
func TestTheCaptureIsBoundedInBytes(t *testing.T) {
	root := appsFixture(t, "web")
	logs := t.TempDir()

	// One line, far larger than the bound.
	orig := execCompose
	execCompose = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c",
			"yes abcdefghijklmnopqrstuvwxyz | head -c "+strconv.Itoa(box.LogsMax*4))
	}
	defer func() { execCompose = orig }()

	done := make(chan struct{})
	go func() { collectLogs(context.Background(), root, logs); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("collecting an enormous log did not finish")
	}

	// Asserted on what the CAPTURE returned, not on the file: WriteLog trims to
	// LogsMax as well, so the file is bounded either way and a test looking at
	// it passes with the capture unbounded -- which is what the first version of
	// this did. The bound that matters is the one at root, before the bytes
	// exist in this process at all.
	out, err := composeCapped(context.Background(), "/srv/web", "", 4096, "logs")
	if err != nil && out == "" {
		t.Fatalf("captured nothing: %v", err)
	}
	if len(out) > 4096 {
		t.Errorf("captured %d bytes with a bound of 4096", len(out))
	}

	fi, err := os.Stat(filepath.Join(logs, "web.log"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > int64(box.LogsMax) {
		t.Errorf("%d bytes written, want at most %d", fi.Size(), box.LogsMax)
	}
}
