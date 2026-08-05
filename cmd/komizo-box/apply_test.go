package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/box"
)

// captureCompose replaces the exec seam and records what would have run.
//
// The applier's whole job is deciding whether to touch the machine, so what a
// test has to see is exactly that: did anything reach docker, and with what.
func captureCompose(t *testing.T) *[][]string {
	t.Helper()
	var runs [][]string
	orig := execCompose
	execCompose = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		runs = append(runs, append([]string{name}, args...))
		return exec.CommandContext(ctx, "true")
	}
	t.Cleanup(func() { execCompose = orig })
	return &runs
}

func drop(t *testing.T, dir string, priv ed25519.PrivateKey, c box.Command) string {
	t.Helper()
	env, err := box.SignCommand(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	name := "cmd-" + strings.ReplaceAll(t.Name(), "/", "_")
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// dropRaw puts arbitrary bytes in the inbox, as a hostile writer would.
func dropRaw(t *testing.T, dir string, b []byte) string {
	t.Helper()
	path := filepath.Join(dir, "raw-"+strings.ReplaceAll(t.Name(), "/", "_"))
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// AN UNVERIFIED COMMAND NEVER TOUCHES THE MACHINE.
//
// The one property everything else rests on. Each of these is a different way
// to be wrong and none of them may reach docker.
func TestNothingUnverifiedIsEverApplied(t *testing.T) {
	runs := captureCompose(t)
	pub, priv := device(t)
	_, stranger := device(t)
	inbox, results := t.TempDir(), t.TempDir()
	conf := box.AgentConf{ServerID: "srv_mine", OperatorKeys: []string{box.FormatDeviceKey(pub)}}
	ok := box.Command{ID: "would-be-applied", Srv: "srv_mine", Exp: time.Now().Add(time.Minute).Unix(),
		Op: box.OpAppStop, Args: map[string]string{"app": "web"}}

	for name, build := range map[string]func() string{
		"signed by a key this box does not hold": func() string {
			return drop(t, inbox, stranger, ok)
		},
		"meant for another box": func() string {
			c := ok
			c.Srv = "srv_theirs"
			return drop(t, inbox, priv, c)
		},
		"expired": func() string {
			c := ok
			c.Exp = time.Now().Add(-time.Minute).Unix()
			return drop(t, inbox, priv, c)
		},
		"not a command at all": func() string {
			return dropRaw(t, inbox, []byte("hello"))
		},
		"empty": func() string {
			return dropRaw(t, inbox, nil)
		},
	} {
		path := build()
		applyPending(context.Background(), conf, inbox, results)
		if len(*runs) != 0 {
			t.Fatalf("%s: reached docker: %v", name, *runs)
		}
		// And it is not left behind to be retried every half second forever.
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s: the command was left in the inbox", name)
		}
		// A refusal writes no result: there is nobody entitled to one.
		if _, found := box.ReadResult(results, ok.ID); found {
			t.Errorf("%s: a refusal wrote a result", name)
		}
	}
}

// A BOX THAT TRUSTS NO DEVICE APPLIES NOTHING.
//
// Which is every box that exists today, and is the state a box is in until an
// operator plants a key with root.
func TestABoxWithNoOperatorKeysAppliesNothing(t *testing.T) {
	runs := captureCompose(t)
	_, priv := device(t)
	inbox := t.TempDir()
	drop(t, inbox, priv, box.Command{Srv: "srv_mine", Exp: time.Now().Add(time.Minute).Unix(),
		Op: box.OpAppStop, Args: map[string]string{"app": "web"}})

	applyPending(context.Background(), box.AgentConf{ServerID: "srv_mine"}, inbox, t.TempDir())
	if len(*runs) != 0 {
		t.Fatalf("a box that trusts nothing acted: %v", *runs)
	}
}

// The op becomes arguments HERE, from a closed set.
//
// app-only.md §4: a signed command carrying a command line would be remote code
// execution with the signature as its authorisation. So the envelope names an
// op and the box decides what that means.
func TestAVerifiedCommandRunsTheSameThingTheCLIWouldRun(t *testing.T) {
	for op, want := range map[string]string{
		box.OpAppStop:    "stop",
		box.OpAppStart:   "up -d",
		box.OpAppRestart: "restart",
	} {
		verb, ok := opVerbs[op]
		if !ok {
			t.Fatalf("%s maps to no verb", op)
		}
		if got := strings.Join(composeArgs(verb, 0, ""), " "); got != want {
			t.Errorf("%s -> %q, want %q", op, got, want)
		}
	}
	// Every op VerifyCommand accepts has a verb here, and the reverse. Two
	// closed sets that can disagree are one that silently succeeds.
	for _, op := range []string{box.OpAppStart, box.OpAppStop, box.OpAppRestart} {
		if _, ok := opVerbs[op]; !ok {
			t.Errorf("%s is accepted by the envelope and has no verb", op)
		}
	}
	if len(opVerbs) != 3 {
		t.Errorf("opVerbs has %d entries; the envelope accepts 3", len(opVerbs))
	}
}

// AN APPLIED COMMAND IS NOT APPLIED TWICE.
//
// The result is the replay record, and it is on disk rather than in memory
// because a box restarts -- a window that reset on restart would let every
// still-valid signature through again for the rest of its life.
func TestACommandIsNotAppliedTwice(t *testing.T) {
	runs := captureCompose(t)
	pub, priv := device(t)
	inbox, results := t.TempDir(), t.TempDir()
	root := appFixture(t, "web", "/srv/web")

	conf := box.AgentConf{ServerID: "srv_mine", OperatorKeys: []string{box.FormatDeviceKey(pub)}}
	c := box.Command{ID: "replay-me", Srv: "srv_mine", Exp: time.Now().Add(time.Minute).Unix(),
		Op: box.OpAppStop, Args: map[string]string{"app": "web"}}

	withRoot(t, root, func() {
		drop(t, inbox, priv, c)
		applyPending(context.Background(), conf, inbox, results)
		if len(*runs) != 1 {
			t.Fatalf("the first arrival ran %d commands, want 1: %v", len(*runs), *runs)
		}
		if r, found := box.ReadResult(results, c.ID); !found || !r.OK {
			t.Fatalf("no successful result was recorded: %+v", r)
		}

		// The same signed bytes again, which is what a replay is.
		drop(t, inbox, priv, c)
		applyPending(context.Background(), conf, inbox, results)
		if len(*runs) != 1 {
			t.Errorf("a replay ran the command again: %v", *runs)
		}
	})
}

// A result says what happened, including when it did not.
func TestAResultRecordsBothOutcomes(t *testing.T) {
	captureCompose(t)
	pub, priv := device(t)
	inbox, results := t.TempDir(), t.TempDir()
	conf := box.AgentConf{ServerID: "srv_mine", OperatorKeys: []string{box.FormatDeviceKey(pub)}}

	// An app this box does not have: verified, attempted, and it fails.
	drop(t, inbox, priv, box.Command{ID: "no-such-app", Srv: "srv_mine",
		Exp: time.Now().Add(time.Minute).Unix(), Op: box.OpAppStop,
		Args: map[string]string{"app": "nosuchapp"}})
	applyPending(context.Background(), conf, inbox, results)

	r, found := box.ReadResult(results, "no-such-app")
	if !found {
		t.Fatal("a command that failed left no result, so the app would wait forever")
	}
	if r.OK {
		t.Error("a failure was recorded as a success")
	}
	if r.Detail == "" {
		t.Error("a failure recorded no detail")
	}
	if r.Op != box.OpAppStop {
		t.Errorf("op = %q", r.Op)
	}
	if r.V != box.ResultVersion {
		t.Errorf("v = %d, want %d", r.V, box.ResultVersion)
	}
}

// One pass does a bounded amount of work.
//
// The inbox is reachable, through the serving account, from a route on the
// internet -- without a bound a burst is a burst of public-key operations at
// root.
func TestOnePassIsBounded(t *testing.T) {
	runs := captureCompose(t)
	pub, priv := device(t)
	inbox := t.TempDir()
	for i := 0; i < maxPending+10; i++ {
		env, err := box.SignCommand(priv, box.Command{Srv: "srv_mine",
			Exp: time.Now().Add(time.Minute).Unix(), Op: box.OpAppStop,
			Args: map[string]string{"app": "nosuchapp"}})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(env)
		if err := os.WriteFile(filepath.Join(inbox, env.Sig[:16]), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	applyPending(context.Background(), box.AgentConf{ServerID: "srv_mine",
		OperatorKeys: []string{box.FormatDeviceKey(pub)}}, inbox, t.TempDir())

	left, err := os.ReadDir(inbox)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 10 {
		t.Errorf("%d commands left in the inbox, want 10 -- the pass was not bounded at %d",
			len(left), maxPending)
	}
	// None of them reached docker: the app does not exist, so each fails at the
	// lookup. What is under test is the COUNT consumed, not the outcome.
	_ = runs
}

func device(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// appFixture makes a root with one app record in it, so resolveSubject has
// something to find without a box.
func appFixture(t *testing.T, name, dir string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, box.AppsDir), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, box.AppsDir, name+".env"),
		[]byte("APP_NAME="+name+"\nAPP_DIR="+dir+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	return root
}

// withRoot points the applier's lookups at a fixture for the duration of f.
func withRoot(t *testing.T, root string, f func()) {
	t.Helper()
	orig := lookupRoot
	lookupRoot = root
	defer func() { lookupRoot = orig }()
	f()
}

// perform refuses an op it has no verb for.
//
// Unreachable through applyPending today, because VerifyCommand rejects an
// unknown op first -- which is exactly why this is tested directly. The two
// closed sets are in different files, and the failure of them disagreeing is a
// command that reports success having run `docker compose` with no verb at all.
func TestPerformRefusesAnOpItCannotMap(t *testing.T) {
	runs := captureCompose(t)
	// A REAL app, so the refusal under test is the op. Against a machine with
	// no such app this passes with the guard deleted, because the lookup fails
	// one step later -- and then the assertion is about the fixture.
	withRoot(t, appFixture(t, "web", "/srv/web"), func() {
		err := perform(context.Background(), box.Command{Op: "app.detonate",
			Args: map[string]string{"app": "web"}})
		if err == nil {
			t.Error("an op with no verb was performed")
		}
		if len(*runs) != 0 {
			t.Errorf("it reached docker anyway: %v", *runs)
		}
	})
}

// And it checks the app name rather than passing the argument through.
//
// box.AppDir refuses most of these a step later, which is why this asks perform
// itself: a check that is only load-bearing because of the next one is a check
// that silently stops mattering when the next one moves.
func TestPerformChecksTheAppName(t *testing.T) {
	runs := captureCompose(t)
	for _, bad := range []string{"", "../etc", "a/b", "-rf", "web app", "web;id"} {
		err := perform(context.Background(), box.Command{Op: box.OpAppStop,
			Args: map[string]string{"app": bad}})
		if err == nil {
			t.Errorf("app %q was performed", bad)
		}
	}

	// And one that box.AppDir would happily resolve, because its own check is
	// only about path separators. `-rf` is a FLAG once it reaches a command
	// line, and the record it needs is one line in a directory -- so this is
	// what makes AppOf load-bearing rather than a duplicate of the next check.
	withRoot(t, appFixture(t, "-rf", "/srv/rf"), func() {
		if err := perform(context.Background(), box.Command{Op: box.OpAppStop,
			Args: map[string]string{"app": "-rf"}}); err == nil {
			t.Error("an app named like a flag was performed")
		}
	})
	if len(*runs) != 0 {
		t.Errorf("one of them reached docker: %v", *runs)
	}
}

// readBounded refuses a file larger than the bound, without reading it whole.
//
// VerifyCommand bounds the same thing again on the way in. Both exist because
// this one is at ROOT, reading a file an internet-facing process created, and an
// unbounded read there is an unbounded allocation before anything is verified.
func TestReadBoundedRefusesAnOversizedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big")
	if err := os.WriteFile(path, make([]byte, box.MaxCommandBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(path, box.MaxCommandBytes); err == nil {
		t.Error("a file over the bound was read")
	}
	// And one at the bound is fine, so the check is not simply refusing
	// everything.
	if err := os.WriteFile(path, make([]byte, box.MaxCommandBytes), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(path, box.MaxCommandBytes); err != nil {
		t.Errorf("a file at the bound was refused: %v", err)
	}
}
