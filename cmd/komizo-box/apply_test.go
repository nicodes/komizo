package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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

// A FIFO IN THE INBOX MUST NOT HANG ROOTD.
//
// The inbox is owned by the account that talks to the internet, so it can
// mkfifo there. A plain Open on a FIFO blocks in the kernel until somebody
// writes, and this ran inside rootd's loop -- so one command-shaped pipe stopped
// commands AND the report, forever. A box that stops reporting is
// indistinguishable from a box that is down.
func TestAFifoInTheInboxDoesNotHang(t *testing.T) {
	captureCompose(t)
	inbox, results := t.TempDir(), t.TempDir()
	fifo := filepath.Join(inbox, "looks-like-a-command")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot make a fifo here: %v", err)
	}
	pub, _ := device(t)
	conf := box.AgentConf{ServerID: "srv_mine", OperatorKeys: []string{box.FormatDeviceKey(pub)}}

	done := make(chan struct{})
	go func() {
		applyPending(context.Background(), conf, inbox, results)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("applyPending blocked on a fifo -- rootd would stop reporting")
	}
	if _, err := os.Stat(fifo); !os.IsNotExist(err) {
		t.Error("the fifo was left behind to block the next pass too")
	}
}

// And a symlink is not followed, so root cannot be made to read an arbitrary
// file on the box.
func TestASymlinkInTheInboxIsNotFollowed(t *testing.T) {
	inbox := t.TempDir()
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("shhh"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(inbox, "link")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("cannot symlink here: %v", err)
	}
	if _, err := readBounded(link, box.MaxCommandBytes); err == nil {
		t.Error("root followed a symlink out of the inbox")
	}
	// And the target survives: removing the entry unlinks the link, not the file.
	_ = os.Remove(link)
	if _, err := os.Stat(secret); err != nil {
		t.Errorf("the symlink's target was removed: %v", err)
	}
}

// A COMMAND THAT CANNOT BE RECORDED IS NOT PERFORMED.
//
// The record used to be written after the work, so a results directory that
// could not be written to meant the command ran and left no trace -- and then
// ran again on every arrival. Replay protection degraded to nothing, silently,
// in the case somebody would least notice.
func TestACommandIsNotAppliedIfItCannotBeClaimed(t *testing.T) {
	runs := captureCompose(t)
	pub, priv := device(t)
	inbox, results := t.TempDir(), t.TempDir()
	root := appFixture(t, "web", "/srv/web")
	if err := os.Chmod(results, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(results, 0o750) })
	if os.Geteuid() == 0 {
		t.Skip("root ignores the mode this test depends on")
	}

	conf := box.AgentConf{ServerID: "srv_mine", OperatorKeys: []string{box.FormatDeviceKey(pub)}}
	c := box.Command{ID: "unclaimable", Srv: "srv_mine", Exp: time.Now().Add(time.Minute).Unix(),
		Op: box.OpAppStop, Args: map[string]string{"app": "web"}}

	withRoot(t, root, func() {
		for i := 0; i < 3; i++ {
			drop(t, inbox, priv, c)
			applyPending(context.Background(), conf, inbox, results)
		}
	})
	if len(*runs) != 0 {
		t.Errorf("a command ran %d times with no record of it: %v", len(*runs), *runs)
	}
}

// The inbox is bounded, and it is swept whether or not this box takes orders.
//
// A box with no operator keys -- which is every box today -- used to return
// without removing anything, so its inbox filled and stayed full. That
// directory is on tmpfs, which is RAM.
func TestTheInboxIsSweptEvenWhenNothingCanCommand(t *testing.T) {
	captureCompose(t)
	inbox, results := t.TempDir(), t.TempDir()
	for i := 0; i < maxInbox+50; i++ {
		if err := os.WriteFile(filepath.Join(inbox, "junk"+strconv.Itoa(i)), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A directory, which is re-listed every pass forever if it is never removed.
	if err := os.Mkdir(filepath.Join(inbox, "adir"), 0o750); err != nil {
		t.Fatal(err)
	}

	// No operator keys at all.
	applyPending(context.Background(), box.AgentConf{ServerID: "srv_mine"}, inbox, results)

	left, err := os.ReadDir(inbox)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) > maxInbox {
		t.Errorf("%d entries left, want at most %d -- the inbox is unbounded", len(left), maxInbox)
	}
	for _, e := range left {
		if e.IsDir() {
			t.Error("a directory was left in the inbox")
		}
	}
}

// And anything too old to still be valid is removed.
func TestStaleCommandsAreSweptOut(t *testing.T) {
	captureCompose(t)
	inbox, results := t.TempDir(), t.TempDir()
	old := filepath.Join(inbox, "ancient")
	if err := os.WriteFile(old, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-2 * (box.MaxCommandTTL + commandSweepGrace))
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	applyPending(context.Background(), box.AgentConf{ServerID: "srv_mine"}, inbox, results)
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("a command older than it could possibly be valid was kept")
	}
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// "A SENTENCE INSTEAD OF A SILENCE" HAS TO BE READABLE.
//
// app-only.md §4 promises that an op a box does not know fails with a sentence.
// It was printed to the box's stderr and nowhere else, so the app polled a
// result that never appeared and waited forever. This caller is signed by a
// device the box trusts and is entitled to be told.
func TestATrustedCallerIsToldWhatThisBoxCannotDo(t *testing.T) {
	captureCompose(t)
	pub, priv := device(t)
	inbox, results := t.TempDir(), t.TempDir()
	conf := box.AgentConf{ServerID: "srv_mine", OperatorKeys: []string{box.FormatDeviceKey(pub)}}

	payload := []byte(fmt.Sprintf(
		`{"v":1,"id":"unknownop","srv":"srv_mine","exp":%d,"op":"app.hibernate","args":{"app":"web"}}`,
		time.Now().Add(time.Minute).Unix()))
	raw, err := json.Marshal(box.Signed{Payload: b64url(payload), Sig: b64url(ed25519.Sign(priv, payload))})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inbox, "unknownop"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	applyPending(context.Background(), conf, inbox, results)

	r, found := box.ReadResult(results, "unknownop")
	if !found {
		t.Fatal("an op this box cannot do left no result, so the app waits forever")
	}
	if r.OK || !strings.Contains(r.Detail, "app.hibernate") {
		t.Errorf("result = %+v, want a failure naming the op", r)
	}

	// The same for a version this box does not speak, which is the other thing
	// an app that is ahead of a box runs into.
	payload = []byte(fmt.Sprintf(
		`{"v":99,"id":"newversion","srv":"srv_mine","exp":%d,"op":"app.stop","args":{"app":"web"}}`,
		time.Now().Add(time.Minute).Unix()))
	raw, err = json.Marshal(box.Signed{Payload: b64url(payload), Sig: b64url(ed25519.Sign(priv, payload))})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inbox, "newversion"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	applyPending(context.Background(), conf, inbox, results)

	r, found = box.ReadResult(results, "newversion")
	if !found {
		t.Fatal("a version this box does not speak left no result")
	}
	if r.OK || !strings.Contains(r.Detail, "speaks v") {
		t.Errorf("result = %+v, want a failure naming both versions", r)
	}
}

// A BOX WITH NO SERVER ID OBEYS NOBODY.
//
// Held by two guards -- the credential's CanCommand and the envelope's audience
// check -- and pinned by neither: removing both left the suite green. No command
// can name a machine no registry has heard of.
func TestABoxWithNoServerIDAppliesNothing(t *testing.T) {
	runs := captureCompose(t)
	pub, priv := device(t)
	inbox, results := t.TempDir(), t.TempDir()

	// Keys planted, no server id -- an un-enrolled box that somebody gave a
	// device key to.
	conf := box.AgentConf{OperatorKeys: []string{box.FormatDeviceKey(pub)}}
	drop(t, inbox, priv, box.Command{ID: "nosrv", Srv: "srv_mine",
		Exp: time.Now().Add(time.Minute).Unix(), Op: box.OpAppStop,
		Args: map[string]string{"app": "web"}})

	applyPending(context.Background(), conf, inbox, results)
	if len(*runs) != 0 {
		t.Errorf("a box no registry has heard of obeyed a command: %v", *runs)
	}
	if _, found := box.ReadResult(results, "nosrv"); found {
		t.Error("it answered one, too")
	}

	// And the case the two guards actually overlap on: a command that names NO
	// server, at a box that has none. Both empty compare equal, so an audience
	// check written as a plain inequality would accept it. SignCommand refuses
	// to mint one, so it is built by hand.
	payload := []byte(fmt.Sprintf(
		`{"v":1,"id":"nosrv2","srv":"","exp":%d,"op":"app.stop","args":{"app":"web"}}`,
		time.Now().Add(time.Minute).Unix()))
	raw, err := json.Marshal(box.Signed{Payload: b64url(payload), Sig: b64url(ed25519.Sign(priv, payload))})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inbox, "nosrv2"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// With a REAL app, so that if both guards were gone the command would reach
	// docker rather than dying at a lookup -- which is what made an earlier
	// version of this pass against the hole it was written for.
	withRoot(t, appFixture(t, "web", "/srv/web"), func() {
		applyPending(context.Background(), conf, inbox, results)
	})
	if len(*runs) != 0 {
		t.Errorf("a command naming no server was applied at a box with none: %v", *runs)
	}
}

// ROOTD NEVER READS A FILE THAT IS STILL BEING WRITTEN.
//
// The route writes to `.tmp-*` and renames, which is only atomic if nothing
// reads the temporary -- and this loop filtered on IsDir alone. A complete but
// unrenamed temp was applied and then removed, so the rename failed and the
// caller was told 503 for a command that had run. A partial one was removed, so
// the caller was told 503 for a command that was discarded. Both are the
// "silently might have" the design exists to prevent.
func TestRootdIgnoresTheRoutesTemporaries(t *testing.T) {
	runs := captureCompose(t)
	pub, priv := device(t)
	inbox, results := t.TempDir(), t.TempDir()
	root := appFixture(t, "web", "/srv/web")
	conf := box.AgentConf{ServerID: "srv_mine", OperatorKeys: []string{box.FormatDeviceKey(pub)}}

	// A complete, valid, correctly signed command -- sitting under a temporary
	// name, exactly as it does for the moment between write and rename.
	c := box.Command{ID: "inflight", Srv: "srv_mine", Exp: time.Now().Add(time.Minute).Unix(),
		Op: box.OpAppStop, Args: map[string]string{"app": "web"}}
	env, err := box.SignCommand(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(inbox, ".tmp-123456")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	withRoot(t, root, func() {
		applyPending(context.Background(), conf, inbox, results)
	})
	if len(*runs) != 0 {
		t.Errorf("root applied a command that was still being written: %v", *runs)
	}
	if _, err := os.Stat(tmp); err != nil {
		t.Error("the temporary was removed, so the rename would fail and the caller " +
			"would be told 503 for a command that was discarded")
	}
	if _, found := box.ReadResult(results, c.ID); found {
		t.Error("a result was written for a command that had not arrived")
	}

	// And the installer's own probe file is not a command either.
	probe := filepath.Join(inbox, ".probe")
	if err := os.WriteFile(probe, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	applyPending(context.Background(), conf, inbox, results)
	if _, err := os.Stat(probe); err != nil {
		t.Error("the installer's probe was treated as a command")
	}
}

// A COMMAND DROPPED FOR CAPACITY IS TOLD, NOT DISCARDED.
//
// Readdir order on tmpfs is roughly hash order rather than arrival order, so
// the bound removes arbitrary valid, signed, unapplied commands -- and with no
// result the app polls a 404 forever for something nothing ever refused.
func TestACommandDroppedForCapacityGetsAResult(t *testing.T) {
	captureCompose(t)
	pub, _ := device(t)
	inbox, results := t.TempDir(), t.TempDir()
	conf := box.AgentConf{ServerID: "srv_mine", OperatorKeys: []string{box.FormatDeviceKey(pub)}}

	var ids []string
	for i := 0; i < maxInbox+20; i++ {
		id, err := box.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
		if err := os.WriteFile(filepath.Join(inbox, id), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	applyPending(context.Background(), conf, inbox, results)

	dropped := 0
	for _, id := range ids {
		if r, found := box.ReadResult(results, id); found && !r.OK &&
			strings.Contains(r.Detail, "too many") {
			dropped++
		}
	}
	if dropped == 0 {
		t.Error("commands were removed for capacity with no result, so the app polls forever")
	}
}

// A COMMAND DROPPED IN THE SWEEP STILL GETS AN ANSWER.
//
// This loop is serial and provisionTimeout is fifteen minutes, against a
// command that stops being valid after six -- so a stop pressed while an
// app.add was running was deleted in silence, and the screen waited out its
// own deadline for an answer that had already been thrown away.
//
// The command really did expire. What was missing was saying so, and the app
// tells "the box refused this" and "the box never answered" apart.
func TestASweptCommandIsToldItWasSwept(t *testing.T) {
	runs := captureCompose(t)
	pub, priv := device(t)
	inbox, results := t.TempDir(), t.TempDir()
	conf := box.AgentConf{ServerID: "srv_mine", OperatorKeys: []string{box.FormatDeviceKey(pub)}}

	id := "sweptCommandId"
	path := drop(t, inbox, priv, box.Command{ID: id, Srv: "srv_mine",
		Exp: time.Now().Add(time.Minute).Unix(),
		Op:  box.OpAppStop, Args: map[string]string{"app": "web"}})
	// Renamed to its id, because that is what the route writes and what the
	// sweep files a result under.
	filed := filepath.Join(inbox, id)
	if err := os.Rename(path, filed); err != nil {
		t.Fatal(err)
	}
	// Old enough that no clock difference could still make it valid.
	old := time.Now().Add(-(box.MaxCommandTTL + commandSweepGrace + time.Hour))
	if err := os.Chtimes(filed, old, old); err != nil {
		t.Fatal(err)
	}

	applyPending(context.Background(), conf, inbox, results)

	if len(*runs) != 0 {
		t.Fatalf("an expired command was applied: %v", *runs)
	}
	if _, err := os.Stat(filed); !os.IsNotExist(err) {
		t.Error("the expired command was left in the inbox")
	}
	r, found := box.ReadResult(results, id)
	if !found {
		t.Fatal("a swept command wrote no result, so the app waits out its whole deadline for nothing")
	}
	if r.OK {
		t.Error("a swept command was reported as having succeeded")
	}
	if !strings.Contains(r.Detail, "expired") {
		t.Errorf("detail = %q, want it to say the command expired", r.Detail)
	}
}
