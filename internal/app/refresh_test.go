package app

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/scripts"
)

// An update that leaves every app's deploy script exactly as it found it.
//
// That was `komizo update` until komizo#58: it ran the init script, installed
// the agent, re-ran the proxy, and never touched scripts/alpine.sh -- which is
// the only thing that writes deploy-<app>. The operator was told the box was up
// to date and every app on it kept running the previous release's generated
// shell, for as long as nobody happened to re-run `komizo add` per app.
//
// The tests below are in three layers because the failure can hide in three
// places: the surfaces can forget to call it, the environment it passes can
// quietly reconfigure the app it was meant to leave alone, and the script it
// runs can drop the one piece of state an update must never touch. The last of
// those is run rather than read -- the record after a simulated update is
// produced by executing alpine.sh's own blocks, driven by the environment the
// Go code actually builds.

// --- layer 1: both surfaces call it ----------------------------------------

// A capability on one surface and not the other is the shape of bug this whole
// change is about, one level up: `komizo update` and the interface's `u` are
// the same operation, and the sentence in update.go promising to re-run "the
// whole setup" was true of the comment and of neither caller.
func TestEveryUpdatePathRefreshesEveryAppsScripts(t *testing.T) {
	for _, tc := range []struct{ file, fn string }{
		{"update.go", "RunUpdate"},
		{"tui_server.go", "startKomizoUpdate"},
	} {
		body := functionBody(t, sourceOf(t, tc.file), tc.fn)
		if !strings.Contains(body, "refreshBoxApps") {
			t.Errorf("%s in %s updates a box without regenerating any app's deploy "+
				"script -- every app on it keeps the one it already had, and the "+
				"command still reports the box up to date (komizo#58)", tc.fn, tc.file)
			continue
		}

		// AND THE RESULT HAS TO GO SOMEWHERE. Calling it and dropping what it
		// says is the same outcome as not calling it, one step later: an app
		// that was skipped or that failed its run is an app silently still
		// carrying the old deploy script, and refreshApps' whole reason for
		// returning an error is that this must not be silent. A substring
		// search for the call cannot tell `appErr := f()` from `_ = f()`, and
		// Review 1 found exactly that mutant alive.
		m := regexp.MustCompile(`(\w+)\s*:?=\s*refreshBoxApps\(`).FindStringSubmatch(body)
		if m == nil {
			t.Errorf("%s in %s calls refreshBoxApps without keeping what it returns, so an "+
				"app it could not refresh is never reported", tc.fn, tc.file)
			continue
		}
		v := m[1]
		if v == "_" {
			t.Errorf("%s in %s throws away refreshBoxApps' error", tc.fn, tc.file)
			continue
		}
		// Somewhere after the call, that value has to reach the caller: returned,
		// joined with another failure, or put on the message the interface ends on.
		out := regexp.MustCompile(`(?m)^\s*(return|ch <- runDoneMsg\{|.*errors\.Join\().*\b` +
			regexp.QuoteMeta(v) + `\b`)
		if !out.MatchString(body) {
			t.Errorf("%s in %s keeps refreshBoxApps' error in %s and never reports it -- "+
				"an app that was not refreshed ends the command green", tc.fn, tc.file, v)
		}
		// AND EVERY exit path after it, not just one.
		//
		// "at least one path reports it" and "no path says return nil" are both
		// satisfied while a SECOND path quietly drops it, which is what Review 2
		// found: the interface's done message could carry `err: nil` while the
		// proxy-failure branch above it still mentioned the value, and the CLI
		// could drop it from its errors.Join while the final return kept it. So
		// the exit paths are enumerated rather than searched, which needs the
		// parser rather than a regexp.
		assertEveryExitReports(t, tc.file, tc.fn, v)
	}
}

// assertEveryExitReports walks a function and requires every value-returning
// exit after the refresh -- a `return x`, or a message put on the run channel --
// to mention the name the refresh's error was kept in.
//
// A bare `return` is exempt: the interface reports by sending on a channel and
// then returning, so the report is on the line before. What is NOT exempt is
// the message itself, which is why runDoneMsg literals are checked as well as
// returns.
func assertEveryExitReports(t *testing.T, file, fn, name string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(".", file), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var decl *ast.FuncDecl
	ast.Inspect(f, func(n ast.Node) bool {
		if d, ok := n.(*ast.FuncDecl); ok && d.Name.Name == fn {
			decl = d
		}
		return decl == nil
	})
	if decl == nil {
		t.Fatalf("could not find func %s in %s", fn, file)
	}

	// The call, and the span it occupies. Anything inside it -- the runner
	// closure, most obviously -- belongs to the refresh rather than to the
	// function's own exits.
	var call *ast.CallExpr
	ast.Inspect(decl, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "refreshBoxApps" {
			call = c
			return false
		}
		return true
	})
	if call == nil {
		t.Fatalf("could not find the refreshBoxApps call in %s", fn)
	}

	// The exits that matter are the ones of the function the call SITS IN. In
	// the interface that is the goroutine, not the surrounding tea.Cmd: the
	// latter's `return m.run.wait()` hands back a command to run, not a result,
	// and has nothing to do with whether an app was refreshed.
	var scope ast.Node = decl
	ast.Inspect(decl, func(n ast.Node) bool {
		lit, ok := n.(*ast.FuncLit)
		if !ok {
			return true
		}
		if lit.Pos() < call.Pos() && lit.End() > call.End() {
			scope = lit // innermost wins, because Inspect descends
		}
		return true
	})

	mentions := func(n ast.Node) bool {
		found := false
		ast.Inspect(n, func(m ast.Node) bool {
			if id, ok := m.(*ast.Ident); ok && id.Name == name {
				found = true
			}
			return !found
		})
		return found
	}

	checked := 0
	ast.Inspect(scope, func(n ast.Node) bool {
		if n == nil || n.Pos() < call.End() || (n.Pos() >= call.Pos() && n.End() <= call.End()) {
			return true
		}
		switch x := n.(type) {
		case *ast.ReturnStmt:
			if len(x.Results) == 0 {
				return true // reports by sending, on the line above
			}
			checked++
			if !mentions(x) {
				t.Errorf("%s in %s has a return after the refresh that does not carry %s, "+
					"so that path ends green with apps still on the old deploy script:\n    %s",
					fn, file, name, exprText(fset, x))
			}
		case *ast.CompositeLit:
			id, ok := x.Type.(*ast.Ident)
			if !ok || id.Name != "runDoneMsg" {
				return true
			}
			checked++
			if !mentions(x) {
				t.Errorf("%s in %s ends the run with a message that does not carry %s -- the "+
					"interface would show a clean update over apps that were never refreshed, "+
					"while `komizo update` on the same box fails:\n    %s",
					fn, file, name, exprText(fset, x))
			}
		}
		return true
	})
	if checked == 0 {
		t.Errorf("%s in %s has no exit path after the refresh at all -- this check found "+
			"nothing to assert, which means it is not asserting anything", fn, file)
	}
}

func exprText(fset *token.FileSet, n ast.Node) string {
	var b strings.Builder
	if err := printer.Fprint(&b, fset, n); err != nil {
		return "?"
	}
	return b.String()
}

// The seam itself, which is where the whole feature can be switched off.// The seam itself, which is where the whole feature can be switched off.
//
// Everything above refreshBoxApps is a surface and everything below it is
// logic, so a version of it that quietly returned nil would restore exactly the
// behaviour komizo#58 is about while every test entering below it stayed green.
// That mutant was alive until Review 1 ran it.
func TestTheSeamActuallyListsAndActs(t *testing.T) {
	recs := []appRecord{
		{name: "blog", user: "komizo-blog", config: "ghcr.io/you/blog-config", dir: "/srv/blog"},
	}
	r := &recordingRunner{}
	if err := refreshBoxApps(func() ([]appRecord, error) { return recs, nil }, &silentProgress{}, r.run); err != nil {
		t.Fatalf("refreshBoxApps: %v", err)
	}
	if got := r.appRuns(); len(got) != 1 || got[0]["APP_NAME"] != "blog" {
		t.Fatalf("the seam listed the apps and did nothing with them: ran %d time(s)", len(got))
	}
	// AND SSHD WAS RELOADED ONCE, not once per app -- komizo#65. Each per-app
	// reload is a window in which a CI deploy dialling this box can fail, and
	// the count used to grow with the fleet.
	if n := r.reloads(); n != 1 {
		t.Errorf("sshd was reloaded %d times for 1 app, want exactly 1", n)
	}

	// A box that cannot say what is on it must fail rather than report that
	// there is nothing to do. "no apps on this box" over an unreadable box is
	// the same green silence as never looking.
	boom := fmt.Errorf("ssh said no")
	r2 := &recordingRunner{}
	err := refreshBoxApps(func() ([]appRecord, error) { return nil, boom }, &silentProgress{}, r2.run)
	if !errors.Is(err, boom) {
		t.Errorf("a box whose apps could not be listed did not fail the update: %v", err)
	}
	if len(r2.envs) != 0 {
		t.Errorf("it ran the setup script for %d app(s) it could not list", len(r2.envs))
	}

	// And a listing that WORKS while an app fails must still fail the update.
	// Review 2 found this: the two cases above cover "the listing worked" and
	// "the listing failed", and a seam that dropped refreshApps' own result
	// passed both -- which is Review 1's blocker one layer further down, and the
	// same green silence over an app still carrying the old deploy script.
	r3 := &recordingRunner{fail: map[string]error{"blog": fmt.Errorf("boom")}}
	if err := refreshBoxApps(func() ([]appRecord, error) { return recs, nil }, &silentProgress{}, r3.run); err == nil {
		t.Error("an app that failed its re-run did not fail the update")
	}
}

// The enumeration is SHELL, and it decides which apps exist. Run it.
//
// Nothing here was executed until Review 1 pointed out that replacing the whole
// command with `true` left the suite green -- which on a box is the original
// bug wearing the fix's clothes: `komizo update` prints "no apps on this box",
// exits 0, and every app keeps last release's deploy script while the operator
// is told a second time that the box is up to date.
func TestTheEnumerationFindsEveryAppAndNothingElse(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	// The command every box gets must be this same command, pointed at the
	// directory komizo enumerates. Otherwise this test proves things about a
	// directory nothing reads.
	if appRecordsCmd != appRecordsCmdFor(box.AppsDir) {
		t.Fatal("the shipped enumeration is not the one this test runs")
	}

	run := func(t *testing.T, dir string) []appRecord {
		t.Helper()
		out := enumerate(t, dir)
		// THE BOX STRIPS THE CR, not the parser. parseAppRecords trims each
		// field as well, so a CR left on would be invisible here -- and the
		// shell strip is the one that matters, because the deploy script and
		// alpine.sh read these same files with the same idiom and there is no
		// Go trim behind them. Asserted on the raw output for that reason.
		if strings.Contains(out, "\r") {
			t.Errorf("the enumeration handed back a carriage return: %q", out)
		}
		return parseAppRecords(out)
	}

	t.Run("a box with apps on it", func(t *testing.T) {
		dir := t.TempDir()
		// A plain record; one with a custom account and directory; one with
		// CRLF endings; one from before some key existed.
		write(t, filepath.Join(dir, "blog.env"), 0o640,
			"APP_NAME=blog\nAPP_DIR=/srv/blog\nCI_USER=komizo-blog\nCONFIG_IMAGE=ghcr.io/you/blog-config\nKNOWN_AS=\n")
		write(t, filepath.Join(dir, "shop.env"), 0o640,
			"APP_NAME=shop\nAPP_DIR=/opt/shop\nCI_USER=deployer\nCONFIG_IMAGE=registry.internal:5000/shop-config\n")
		write(t, filepath.Join(dir, "wiki.env"), 0o640,
			"APP_NAME=wiki\r\nAPP_DIR=/srv/wiki\r\nCI_USER=komizo-wiki\r\nCONFIG_IMAGE=ghcr.io/you/wiki-config\r\n")
		write(t, filepath.Join(dir, "old.env"), 0o640, "APP_NAME=old\n")
		// A record with a key twice. FIRST WINS, which every other reader of
		// these files also does -- box/paths.go states it as an invariant, and
		// box/stopped.go's argument that a forged duplicate key is inert rests
		// on it holding for EVERY reader, of which this is now the fourth.
		//
		// The failure if it stopped holding is not a wrong value, it is a
		// disappearance: the command substitution would span two lines, so this
		// app's row splits into fragments with too few fields each,
		// parseAppRecords drops both, and `komizo update` refreshes every app on
		// the box except that one while saying nothing about it.
		write(t, filepath.Join(dir, "twice.env"), 0o640,
			"APP_NAME=twice\nAPP_DIR=/srv/twice\nCI_USER=komizo-twice\n"+
				"CONFIG_IMAGE=ghcr.io/you/twice-config\n"+
				// Every column duplicated, because the line count only catches a
				// spill in the column that spilled.
				"CI_USER=impostor\nCONFIG_IMAGE=ghcr.io/impostor\nAPP_DIR=/tmp/impostor\n")
		// A record whose APP_NAME disagrees with its file name. The FILE NAME
		// wins, because that is what alpine.sh, box/paths.go and the deploy
		// script's cross-app scan all key on -- taking the line instead would
		// have this command reprovision a different app than the one whose
		// record it is holding, with that app's directory and account.
		write(t, filepath.Join(dir, "renamed.env"), 0o640,
			"APP_NAME=somethingelse\nAPP_DIR=/srv/renamed\nCI_USER=komizo-renamed\nCONFIG_IMAGE=ghcr.io/you/renamed-config\n")
		// Things that are NOT apps and must not be treated as any: a record a
		// dying run left behind, a backup, and a directory.
		write(t, filepath.Join(dir, "blog.env.tmp.999"), 0o640, "APP_NAME=blog\nAPP_DIR=/tmp/wrong\n")
		write(t, filepath.Join(dir, "notes.env.bak"), 0o640, "APP_NAME=notes\nAPP_DIR=/srv/notes\n")
		if err := os.MkdirAll(filepath.Join(dir, "adir.env"), 0o750); err != nil {
			t.Fatal(err)
		}

		want := []appRecord{
			{name: "blog", user: "komizo-blog", config: "ghcr.io/you/blog-config", dir: "/srv/blog"},
			{name: "old"},
			{name: "renamed", user: "komizo-renamed", config: "ghcr.io/you/renamed-config", dir: "/srv/renamed"},
			{name: "shop", user: "deployer", config: "registry.internal:5000/shop-config", dir: "/opt/shop"},
			{name: "twice", user: "komizo-twice", config: "ghcr.io/you/twice-config", dir: "/srv/twice"},
			// The CR is stripped ON THE BOX. Left on, every value fails
			// check()'s charset test and the app is refused for a reason
			// invisible in the file and in the message.
			{name: "wiki", user: "komizo-wiki", config: "ghcr.io/you/wiki-config", dir: "/srv/wiki"},
		}
		// ONE LINE PER APP. A read that lost its `head -n 1` spills a second
		// line into the output, and depending on which column it is the row
		// either splits into fragments the parser drops -- an app that silently
		// vanishes from the update -- or quietly parses right while leaving a
		// stray behind. Counting the lines catches both; comparing the records
		// only catches the first.
		if n := len(strings.Split(strings.TrimRight(enumerate(t, dir), "\n"), "\n")); n != len(want) {
			t.Errorf("the enumeration printed %d lines for %d apps -- a value that spans two "+
				"lines splits that app's row into fragments the parser drops", n, len(want))
		}
		got := run(t, dir)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("the enumeration read the box wrongly:\n got %+v\nwant %+v", got, want)
		}
	})

	// A box that has never had an app, and a box whose state directory does not
	// exist at all. Both must be "no apps", not an error and not one app called
	// "*".
	t.Run("a box with no apps", func(t *testing.T) {
		if got := run(t, t.TempDir()); len(got) != 0 {
			t.Errorf("an empty state directory produced %+v", got)
		}
	})
	t.Run("a box with no state directory", func(t *testing.T) {
		if got := run(t, filepath.Join(t.TempDir(), "never-created")); len(got) != 0 {
			t.Errorf("a missing state directory produced %+v", got)
		}
	})
}

// --- layer 2: what one app's re-run is told --------------------------------

// recordingRunner stands in for the SSH pipe: it remembers what would have been
// sent to the box instead of sending it.
type recordingRunner struct {
	scripts []string
	envs    []map[string]string
	fail    map[string]error
}

func (r *recordingRunner) run(script string, env map[string]string) error {
	r.scripts = append(r.scripts, script)
	r.envs = append(r.envs, env)
	return r.fail[env["APP_NAME"]]
}

// appRuns is the per-app script only.
//
// SEPARATED FROM THE RELOAD, because komizo#65 made an update run two different
// scripts: alpine.sh once per app, and alpine-reload-sshd.sh once at the end.
// Counting every invocation together made "ran once per app" and "ran once per
// app plus a reload" indistinguishable -- so a reload that fired per app, which
// is the bug #65 is about, would look the same as one that fired once.
func (r *recordingRunner) appRuns() []map[string]string {
	var out []map[string]string
	for i, sc := range r.scripts {
		if sc != scripts.AlpineReloadSSHDScript {
			out = append(out, r.envs[i])
		}
	}
	return out
}

// reloads is how many times the daemon was actually told to pick the config up.
func (r *recordingRunner) reloads() int {
	n := 0
	for _, sc := range r.scripts {
		if sc == scripts.AlpineReloadSSHDScript {
			n++
		}
	}
	return n
}

type silentProgress struct{ lines []string }

func (p *silentProgress) step(format string, a ...any) {
	p.lines = append(p.lines, fmt.Sprintf(format, a...))
}
func (p *silentProgress) note(format string, a ...any) {
	p.lines = append(p.lines, fmt.Sprintf(format, a...))
}

// Every app on the box, with that app's own settings and nobody else's.
//
// The two records here are deliberately the awkward ones: an app whose deploy
// account is NOT komizo-<app> and whose directory is NOT /srv/<app>. Those are
// the two values alpine.sh will happily default for itself, and both defaults
// are destructive applied to an app that chose otherwise -- see appRecord.check.
func TestAnUpdateReprovisionsEveryAppWithItsOwnSettings(t *testing.T) {
	recs := []appRecord{
		{name: "blog", user: "komizo-blog", config: "ghcr.io/you/blog-config", dir: "/srv/blog"},
		{name: "shop", user: "deployer", config: "registry.internal:5000/shop-config", dir: "/opt/shop"},
	}
	r := &recordingRunner{}
	if err := refreshApps(recs, &silentProgress{}, r.run); err != nil {
		t.Fatalf("refreshApps: %v", err)
	}
	runs := r.appRuns()
	if len(runs) != 2 {
		t.Fatalf("ran %d times for 2 apps -- an app that is not re-run is an app "+
			"still carrying the old deploy script", len(runs))
	}
	// ONE reload for the pair, not one each -- komizo#65.
	//
	// BOTH HALVES, and the second is the one that matters. Counting the reload
	// script alone says nothing about whether alpine.sh still reloads per app:
	// setting DEFER_SSHD_RELOAD to "0" restores #65 in full -- N per-app reloads
	// plus the new one -- and the count above stays at 1. Verified by doing it.
	//
	// So every app run must carry the deferral, and the script must honour it.
	if n := r.reloads(); n != 1 {
		t.Errorf("sshd was reloaded %d times for 2 apps, want exactly 1", n)
	}
	for _, env := range runs {
		if env["DEFER_SSHD_RELOAD"] != "1" {
			t.Errorf("%s was refreshed without DEFER_SSHD_RELOAD=1, so alpine.sh reloads sshd "+
				"for it -- that is one window per app, which is komizo#65", env["APP_NAME"])
		}
	}
	// And the script actually branches on it. A flag nothing reads is a flag.
	if !strings.Contains(scripts.AlpineScript, `"${DEFER_SSHD_RELOAD:-0}" = "1"`) {
		t.Error("alpine.sh no longer honours DEFER_SSHD_RELOAD, so passing it changes nothing")
	}
	for i, want := range recs {
		if i < len(r.scripts) && r.scripts[i] != scripts.AlpineScript {
			t.Errorf("%s was not re-run with the app setup script", want.name)
		}
		got := r.envs[i]
		for k, v := range map[string]string{
			"APP_NAME":     want.name,
			"CI_USER":      want.user,
			"CONFIG_IMAGE": want.config,
			"APP_DIR":      want.dir,
		} {
			if got[k] != v {
				t.Errorf("%s: %s=%q, want %q -- an update must reprovision an app "+
					"with the settings it already has, not with defaults", want.name, k, got[k], v)
			}
		}
	}
}

// The three inputs an update must NOT express an opinion about. Each one is a
// way for a routine upgrade to break something nobody asked it to touch.
func TestAnUpdateRotatesNoKeyAndChangesNoPolicy(t *testing.T) {
	env := appRefreshEnv(appRecord{
		name: "blog", user: "komizo-blog", config: "ghcr.io/you/blog-config", dir: "/srv/blog",
	})
	for _, tc := range []struct{ key, want, why string }{
		{"CI_PUBKEY", "", "a key here REPLACES the account's authorized_keys, so every " +
			"repo's deploy secret would stop working the moment somebody updated the box"},
		{"KNOWN_AS", "", "an update is not saying the names CI dials this app by have changed"},
		{"CLEAR_KNOWN_AS", "0", "clearing them would fail the next deploy's host key check " +
			"on a name that had worked for months"},
		{"HARDEN_SSH", "0", "whether root may log in with a password is a decision about the " +
			"whole machine, not something an upgrade gets to take"},
	} {
		if got, ok := env[tc.key]; !ok || got != tc.want {
			t.Errorf("%s=%q (present=%v), want %q -- %s", tc.key, got, ok, tc.want, tc.why)
		}
	}
	// Nothing may name the stop marker in either direction. alpine.sh carries it
	// across its own rewrite; an input that set or cleared one would make an
	// upgrade a decision about whether an app should be running.
	for k := range env {
		if strings.HasPrefix(k, "STOPPED") {
			t.Errorf("the refresh passes %s -- an update must not decide whether an app runs", k)
		}
	}
}

// An app whose record cannot fully describe it is left alone, and the command
// fails saying so. Silently skipping it would be this bug with an extra step:
// the app keeps the old deploy script and everything reports success.
func TestAnAppWhoseRecordIsIncompleteIsSkippedAndReported(t *testing.T) {
	good := appRecord{name: "blog", user: "komizo-blog", config: "ghcr.io/you/blog-config", dir: "/srv/blog"}
	for _, tc := range []struct {
		name string
		rec  appRecord
		// missing says the record is INCOMPLETE rather than malformed. Those
		// three get their message checked below as well: a value that is absent
		// has no wrong value to quote back, so the sentence has to be komizo's
		// own rather than a validator's.
		missing bool
	}{
		{name: "no CI_USER", missing: true,
			rec: appRecord{name: "shop", config: good.config, dir: "/srv/shop"}},
		{name: "no CONFIG_IMAGE", missing: true,
			rec: appRecord{name: "shop", user: "komizo-shop", dir: "/srv/shop"}},
		{name: "no APP_DIR", missing: true,
			rec: appRecord{name: "shop", user: "komizo-shop", config: good.config}},
		{name: "a malformed CI_USER",
			rec: appRecord{name: "shop", user: "komizo shop",
				config: good.config, dir: "/srv/shop"}},
		{name: "a config image with a tag",
			rec: appRecord{name: "shop", user: "komizo-shop",
				config: "ghcr.io/you/shop-config:v1", dir: "/srv/shop"}},
		{name: "a traversal in APP_DIR",
			rec: appRecord{name: "shop", user: "komizo-shop",
				config: good.config, dir: "/srv/../etc"}},
		{name: "a reserved name",
			rec: appRecord{name: "_proxy", user: "komizo-x",
				config: good.config, dir: "/srv/_proxy"}},
	} {
		// BOTH ORDERS. A bad record listed last cannot tell "skip this one" from
		// "stop here", and the apps on a box are refreshed in whatever order the
		// box lists them -- so the version that gives up on the first problem
		// leaves every app after it on the old deploy script, silently, and only
		// on the boxes whose first app is the broken one.
		for _, order := range []struct {
			name string
			recs []appRecord
		}{
			{"the bad record first", []appRecord{tc.rec, good}},
			{"the bad record last", []appRecord{good, tc.rec}},
		} {
			t.Run(tc.name+", "+order.name, func(t *testing.T) {
				r := &recordingRunner{}
				p := &silentProgress{}
				err := refreshApps(order.recs, p, r.run)
				if err == nil {
					t.Fatal("an app that was not refreshed must fail the command -- it is " +
						"still running the deploy script the update was supposed to replace")
				}
				if !strings.Contains(err.Error(), tc.rec.name) {
					t.Errorf("the error does not name %s: %v", tc.rec.name, err)
				}
				if got := r.appRuns(); len(got) != 1 || got[0]["APP_NAME"] != good.name {
					t.Errorf("ran for %d app(s); the good one must still be refreshed and the "+
						"bad one must not be touched", len(got))
				}
				// NO reason may be reported as a bad FLAG. The validators are
				// written for `komizo add`, where there is a --user or a
				// --config to be wrong about; an update passes neither, so
				// falling through to one of them tells the operator to go and
				// fix something they never typed while the record that is
				// actually wrong goes unmentioned. Checked for the malformed
				// records as well as the incomplete ones -- Review 1 found the
				// flag text still leaking through those after the missing cases
				// had been dealt with, and those are the ones an operator's own
				// stray file produces.
				said := strings.Join(p.lines, "\n")
				for _, flag := range []string{"--user", "--config", "--app-dir", "--app "} {
					if strings.Contains(said, flag) {
						t.Errorf("the skip blames %s, which nothing passed to `komizo update`:\n%s",
							flag, said)
					}
				}
				if !tc.missing {
					return
				}
				for _, key := range []string{"CI_USER", "CONFIG_IMAGE", "APP_DIR"} {
					if strings.Contains(tc.name, key) && !strings.Contains(said, key) {
						t.Errorf("the skip never names %s, which is the line missing from the "+
							"record:\n%s", key, said)
					}
				}
			})
		}
	}
}

// One app failing on the box does not abandon the others, and the command still
// fails at the end.
func TestOneAppFailingDoesNotStopTheRest(t *testing.T) {
	recs := []appRecord{
		{name: "blog", user: "komizo-blog", config: "ghcr.io/you/blog-config", dir: "/srv/blog"},
		{name: "shop", user: "komizo-shop", config: "ghcr.io/you/shop-config", dir: "/srv/shop"},
		{name: "wiki", user: "komizo-wiki", config: "ghcr.io/you/wiki-config", dir: "/srv/wiki"},
	}
	r := &recordingRunner{fail: map[string]error{"shop": fmt.Errorf("boom")}}
	err := refreshApps(recs, &silentProgress{}, r.run)
	if err == nil || !strings.Contains(err.Error(), "shop") {
		t.Fatalf("want a failure naming shop, got %v", err)
	}
	if got := r.appRuns(); len(got) != 3 {
		t.Errorf("ran %d times; a failure on one app must not leave the ones after it "+
			"on the old deploy script", len(got))
	}
	// AND THE PARTIAL RUN STILL RELOADS. The apps that succeeded have written
	// and validated their sshd blocks but deferred the reload, so skipping it
	// would leave their deploy accounts unable to connect at all -- a worse
	// outcome than the one failed app.
	if n := r.reloads(); n != 1 {
		t.Errorf("sshd was reloaded %d times after a partial refresh, want 1", n)
	}
}

// --- layer 2b: reading the apps off the box --------------------------------

func TestReadingTheAppsOffABox(t *testing.T) {
	got := parseAppRecords(strings.Join([]string{
		"blog\tkomizo-blog\tghcr.io/you/blog-config\t/srv/blog",
		"shop\tdeployer\tregistry.internal:5000/shop-config\t/opt/shop",
		"",                      // the trailing newline of any output at all
		"half\tkomizo-half\t\t", // a record missing values still arrives, to be refused later
		// Not a line this command printed -- an ssh banner, a motd, anything
		// the login shell had to say before the loop ran. Read as an app it
		// would be an app komizo tries to reprovision.
		"Welcome to Alpine!",
		"partial\tkomizo-partial",
		// A tab INSIDE a value, from a record somebody edited by hand. It must
		// not shorten the line into something unrecognisable: the value lands
		// in the last field, keeps its tab, and is refused by name below.
		"odd\tkomizo-odd\tghcr.io/you/odd-config\t/srv/odd\tx",
	}, "\n"))
	want := []appRecord{
		{name: "blog", user: "komizo-blog", config: "ghcr.io/you/blog-config", dir: "/srv/blog"},
		{name: "shop", user: "deployer", config: "registry.internal:5000/shop-config", dir: "/opt/shop"},
		{name: "half", user: "komizo-half"},
		{name: "odd", user: "komizo-odd", config: "ghcr.io/you/odd-config", dir: "/srv/odd\tx"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseAppRecords:\n got %+v\nwant %+v", got, want)
	}
	// A record komizo cannot act on must still be SEEN. Dropping it during the
	// parse would mean the command never mentions it, which is the silence this
	// whole change exists to remove -- check() is what refuses it, out loud.
	for _, r := range []appRecord{want[2], want[3]} {
		if err := r.check(); err == nil {
			t.Errorf("%s should have been refused: %+v", r.name, r)
		}
	}
}

// The directory the Go side enumerates and the one the script writes into have
// to be the same directory. If they ever drift, the shell test below would
// happily prove things about a file nothing reads.
func TestTheScriptsStateDirIsTheOneKomizoEnumerates(t *testing.T) {
	want := "STATE_DIR=" + box.AppsDir + "\n"
	if !strings.Contains(scripts.AlpineScript, want) {
		t.Errorf("alpine.sh does not contain %q -- the app setup script and box.AppsDir "+
			"disagree about where an app's record lives", strings.TrimSpace(want))
	}
}

// The two languages have to take the SAME lock, by name.
//
// alpine.sh rewrites an app's record whole and box/stopped.go rewrites three
// keys of it, and the safety argument for running the first once per app on
// every update is that the two exclude each other. They only do if the path
// matches: two processes locking different files exclude nothing, and
// stopped.go's own comment says exactly that. Same shape as the STATE_DIR test
// above, and for the same reason -- this is the kind of agreement that drifts
// silently and takes the suite's word for it with it.
func TestTheStateLockIsTheSameFileInBothLanguages(t *testing.T) {
	// Built from box.RecordLockName, so this is ONE definition compared against
	// the shell rather than two literals that happen to look alike. Review 2
	// pointed out that pinning the directory alone left the NAME free to drift
	// on either side -- the same "two processes locking different files exclude
	// nothing", reached by the half that was not being watched.
	want := `STATE_LOCK="` + box.RunDir + "/" + box.RecordLockName("$APP_NAME") + `"`
	if !strings.Contains(scripts.AlpineScript, want) {
		t.Errorf("alpine.sh does not contain %q -- the shell and box/stopped.go would be "+
			"locking different files, which excludes nothing", want)
	}
}

// The record is REPLACED BY RENAME, never truncated and refilled.
//
// Asserted as source rather than run, because what it guards is a window
// between two processes and no single-process test can see one. It is pinned
// here rather than left to komizo#51, which introduced it, because THIS change
// is what makes the window common: before, that block ran when somebody added
// or reconfigured an app, and now it runs once per app every time anybody
// updates a box. A reader that catches the file empty gets a record with no
// APP_DIR, and box/paths.go's answer to one of those is "names no APP_DIR, so
// komizo does not know where %q is" -- for an app that is running fine, until
// something rewrites the record again.
func TestAnAppsRecordIsReplacedByRenameAndNeverTruncated(t *testing.T) {
	block := fromTo(t, scripts.AlpineScript, `STATE_TMP="$STATE_FILE.tmp.`, `# Released here rather than left`)
	if !strings.Contains(block, `mv -f "$STATE_TMP" "$STATE_FILE"`) {
		t.Error("the record is no longer moved over its own name -- a reader that catches " +
			"the file mid-write sees an app with no APP_DIR and believes it")
	}
	// Nothing may open the live record for writing. `cat > "$STATE_FILE"` and
	// friends empty it first, which is the window the rename exists to close.
	for _, bad := range []string{`> "$STATE_FILE"`, `>> "$STATE_FILE"`, `>"$STATE_FILE"`} {
		if strings.Contains(block, bad) {
			t.Errorf("something writes %s directly, so the record is empty for an instant "+
				"on every update of every app", bad)
		}
	}
}

// --- layer 3: what the script does with that environment -------------------

// A DELIBERATE STOP SURVIVES AN UPDATE, and this is the assertion the whole
// change turns on.
//
// The failure it guards against is the one komizo#57 describes from the other
// side. box/diagnose.go keys app_down off the STOPPED marker, so a marker that
// disappears starts paging for an app somebody stopped on purpose -- and a
// marker that is wrongly SET silences an app that is up. An update that cleared
// a stop would be a worse version of the bug being fixed here: the app comes
// back, nobody asked for it, and the report agrees with the containers so
// nothing looks wrong.
//
// RUN, NOT READ. The blocks below are lifted out of scripts/alpine.sh exactly
// as they ship -- including its own STATE_FILE assignment, so the test cannot
// invent the path the script reads -- and executed under /bin/sh with the
// environment appRefreshEnv actually produces. So it fails both when the shell
// stops carrying the marker and when the Go side starts passing something that
// makes it stop.
func TestAnUpdateDoesNotDisturbADeliberateStop(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	rec := appRecord{
		name: "blog",
		// Not komizo-blog and not /srv/blog: if the refresh stops carrying an
		// app's own settings, these are what change.
		user:   "deployer",
		config: "registry.internal:5000/blog-config",
		dir:    "/opt/blog",
	}
	const knownAs = "blog.example.com,www.blog.example.com"

	for _, tc := range []struct {
		name     string
		existing string
		wantStop map[string]string
	}{
		{
			name: "an app somebody stopped",
			existing: "APP_NAME=blog\nAPP_DIR=/opt/blog\nCI_USER=deployer\n" +
				"CONFIG_IMAGE=registry.internal:5000/blog-config\nKNOWN_AS=" + knownAs + "\n" +
				"STOPPED=1\nSTOPPED_BY=nico\nSTOPPED_AT=2026-08-05T12:00:00Z\n",
			wantStop: map[string]string{"STOPPED": "1", "STOPPED_BY": "nico", "STOPPED_AT": "2026-08-05T12:00:00Z"},
		},
		{
			// The mirror image, and just as important: an update must not invent
			// a stop either. A marker that appears from nowhere switches app_down
			// off for an app that is running and can fail.
			name: "an app that is running",
			existing: "APP_NAME=blog\nAPP_DIR=/opt/blog\nCI_USER=deployer\n" +
				"CONFIG_IMAGE=registry.internal:5000/blog-config\nKNOWN_AS=" + knownAs + "\n",
			wantStop: nil,
		},
		{
			// STOPPED=0 is what a start leaves behind. It means "not stopped", so
			// there is nothing to carry.
			name: "an app that was started again",
			existing: "APP_NAME=blog\nAPP_DIR=/opt/blog\nCI_USER=deployer\n" +
				"CONFIG_IMAGE=registry.internal:5000/blog-config\nKNOWN_AS=" + knownAs + "\n" +
				"STOPPED=0\nSTOPPED_BY=nico\nSTOPPED_AT=2026-08-05T12:00:00Z\n",
			wantStop: nil,
		},
		{
			// A record that picked up CRLF somewhere. The CR is invisible, and a
			// comparison against a literal "1" fails on "1\r" -- so without the
			// tr -d '\r' this drops a stop for a reason nobody can see in the file.
			name: "a record with CRLF line endings",
			existing: "APP_NAME=blog\r\nAPP_DIR=/opt/blog\r\nCI_USER=deployer\r\n" +
				"CONFIG_IMAGE=registry.internal:5000/blog-config\r\nKNOWN_AS=" + knownAs + "\r\n" +
				"STOPPED=1\r\nSTOPPED_BY=nico\r\nSTOPPED_AT=2026-08-05T12:00:00Z\r\n",
			wantStop: map[string]string{"STOPPED": "1", "STOPPED_BY": "nico", "STOPPED_AT": "2026-08-05T12:00:00Z"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := runUpdateStateBlocks(t, rec, tc.existing)

			// The app's own settings, unchanged by the update.
			for k, want := range map[string]string{
				"APP_NAME":     rec.name,
				"APP_DIR":      rec.dir,
				"CI_USER":      rec.user,
				"CONFIG_IMAGE": rec.config,
				"KNOWN_AS":     knownAs,
			} {
				if got[k] != want {
					t.Errorf("%s=%q after an update, want %q", k, got[k], want)
				}
			}
			// And the stop, in whichever direction this case expects.
			for _, k := range []string{"STOPPED", "STOPPED_BY", "STOPPED_AT"} {
				want, expected := tc.wantStop[k]
				switch {
				case expected && got[k] != want:
					t.Errorf("%s=%q after an update, want %q -- an update that loses a "+
						"deliberate stop makes the box page for an app somebody stopped "+
						"on purpose, with nothing saying why it changed its mind", k, got[k], want)
				case !expected && got[k] != "":
					t.Errorf("%s=%q appeared out of an update -- a stop marker on a running "+
						"app switches app_down off for it, indefinitely (komizo#57)", k, got[k])
				}
			}
		})
	}
}

// runUpdateStateBlocks writes an existing record, runs the parts of alpine.sh
// that decide what the record becomes, and reads the result back.
//
// The blocks are lifted verbatim. The ONE edit is STATE_DIR, which the script
// hard-codes at /var/lib/komizo/apps and this test has no business writing to;
// the replacement is asserted to have matched, so a script that renamed or
// reshaped that assignment fails here rather than silently testing nothing, and
// TestTheScriptsStateDirIsTheOneKomizoEnumerates pins the shipped value.
func runUpdateStateBlocks(t *testing.T, rec appRecord, existing string) map[string]string {
	t.Helper()
	got, old := runUpdateStateBlocksFull(t, rec, existing, nil)
	// AN UPDATE NEVER RETIRES AN ACCOUNT, and this is the assertion behind the
	// longest argument in refresh.go. alpine.sh reads the recorded CI_USER and,
	// when it differs from the one it was given, concludes the app was RENAMED
	// onto a new account -- and then deletes the previous one, its key file, its
	// doas rule and its sshd block. A refresh carries the recorded value
	// verbatim precisely so that never fires. Nothing ran that block until
	// Review 1 pointed out that the argument for it was untested; it is checked
	// on every case here rather than in one of its own, because the values that
	// could make it fire (a CR, a stray space) are per-record.
	if old != "" {
		t.Errorf("the update decided this app had been renamed off %q -- that path deletes "+
			"the account, its key file, its doas rule and its sshd block, from a routine "+
			"upgrade", old)
	}
	return got
}

// TestARenameIsStillDetectedWhenThereIsOne is the positive control for the
// assertion above: a check that never fires is indistinguishable from a check
// that cannot. This is the `komizo add --user` path, not an update.
func TestARenameIsStillDetectedWhenThereIsOne(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	rec := appRecord{name: "blog", user: "newacct", config: "ghcr.io/you/blog-config", dir: "/srv/blog"}
	_, old := runUpdateStateBlocksFull(t, rec,
		"APP_NAME=blog\nAPP_DIR=/srv/blog\nCI_USER=oldacct\nCONFIG_IMAGE=ghcr.io/you/blog-config\n", nil)
	if old != "oldacct" {
		t.Errorf("OLD_CI_USER=%q for a genuine rename, want \"oldacct\" -- if this block "+
			"never fires, the test above proves nothing", old)
	}
}

// A record beside this app's must not make this app look renamed, and a record
// still in use by another app must never be retired.
func TestAnAccountSharedWithAnotherAppIsNeverRetired(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	rec := appRecord{name: "blog", user: "newacct", config: "ghcr.io/you/blog-config", dir: "/srv/blog"}
	_, old := runUpdateStateBlocksFull(t, rec,
		"APP_NAME=blog\nAPP_DIR=/srv/blog\nCI_USER=shared\nCONFIG_IMAGE=ghcr.io/you/blog-config\n",
		map[string]string{
			"shop.env": "APP_NAME=shop\nAPP_DIR=/srv/shop\nCI_USER=shared\nCONFIG_IMAGE=ghcr.io/you/shop-config\n",
		})
	if old != "" {
		t.Errorf("OLD_CI_USER=%q for an account another app still deploys under -- retiring "+
			"it would break that app", old)
	}
}

// stubBin writes fake executables into a directory and returns it, along with
// the file each one appends its arguments to when called.
func stubBin(t *testing.T, names ...string) (dir, log string) {
	t.Helper()
	dir = t.TempDir()
	log = filepath.Join(dir, "calls.log")
	for _, n := range names {
		body := "#!/bin/sh\nprintf '%s %s\\n' " + shQuote(n) + ` "$*" >> ` + shQuote(log) + "\nexit 0\n"
		write(t, filepath.Join(dir, n), 0o755, body)
	}
	return dir, log
}

func stubCalls(t *testing.T, log string) string {
	t.Helper()
	b, err := os.ReadFile(log)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatal(err)
	}
	return string(b)
}

// THE DEFERRAL IS RUN, NOT READ.
//
// Review 1 on komizo#73: the only thing holding komizo#65 shut was a
// strings.Contains for the `if` line's text. Swapping the two branch bodies --
// reloading when the flag is set and printing when it is not -- restores the
// bug in full, 11 reloads for a 10-app update, and every assertion stays green
// because the line it matches is still there.
//
// So run the branch, with `rc-service` stubbed, and look at whether the daemon
// was actually told to reload.
func TestTheDeferredReloadIsTheBranchThatRunsNotTheLineThatMatches(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	block := fromTo(t, scripts.AlpineScript,
		`if [ "${DEFER_SSHD_RELOAD:-0}" = "1" ]; then`,
		"# Success: stop guarding the file")

	for _, tc := range []struct {
		name, defer_ string
		wantReload   bool
	}{
		{"deferred, as an update sets it", "1", false},
		{"not deferred, as a single add leaves it", "0", true},
		{"unset, which is a single add too", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binDir, log := stubBin(t, "rc-service")
			cmd := exec.Command("sh", "-s")
			cmd.Stdin = strings.NewReader("set -eu\n" + block)
			cmd.Env = []string{"PATH=" + binDir + ":" + os.Getenv("PATH")}
			if tc.defer_ != "" {
				cmd.Env = append(cmd.Env, "DEFER_SSHD_RELOAD="+tc.defer_)
			}
			var errBuf strings.Builder
			cmd.Stderr = &errBuf
			if err := cmd.Run(); err != nil {
				t.Fatalf("the reload branch failed: %v\n%s", err, errBuf.String())
			}
			got := strings.Contains(stubCalls(t, log), "rc-service sshd reload")
			if got != tc.wantReload {
				if tc.wantReload {
					t.Errorf("sshd was not reloaded with DEFER_SSHD_RELOAD=%q -- an app added on "+
						"its own would never pick up the rules it just wrote", tc.defer_)
				} else {
					t.Errorf("sshd was reloaded with DEFER_SSHD_RELOAD=%q -- komizo#65 is back, and "+
						"an update of N apps reloads N times", tc.defer_)
				}
			}
		})
	}
}

// And the script that does the one deferred reload, run rather than read: no
// test executed a line of it, so replacing its body with `true` was green.
func TestTheDeferredReloadScriptValidatesBeforeItReloads(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	for _, tc := range []struct {
		name       string
		sshdTestOK bool
		wantReload bool
	}{
		{"a config that validates is applied", true, true},
		{"a config that does not is left unapplied", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binDir, log := stubBin(t, "rc-service")
			// `sshd` is the stub whose exit status this test varies; it is the
			// only thing between a file on disk and the running daemon.
			rc := "0"
			if !tc.sshdTestOK {
				rc = "1"
			}
			write(t, filepath.Join(binDir, "sshd"), 0o755,
				"#!/bin/sh\nprintf 'sshd %s\\n' \"$*\" >> "+shQuote(log)+"\nexit "+rc+"\n")

			cmd := exec.Command("sh", "-s")
			cmd.Stdin = strings.NewReader(scripts.AlpineReloadSSHDScript)
			cmd.Env = []string{"PATH=" + binDir + ":" + os.Getenv("PATH")}
			var errBuf strings.Builder
			cmd.Stderr = &errBuf
			err := cmd.Run()
			calls := stubCalls(t, log)

			if !strings.Contains(calls, "sshd -t") {
				t.Errorf("the config was never validated before the reload decision:\n%s", calls)
			}
			if got := strings.Contains(calls, "rc-service sshd reload"); got != tc.wantReload {
				t.Errorf("reloaded=%v, want %v -- calls:\n%s", got, tc.wantReload, calls)
			}
			if tc.wantReload && err != nil {
				t.Errorf("a valid config was reported as a failure: %v\n%s", err, errBuf.String())
			}
			if !tc.wantReload {
				if err == nil {
					t.Error("an invalid sshd config exited 0, so an update would report success")
				}
				// The operator has to know which rules are in force, not just
				// that something failed.
				if !strings.Contains(errBuf.String(), "before this update") {
					t.Errorf("the failure does not say which rules are still in force:\n%s", errBuf.String())
				}
			}
		})
	}
}

// stateBlocksHead is the shipped setup script's account blocks -- the CI_USER
// validation, the settings, and the refusal of an account another app already
// holds -- with STATE_DIR repointed at a directory this test owns.
//
// Taken from the real script by its own line text, never retyped, and both
// extractions are checked: an anchor that stops matching is a fatal error here
// rather than a shorter script that quietly asserts less.
func stateBlocksHead(t *testing.T, stateDir string) string {
	t.Helper()
	src := scripts.AlpineScript
	settings := fromTo(t, src, `APP_DIR="${APP_DIR:-/srv/$APP_NAME}"`, `# If this app was previously set up`)
	const shipped = "STATE_DIR=/var/lib/komizo/apps"
	if strings.Count(settings, shipped) != 1 {
		t.Fatalf("could not repoint %q -- the assignment this test rewrites has moved or changed shape", shipped)
	}
	settings = strings.Replace(settings, shipped, "STATE_DIR="+stateDir, 1)

	head := strings.Join([]string{
		"set -eu",
		fromTo(t, src, `CI_USER="${CI_USER:-komizo-$APP_NAME}"`, `DEPLOY_BIN=`),
		settings,
	}, "\n")

	// The refusal must be in what was extracted. Without this, moving it a few
	// lines down would leave every test below running a script that cannot
	// refuse anything, and passing.
	if !strings.Contains(head, "already belongs to app") {
		t.Fatalf("the one-account-per-app refusal is not in the extracted blocks -- " +
			"it has moved outside them, and the tests that rely on it are asserting nothing")
	}
	return head
}

// runStateBlocks runs those blocks against records this test writes, and
// returns what the script said and whether it refused. Unlike its Full sibling
// a nonzero exit is a RESULT here, not a fatal error: refusing is the behaviour
// under test.
func runStateBlocks(t *testing.T, rec appRecord, existing string, others map[string]string, after ...func(dir string)) (string, error) {
	t.Helper()

	stateDir := t.TempDir()
	if existing != "" {
		if err := os.WriteFile(filepath.Join(stateDir, rec.name+".env"), []byte(existing), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range others {
		if err := os.WriteFile(filepath.Join(stateDir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	for _, fn := range after {
		fn(stateDir)
	}

	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(stateBlocksHead(t, stateDir))
	env := []string{"PATH=" + os.Getenv("PATH")}
	for k, v := range appRefreshEnv(rec) {
		env = append(env, k+"="+v)
	}
	cmd.Env = env
	var errBuf strings.Builder
	cmd.Stderr = &errBuf
	err := cmd.Run()
	return errBuf.String(), err
}

// A DEPLOY ACCOUNT BELONGS TO ONE APP, AND SAYS SO RATHER THAN SHARING BADLY.
//
// komizo#63. Everything alpine.sh writes for a deploy account is keyed by the
// account NAME and replaced whole on each run -- the doas block naming one
// app's two privileged scripts, the sshd Match block, and the key file. So a
// second app naming an account that already exists does not join it, it takes
// it: the first app's CI is left holding a key that opens nothing, and the
// second app's key now reaches an app it was never issued for.
func TestAnAppMayNotClaimAnotherAppsDeployAccount(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	rec := appRecord{name: "blog", user: "shared", config: "ghcr.io/you/blog-config", dir: "/srv/blog"}
	stderr, err := runStateBlocks(t, rec, "", map[string]string{
		"shop.env": "APP_NAME=shop\nAPP_DIR=/srv/shop\nCI_USER=shared\nCONFIG_IMAGE=ghcr.io/you/shop-config\n",
	})
	if err == nil {
		t.Fatal("an app claimed a deploy account another app already holds, and the setup continued")
	}
	// Naming the other app is the whole value of the message: without it the
	// operator is told a name is taken and not where to look.
	if !strings.Contains(stderr, "already belongs to app 'shop'") {
		t.Errorf("the refusal does not name the app that holds the account:\n%s", stderr)
	}
}

// The positive control for the refusal, on the line that makes it usable: an
// app re-run under the account IT already owns is an ordinary update, and
// refusing it would make `komizo update` fail on every app on the box.
func TestAnAppMayKeepItsOwnDeployAccountOnEveryRerun(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	rec := appRecord{name: "blog", user: "komizo-blog", config: "ghcr.io/you/blog-config", dir: "/srv/blog"}
	stderr, err := runStateBlocks(t, rec,
		"APP_NAME=blog\nAPP_DIR=/srv/blog\nCI_USER=komizo-blog\nCONFIG_IMAGE=ghcr.io/you/blog-config\n",
		map[string]string{
			"shop.env": "APP_NAME=shop\nAPP_DIR=/srv/shop\nCI_USER=komizo-shop\nCONFIG_IMAGE=ghcr.io/you/shop-config\n",
		})
	if err != nil {
		t.Fatalf("an app was refused its own deploy account on a re-run: %v\n%s", err, stderr)
	}
}

// A BOX THAT ALREADY SHARES AN ACCOUNT KEEPS WORKING, AND IS TOLD.
//
// Refusing here would break `komizo update` on every app of a box set up before
// this rule existed -- a working box broken by a rule about new ones. The
// sharing is still a real weakness, so it is said out loud on every run.
func TestSharingThatPredatesTheRuleWarnsRatherThanBreakingTheBox(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	rec := appRecord{name: "blog", user: "shared", config: "ghcr.io/you/blog-config", dir: "/srv/blog"}
	stderr, err := runStateBlocks(t, rec,
		"APP_NAME=blog\nAPP_DIR=/srv/blog\nCI_USER=shared\nCONFIG_IMAGE=ghcr.io/you/blog-config\n",
		map[string]string{
			"shop.env": "APP_NAME=shop\nAPP_DIR=/srv/shop\nCI_USER=shared\nCONFIG_IMAGE=ghcr.io/you/shop-config\n",
		})
	if err != nil {
		t.Fatalf("an update was refused on a box that already shared an account: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr, "share the deploy account 'shared'") {
		t.Errorf("the run said nothing about the sharing it just accepted:\n%s", stderr)
	}
}

// The same CR, on the other side of the comparison.
//
// Found by mutation rather than by review: dropping the strip from THIS app's
// record survived every test above. It is the milder direction -- the app is
// refused its own established account rather than another app's being deleted,
// so it fails closed -- but "fails closed" here means `komizo update` stops
// working on a box for a reason no message explains.
func TestACarriageReturnInThisAppsOwnRecordDoesNotCostItItsAccount(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	rec := appRecord{name: "blog", user: "shared", config: "ghcr.io/you/blog-config", dir: "/srv/blog"}
	stderr, err := runStateBlocks(t, rec,
		"APP_NAME=blog\r\nAPP_DIR=/srv/blog\r\nCI_USER=shared\r\nCONFIG_IMAGE=ghcr.io/you/blog-config\r\n",
		map[string]string{
			"shop.env": "APP_NAME=shop\nAPP_DIR=/srv/shop\nCI_USER=shared\nCONFIG_IMAGE=ghcr.io/you/shop-config\n",
		})
	if err != nil {
		t.Fatalf("a CR in this app's own record cost it the account it already holds: %v\n%s", err, stderr)
	}
}

// A record komizo cannot READ is not a record that says the account is free.
func TestARecordThatCannotBeReadIsNotTakenAsNoClash(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads every file, so an unreadable record cannot be staged here")
	}
	rec := appRecord{name: "blog", user: "komizo-blog", config: "ghcr.io/you/blog-config", dir: "/srv/blog"}
	stderr, err := runStateBlocks(t, rec, "", map[string]string{
		"shop.env": "APP_NAME=shop\nAPP_DIR=/srv/shop\nCI_USER=komizo-shop\nCONFIG_IMAGE=ghcr.io/you/shop-config\n",
	}, func(dir string) {
		if cerr := os.Chmod(filepath.Join(dir, "shop.env"), 0o000); cerr != nil {
			t.Fatal(cerr)
		}
	})
	if err == nil {
		t.Fatal("a record komizo could not read was treated as proof the account is free")
	}
	if !strings.Contains(stderr, "cannot read") {
		t.Errorf("the refusal does not say the record was unreadable:\n%s", stderr)
	}
}

// THE TWO READS OF A RECORD'S CI_USER MUST AGREE, BYTE FOR BYTE.
//
// Review 1 on komizo#73. The refusal stripped CR and this path did not, and the
// two decide opposite things from the same bytes: the refusal declines a clash,
// this one DELETES an account when it finds none. So one stray CR in another
// app's record -- edited on Windows, written by hand -- made this path conclude
// the old account was unused and `deluser` an account another app deploys under
// right now, taking its doas block and its sshd Match with it.
func TestACarriageReturnInAnotherAppsRecordCannotRetireItsLiveAccount(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	rec := appRecord{name: "blog", user: "newacct", config: "ghcr.io/you/blog-config", dir: "/srv/blog"}
	_, old := runUpdateStateBlocksFull(t, rec,
		"APP_NAME=blog\nAPP_DIR=/srv/blog\nCI_USER=oldacct\nCONFIG_IMAGE=ghcr.io/you/blog-config\n",
		map[string]string{
			// The only difference from the plain shared case: a CR.
			"shop.env": "APP_NAME=shop\r\nAPP_DIR=/srv/shop\r\nCI_USER=oldacct\r\nCONFIG_IMAGE=ghcr.io/you/shop-config\r\n",
		})
	if old != "" {
		t.Errorf("OLD_CI_USER=%q -- a CR in another app's record made this run retire an account "+
			"that app is deploying under", old)
	}
}

func runUpdateStateBlocksFull(t *testing.T, rec appRecord, existing string, others map[string]string) (map[string]string, string) {
	t.Helper()

	stateDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDir, rec.name+".env"), []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, body := range others {
		if err := os.WriteFile(filepath.Join(stateDir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// The test does not run as root, and the script chowns the record it writes.
	binDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(binDir, "chown"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	src := scripts.AlpineScript
	script := strings.Join([]string{
		stateBlocksHead(t, stateDir),
		// The block that decides whether this app has been renamed onto a new
		// deploy account, and therefore whether the previous one is deleted.
		fromTo(t, src, `OLD_CI_USER=""`, `# The deploy account's key list`),
		fromTo(t, src, `KNOWN_AS="${KNOWN_AS:-}"`, `log() {`),
		fromTo(t, src, `STOPPED_KEEP=""`, `# Released here rather than left`),
		// Reported on stdout so the caller can assert it. The record is the
		// other half of what these blocks decide; this is the half that acts on
		// accounts rather than on files.
		`printf 'komizo-test-old-ci-user=[%s]\n' "$OLD_CI_USER"`,
	}, "\n")

	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(script)
	// The environment the real update builds, and nothing else. An entry this
	// test added by hand would be an entry the box never sees.
	env := []string{"PATH=" + binDir + ":" + os.Getenv("PATH")}
	for k, v := range appRefreshEnv(rec) {
		env = append(env, k+"="+v)
	}
	cmd.Env = env
	var errBuf strings.Builder
	cmd.Stderr = &errBuf
	stdout, err := cmd.Output()
	if err != nil {
		t.Fatalf("the setup script's record blocks failed: %v\n%s\n--- script ---\n%s",
			err, errBuf.String(), script)
	}
	oldUser := ""
	for _, ln := range strings.Split(string(stdout), "\n") {
		if v, ok := strings.CutPrefix(ln, "komizo-test-old-ci-user=["); ok {
			oldUser = strings.TrimSuffix(v, "]")
		}
	}

	b, rerr := os.ReadFile(filepath.Join(stateDir, rec.name+".env"))
	if rerr != nil {
		t.Fatalf("the record is gone after an update: %v", rerr)
	}
	got := map[string]string{}
	for _, ln := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		if k, v, ok := strings.Cut(ln, "="); ok {
			if _, dup := got[k]; !dup { // first wins, as every other reader does
				got[k] = v
			}
		}
	}
	return got, oldUser
}

// enumerate runs the shipped app-listing shell against a directory and returns
// its raw output.
func enumerate(t *testing.T, dir string) string {
	t.Helper()
	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(appRecordsCmdFor(dir))
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("the enumeration failed: %v", err)
	}
	return string(out)
}

// A REMOVAL THAT DID NOT FINISH MUST NOT LEAVE AN APP AN UPDATE WILL PUT BACK.
//
// This is the consequence komizo#58 has for `komizo remove`, and Review 1 is
// where it was found. alpine-remove.sh deletes the record LAST, because
// everything above reads it, and its own header says a run that "died half way"
// is expected -- a dropped connection, a Ctrl-C, a slow `rm -rf`. That was
// survivable while nothing acted on a record by itself. It is not survivable
// now: `komizo update` reads a record as "this app should exist" and re-runs
// the setup script, which CREATES what is missing -- the deploy account, the
// directory, both privileged scripts, the doas rules and the sshd block. The
// removed app's whole deploy path would come back, on its original key, from a
// command billed as a routine upgrade, and nothing on the report would show it
// until that repo's next merge to main brought the app up on a box it had been
// removed from.
//
// The two scripts are run against ONE directory here on purpose. Asserting that
// the removal renames the file, and separately that the enumeration globs
// *.env, would be two true statements that could still disagree. What matters
// is the sentence they make together, so that is what is executed.
func TestAnInterruptedRemovalLeavesNothingAnUpdateWillReprovision(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	dir := t.TempDir()
	write(t, filepath.Join(dir, "blog.env"), 0o600,
		"APP_NAME=blog\nAPP_DIR=/opt/blog\nCI_USER=deployer\nCONFIG_IMAGE=ghcr.io/you/blog-config\n")
	// A second app, to prove the removal is scoped to its own record.
	write(t, filepath.Join(dir, "shop.env"), 0o600,
		"APP_NAME=shop\nAPP_DIR=/srv/shop\nCI_USER=komizo-shop\nCONFIG_IMAGE=ghcr.io/you/shop-config\n")

	// A removal interrupted immediately after step 0: the record has been made
	// inert and nothing else has happened yet.
	user, appDir := runRemovalPrelude(t, dir, "blog")
	if user != "deployer" || appDir != "/opt/blog" {
		t.Fatalf("the removal read the app as %q in %q -- removing by the defaults leaves "+
			"the real account and the real directory behind", user, appDir)
	}

	got := parseAppRecords(enumerate(t, dir))
	for _, r := range got {
		if r.name == "blog" {
			t.Fatalf("a half-finished removal still looks like an app to `komizo update`, "+
				"which would recreate its account, its directory, its doas rules and its "+
				"sshd block: %+v", r)
		}
	}
	if len(got) != 1 || got[0].name != "shop" {
		t.Errorf("the removal was not scoped to its own app: %+v", got)
	}

	// AND THE REMOVAL IS STILL SAFE TO REPEAT. If the renamed record could not
	// be read back, a second `komizo remove` after an interrupted first would
	// fall back to komizo-<app> and /srv/<app> -- silently leaving the real
	// account and the real directory of exactly the apps set up most
	// deliberately, which is the failure the "Read FIRST" block exists for.
	user2, appDir2 := runRemovalPrelude(t, dir, "blog")
	if user2 != "deployer" || appDir2 != "/opt/blog" {
		t.Errorf("a repeated removal read the app as %q in %q -- it lost the record it "+
			"renamed", user2, appDir2)
	}

	// The end of the run drops both names, so nothing is left in the directory.
	src := scripts.AlpineRemoveScript
	// Started at the comment above the line rather than at the line itself:
	// using the statement under test as its own marker turns a mutation of it
	// into "the block markers moved" rather than the sentence this test is
	// about. Killed either way; the message just pointed somewhere else.
	tail := fromTo(t, src, "# BOTH NAMES.", "\n\nlog ")
	runShell(t, strings.Join([]string{
		"set -eu",
		`STATE_FILE="` + filepath.Join(dir, "blog.env") + `"`,
		tail,
	}, "\n"), nil)
	for _, name := range []string{"blog.env", "blog.env.removing"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Errorf("%s survived the removal", name)
		}
	}
}

// A RENAME THAT CANNOT HAPPEN STOPS THE REMOVAL.
//
// Everything else in alpine-remove.sh is `|| true`, because everything else is
// cleanup and absence is fine. This one is not cleanup: if the record is left
// live and the removal carries on to delete the account and the directory, the
// window this whole step exists to close is silently open again -- and the way
// anyone would find out is a decommissioned app coming back on a later update.
// So it says so and refuses, which is the one place in this script where
// failing is the safe answer.
func TestARemovalThatCannotSetTheRecordAsideRefusesToGoOn(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores the directory mode this test relies on")
	}
	dir := t.TempDir()
	write(t, filepath.Join(dir, "blog.env"), 0o600,
		"APP_NAME=blog\nAPP_DIR=/opt/blog\nCI_USER=deployer\nCONFIG_IMAGE=ghcr.io/you/blog-config\n")
	// Read but not writable, so the record can be read and not renamed.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	src := scripts.AlpineRemoveScript
	head := fromTo(t, src, "STATE_DIR=/var/lib/komizo/apps", "# The one irreversible flag")
	head = strings.Replace(head, "STATE_DIR=/var/lib/komizo/apps", "STATE_DIR="+dir, 1)
	inert := fromTo(t, src, "# --- 1c. stop calling it an app", "# --- 2. the privileged commands")

	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(strings.Join([]string{
		"set -eu", "log() { :; }", "APP_NAME=blog", head, inert,
		`printf 'WENT-ON\n'`,
	}, "\n"))
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("the removal carried on after it could not set the record aside -- it would " +
			"delete the account and the directory and leave a record `komizo update` puts back")
	}
	if strings.Contains(string(out), "WENT-ON") {
		t.Error("the removal reached the steps after the guard")
	}
	if !strings.Contains(string(out), "aside") {
		t.Errorf("the refusal does not say what failed: %q", string(out))
	}
}

// runRemovalPrelude runs alpine-remove.sh from its record-reading block through
// the step that makes the record inert, and reports what it resolved the app's
// account and directory to.
func runRemovalPrelude(t *testing.T, stateDir, app string) (user, appDir string) {
	t.Helper()
	src := scripts.AlpineRemoveScript
	head := fromTo(t, src, "STATE_DIR=/var/lib/komizo/apps", "# The one irreversible flag")
	const shipped = "STATE_DIR=/var/lib/komizo/apps"
	if strings.Count(head, shipped) != 1 {
		t.Fatalf("could not repoint %q in the removal script", shipped)
	}
	head = strings.Replace(head, shipped, "STATE_DIR="+stateDir, 1)
	inert := fromTo(t, src, "# --- 1c. stop calling it an app", "# --- 2. the privileged commands")

	out := runShell(t, strings.Join([]string{
		"set -eu",
		// log() is defined further down the script than the block lifted here,
		// and it is prose rather than behaviour. Same stub doas_rollback_test.go
		// uses for the same reason.
		"log() { :; }",
		"APP_NAME=" + app,
		head,
		inert,
		`printf 'user=[%s] dir=[%s]\n' "$CI_USER" "$APP_DIR"`,
	}, "\n"), nil)
	for _, ln := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(ln, "user=["); ok {
			user, _, _ = strings.Cut(v, "]")
			if _, rest, ok := strings.Cut(v, "dir=["); ok {
				appDir, _, _ = strings.Cut(rest, "]")
			}
		}
	}
	return user, appDir
}

func runShell(t *testing.T, script string, env []string) string {
	t.Helper()
	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(script)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, env...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("the lifted shell failed: %v\n--- script ---\n%s", err, script)
	}
	return string(out)
}

// THE GUARDS ON /etc SURVIVE THE SIGNAL THAT ACTUALLY ARRIVES, AND STOP.
//
// alpine.sh backs up /etc/doas.conf and /etc/ssh/sshd_config and restores them
// from a trap. An EXIT trap does not run on HUP, TERM or PIPE, and those are
// exactly how this script dies in practice: `komizo update` is long, and
// interrupting it kills the local ssh, after which the far end takes SIGHUP
// from sshd or SIGPIPE on its next write to a closed stdout.
//
// What is left behind in each window is specific. In the doas one, this app's
// rule block has been removed and not yet re-appended, so its deploys get a
// refusal. In the sshd one, its Match block is gone -- which takes the
// root-owned AuthorizedKeysFile and every restriction in it -- and sshd has not
// been reloaded, so it bites at the next reboot instead.
//
// RUN, WITH A REAL SIGNAL, because listing the signals is not the property.
// Review 1 asked for the signals and Review 2 found that adding them was not
// enough: a handler for a non-EXIT signal RETURNS to where it was interrupted,
// so the first version restored the file and then carried on -- re-appending
// the block, finishing the run on a box whose operator had cancelled it, and
// walking into the sshd window to die there instead, where nothing was catching
// SIGPIPE at all. A string match on the trap line cannot tell those two apart.
// This sends the signal and asserts both halves: the file goes back, and the
// script stops.
//
// There is no race to lose. The lifted section is followed by a marker file and
// a sleep, so the signal is delivered at a point the test chose.
func TestTheGuardsOnEtcRestoreAndStopOnEverySignal(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	const original = "# untouched\n"

	// BOTH SCRIPTS THAT EDIT /etc, not just the one this test was written for.
	//
	// Review 1 on komizo#73: this ran alpine.sh's two guards only, so gutting
	// alpine-remove.sh's restore_doas() to `{ :; }` left the entire suite green.
	// The regex test below did cover the removal script -- and that is the trap
	// worth naming: it covers a DIFFERENT AXIS. It reads which signals a trap
	// line is installed for; it cannot see whether the handler restores anything
	// or stops. Extending it felt like closing this gap and was not.
	for _, guard := range []struct {
		name, src, target, pre, lift, until string
	}{
		{
			name:   "alpine.sh/doas.conf",
			src:    scripts.AlpineScript,
			target: "doas.conf",
			lift:   `doas_bak="/etc/doas.conf.komizo.bak.$$"`,
			until:  "# Delimited block,",
		},
		{
			name:   "alpine.sh/sshd_config",
			src:    scripts.AlpineScript,
			target: "sshd_config",
			lift:   "conf=/etc/ssh/sshd_config",
			until:  "# Retire the previous account's Match block",
		},
		{
			name:   "alpine-remove.sh/doas.conf",
			src:    scripts.AlpineRemoveScript,
			target: "doas.conf",
			lift:   "doas_bak=/etc/doas.conf.komizo.bak",
			until:  `sed -i -E "/^# $PROJECT_MARKER: $CI_USER BEGIN`,
		},
		{
			name:   "alpine-remove.sh/sshd_config",
			src:    scripts.AlpineRemoveScript,
			target: "sshd_config",
			// This guard opens inside `if [ -f "$conf" ]`, so the lift starts at
			// the backup -- as the others do -- and $conf is supplied here. The
			// line is the script's own, and goes through the same rewrite.
			pre:   "conf=/etc/ssh/sshd_config",
			lift:  `conf_bak="$conf.komizo.bak"`,
			until: "sed -i -E \\\n",
		},
	} {
		src := guard.src
		for _, sig := range []syscall.Signal{syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT, syscall.SIGPIPE} {
			t.Run(guard.name+"/"+sig.String(), func(t *testing.T) {
				dir := t.TempDir()
				target := filepath.Join(dir, guard.target)
				write(t, target, 0o600, original)

				// The backup-and-guard block exactly as it ships, pointed at a
				// file this test owns. Everything after it stands in for the
				// edit the guard exists to protect: the file is left in a state
				// it must not be found in, and then the signal arrives.
				block := guard.pre + "\n" + fromTo(t, src, guard.lift, guard.until)
				block = strings.NewReplacer(
					"/etc/doas.conf", target,
					"/etc/ssh/sshd_config", target,
				).Replace(block)

				script := strings.Join([]string{
					"set -eu",
					block,
					`printf 'mid-edit\n' > ` + shQuote(target),
					`printf 'ready\n' > ` + shQuote(filepath.Join(dir, "ready")),
					// A LOOP OF SHORT SUCCESSFUL COMMANDS, which is what the
					// real script is doing when the signal lands -- a sed, a
					// cat, a chmod, each returning 0.
					//
					// Not `sleep & wait`: `wait` returns 128+signal, so `set -e`
					// would end the run by itself and a handler that resumed
					// would be indistinguishable from one that exits. That is
					// the version of this test that let Review 2's blocker
					// survive. A foreground command defers the handler until it
					// finishes and then returns 0, so `set -e` has nothing to
					// act on and the script carries on -- exactly as it would
					// after the `sed -i` that opens the window.
					"i=0",
					`while [ "$i" -lt 200 ]; do sleep 0.05; i=$((i+1)); done`,
					// Reached only if the handler resumed instead of exiting.
					`printf 'RAN-ON\n' >> ` + shQuote(target),
				}, "\n")

				cmd := exec.Command("sh", "-s")
				cmd.Stdin = strings.NewReader(script)
				cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				deadline := time.Now().Add(10 * time.Second)
				for {
					if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
						break
					}
					if time.Now().After(deadline) {
						_ = cmd.Process.Kill()
						t.Fatal("the lifted guard never reached the point the signal is sent at")
					}
					time.Sleep(5 * time.Millisecond)
				}
				if err := cmd.Process.Signal(sig); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- cmd.Wait() }()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					_ = cmd.Process.Kill()
					t.Fatalf("%s did not stop the run -- a handler that returns to where it was "+
						"interrupted carries on provisioning a box whose operator has cancelled "+
						"the command, and dies in the next window instead", sig)
				}

				got, err := os.ReadFile(target)
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != original {
					t.Errorf("%s was left as %q after %s, want it restored to %q",
						guard.target, string(got), sig, original)
				}
				if strings.Contains(string(got), "RAN-ON") {
					t.Errorf("the run continued past %s", sig)
				}
				// And no backup left in /etc for a later, unrelated failure to
				// restore from.
				strays, err := filepath.Glob(target + ".komizo.bak*")
				if err != nil {
					t.Fatal(err)
				}
				if len(strays) > 0 {
					t.Errorf("backups left behind after %s: %v", sig, strays)
				}
			})
		}
	}
}

// WHICH SIGNALS the guards are installed for, pinned as text.
//
// The test above runs a real signal and is the one that matters -- it is what
// caught a handler that restored the file and then carried on. What it cannot
// catch is a signal MISSING from the list, and the reason is worth writing down
// rather than discovering again: the /bin/sh on a developer machine is usually
// bash, and bash runs its EXIT trap when it dies of a fatal signal. So a
// dropped HUP still ends with the file restored here, and the subtest passes
// against a script that would leave /etc mid-edit on the box. Alpine's busybox
// ash does not do that, which is exactly why the difference has to be asserted
// somewhere the host shell cannot paper over.
//
// PIPE is in the list because it is the likeliest of the four, not the most
// exotic: killing the local ssh does not always deliver a signal to the far
// end, and what does is this script's next log line written to a stdout with
// nothing on the other end.
func TestTheGuardsCatchEverySignalAnInterruptedUpdateSends(t *testing.T) {
	// STRUCTURAL, NOT A LIST OF LINES. This asserted four exact strings, which
	// review showed is two separate weaknesses: reverting all four to `EXIT`
	// alone is green if the strings are edited to match, and a FIFTH trap
	// elsewhere in the file is invisible to it. There was one -- the staging
	// cleanup, `EXIT INT TERM`, catching but not stopping and missing HUP and
	// PIPE entirely, which are how a dropped ssh connection actually arrives.
	//
	// So every trap in the script is found and judged, and a new one cannot be
	// added without meeting the rule.
	nonEXIT := regexp.MustCompile(`(?m)^\s*trap\s+(?:'[^']*'|"[^"]*"|[A-Za-z_][A-Za-z0-9_]*)\s+((?:INT|TERM|HUP|PIPE|QUIT)(?:\s+(?:INT|TERM|HUP|PIPE|QUIT))*)\s*$`)
	all := regexp.MustCompile(`(?m)^\s*trap\s+(?:'([^']*)'|"([^"]*)"|([A-Za-z_][A-Za-z0-9_]*))\s+([A-Z ]+)$`)

	// EVERY SCRIPT KOMIZO WRITES ONTO A BOX, not one of them.
	//
	// This read alpine.sh alone, and komizo#64 was the cost: alpine-remove.sh
	// guarded /etc/doas.conf and /etc/ssh/sshd_config with `EXIT` only -- the
	// same defect, in a file nothing was looking at, found by reading rather
	// than by any check. A rule applied to one of two scripts is not a rule.
	for _, script := range []struct {
		name string
		src  string
		min  int
	}{
		{"alpine.sh", scripts.AlpineScript, 6},
		{"alpine-remove.sh", scripts.AlpineRemoveScript, 4},
	} {
		checkTraps(t, script.name, script.src, script.min, all, nonEXIT)
	}
}

// checkTraps judges every trap in one script.
//
// The rule, in both halves: a handler for a SIGNAL must exit, because POSIX sh
// resumes at the interruption point when one returns -- so a trap that only
// tidies carries on doing the work the operator just cancelled. And it must
// cover the signals that actually arrive: a dropped ssh connection is HUP, or
// PIPE at the next write to a dead stdout, and EXIT alone is raised by neither.
func checkTraps(t *testing.T, name, src string, min int, all, nonEXIT *regexp.Regexp) {
	t.Helper()
	found := all.FindAllStringSubmatch(src, -1)
	if len(found) < min {
		t.Fatalf("found %d trap installations in %s, expected at least %d "+
			"-- if a guard was removed say so deliberately; if this regexp stopped "+
			"matching, it is no longer checking anything", len(found), name, min)
	}

	for _, m := range found {
		body, signals := m[1]+m[2]+m[3], strings.Fields(m[4])
		if len(signals) == 1 && signals[0] == "EXIT" {
			continue // the paired EXIT half, which must NOT exit
		}
		// A handler for a signal must STOP. POSIX sh resumes at the
		// interruption point when a handler returns, so a trap that only tidies
		// carries on doing the work the operator just cancelled -- measured
		// under busybox ash: TERM gave "CLEANED" then "RESUMED-AND-FINISHED".
		if !strings.Contains(body, "exit ") {
			t.Errorf("in %s, this trap catches %v and does not exit:\n  %s\n"+
				"POSIX sh resumes where it was interrupted, so the script carries on "+
				"doing what the operator cancelled", name, signals, body)
		}
		// And it must cover the signals that actually arrive. A dropped ssh
		// connection is HUP, or PIPE on the next write to a dead stdout --
		// under busybox ash neither ran the handler at all when absent.
		for _, need := range []string{"INT", "TERM", "HUP", "PIPE"} {
			if !slices.Contains(signals, need) {
				t.Errorf("in %s, this trap does not catch %s:\n  %s\n  has %v", name, need, body, signals)
			}
		}
	}

	// And the paired form is real: every signal trap has an EXIT sibling, so
	// the ordinary path cleans up too.
	if got := len(nonEXIT.FindAllString(src, -1)); got < min/2 {
		t.Errorf("%s has %d signal traps, want at least %d -- every EXIT guard needs a signal sibling",
			name, got, min/2)
	}
}

// And the clears are as wide as the traps.
//
// A signal handler left installed does not merely fail to clean up: it EXITS,
// so it would abandon a later step of the script while restoring a backup that
// no longer exists. Asserted as source because it is about which handlers are
// removed, and the steps after them are the ones this file cannot run.
func TestTheGuardsAreClearedAsWidelyAsTheyAreSet(t *testing.T) {
	if n := strings.Count(scripts.AlpineScript, "trap - EXIT INT TERM HUP PIPE"); n != 4 {
		t.Errorf("alpine.sh clears the /etc guards %d times with the full signal set, want 4 "+
			"-- a narrower clear leaves a handler that would exit a later step", n)
	}
	if strings.Contains(scripts.AlpineScript, "trap - EXIT\n") {
		t.Error("alpine.sh clears a guard with `trap - EXIT` alone, leaving the signal handler installed")
	}
	// Both backups are per-run. Two runs of this script at once is ordinary now
	// -- an update while somebody adds an app, an update while CI adds one --
	// and a shared backup name means the first to finish deletes it, so the
	// second's restore has nothing to move and aborts under set -e with the
	// file left in its edited state.
	for _, want := range []string{
		`doas_bak="/etc/doas.conf.komizo.bak.$$"`,
		`conf_bak="$conf.komizo.bak.$$"`,
	} {
		if !strings.Contains(scripts.AlpineScript, want) {
			t.Errorf("alpine.sh shares a backup name between concurrent runs; expected:\n  %s", want)
		}
	}
}

// A box that cannot say what is on it says WHY.
//
// quiet() suppresses stderr, which is right for a probe whose failure is an
// expected answer and wrong for this one: if this step fails, no app on the box
// is refreshed, and "exit status 1" leaves an operator with a command that
// silently did nothing and nothing to act on.
func TestAFailedListingCarriesTheBoxsOwnWords(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	_, err := exec.Command("sh", "-c", "echo 'permission denied' >&2; exit 1").Output()
	if err == nil {
		t.Fatal("expected the stub to fail")
	}
	got := appListError(err).Error()
	if !strings.Contains(got, "permission denied") {
		t.Errorf("the failure lost what the box said: %q", got)
	}
	if !strings.Contains(got, "could not read the list of apps") {
		t.Errorf("the failure does not say what it was doing: %q", got)
	}
}

// fromTo lifts a run of lines out of a script, start line included, end marker
// excluded. between() drops the line it matched, which is wrong for an
// assignment that is itself the thing being tested.
func fromTo(t *testing.T, src, start, end string) string {
	t.Helper()
	i := strings.Index(src, start)
	if i < 0 {
		t.Fatalf("could not find %q in the setup script -- the block markers moved", start)
	}
	rest := src[i:]
	j := strings.Index(rest, end)
	if j < 0 {
		t.Fatalf("could not find %q after %q", end, start)
	}
	return rest[:j]
}
