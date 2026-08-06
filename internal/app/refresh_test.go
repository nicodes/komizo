package app

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

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
		}
	}
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
	if len(r.envs) != 2 {
		t.Fatalf("ran %d times for 2 apps -- an app that is not re-run is an app "+
			"still carrying the old deploy script", len(r.envs))
	}
	for i, want := range recs {
		if r.scripts[i] != scripts.AlpineScript {
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
				if len(r.envs) != 1 || r.envs[0]["APP_NAME"] != good.name {
					t.Errorf("ran for %d app(s); the good one must still be refreshed and the "+
						"bad one must not be touched", len(r.envs))
				}
				// A MISSING value must not be reported as a bad FLAG. The
				// validators are written for `komizo add`, where there is a
				// --user or a --config to be wrong about; an update passes
				// neither, so falling through to one of them tells the operator
				// to go and fix something they never typed while the record that
				// is actually incomplete goes unmentioned. Only checked for the
				// incomplete records: a malformed value is quoted back by the
				// validator that knows what is wrong with it, which is worth the
				// borrowed phrasing.
				if !tc.missing {
					return
				}
				said := strings.Join(p.lines, "\n")
				for _, flag := range []string{"--user", "--config", "--app-dir", "--app "} {
					if strings.Contains(said, flag) {
						t.Errorf("the skip blames %s, which nothing passed to `komizo update`:\n%s",
							flag, said)
					}
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
	if len(r.envs) != 3 {
		t.Errorf("ran %d times; a failure on one app must not leave the ones after it "+
			"on the old deploy script", len(r.envs))
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

	stateDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDir, rec.name+".env"), []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	// The test does not run as root, and the script chowns the record it writes.
	binDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(binDir, "chown"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	src := scripts.AlpineScript
	settings := fromTo(t, src, `APP_DIR="${APP_DIR:-/srv/$APP_NAME}"`, `# If this app was previously set up`)
	const shipped = "STATE_DIR=/var/lib/komizo/apps"
	if strings.Count(settings, shipped) != 1 {
		t.Fatalf("could not repoint %q -- the assignment this test rewrites has moved or changed shape", shipped)
	}
	settings = strings.Replace(settings, shipped, "STATE_DIR="+stateDir, 1)

	script := strings.Join([]string{
		"set -eu",
		fromTo(t, src, `CI_USER="${CI_USER:-komizo-$APP_NAME}"`, `DEPLOY_BIN=`),
		settings,
		fromTo(t, src, `KNOWN_AS="${KNOWN_AS:-}"`, `log() {`),
		fromTo(t, src, `STOPPED_KEEP=""`, `# Released here rather than left`),
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
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the setup script's record blocks failed: %v\n%s\n--- script ---\n%s", err, out, script)
	}

	b, err := os.ReadFile(filepath.Join(stateDir, rec.name+".env"))
	if err != nil {
		t.Fatalf("the record is gone after an update: %v", err)
	}
	got := map[string]string{}
	for _, ln := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		if k, v, ok := strings.Cut(ln, "="); ok {
			if _, dup := got[k]; !dup { // first wins, as every other reader does
				got[k] = v
			}
		}
	}
	return got
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
