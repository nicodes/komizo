package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A DEPLOY MUST NOT START AN APP SOMEBODY STOPPED -- komizo#54.
//
// The generated deploy script ran `docker compose up -d` with nothing in front
// of it, so a CI deploy brought an app back up that a person had deliberately
// taken down. Once `komizo stop` writes a durable STOPPED marker (komizo#48),
// the same line leaves the app RUNNING with the marker still set, and
// box/diagnose.go keys app_down on that marker -- so the app never pages again,
// silently, for as long as nobody thinks to start an app that is already up.
//
// The thing under test is shell that needs apk, docker and a box, none of which
// exist in CI. So the DECISION is tested rather than the deploy: the block that
// chooses between starting and not starting is lifted out of the script as it
// ships and run under /bin/sh with `docker` replaced by a function that records
// what it was asked to do. That is the same source a box runs, executed, rather
// than a substring somebody hopes still means what it used to -- and it is the
// same trade scripts_test.go's other checks make, one step further.

// deployBody is the generated per-app deploy script, as it is written to the
// box -- the contents of the quoted heredoc inside alpine.sh.
//
// Placeholders are still __LIKE_THIS__ here, because alpine.sh substitutes them
// with sed ON the box; TestNoScriptShipsAnUnsubstitutedPlaceholder exempts the
// alpine scripts for that reason. Nothing below depends on a placeholder's
// value, and alpine.sh refuses to install a script with one left in it.
func deployBody(t *testing.T) string {
	t.Helper()
	const open = "<<'KOMIZO_DEPLOY_EOF'\n"
	const close = "\nKOMIZO_DEPLOY_EOF\n"
	i := strings.Index(AlpineScript, open)
	if i < 0 {
		t.Fatal("alpine.sh no longer writes the deploy script from a KOMIZO_DEPLOY_EOF heredoc -- has it moved?")
	}
	rest := AlpineScript[i+len(open):]
	j := strings.Index(rest, close)
	if j < 0 {
		t.Fatal("the KOMIZO_DEPLOY_EOF heredoc is never closed")
	}
	return rest[:j]
}

// startDecision is the block that decides whether containers come up: the read
// of the stop marker, and the branch it guards.
//
// Located by the read rather than by line numbers, and it fatals when the read
// is not there -- which is what this test does on the code as it was before
// komizo#54, and the message says so rather than leaving a maintainer to work
// out why an extraction failed.
func startDecision(t *testing.T, body string) string {
	t.Helper()
	lines := strings.Split(body, "\n")
	start := -1
	for i, ln := range lines {
		if strings.HasPrefix(ln, "stopped=") {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatal("the deploy script never reads the stop marker, so a CI deploy starts an app somebody stopped on purpose (komizo#54)")
	}
	for i := start; i < len(lines); i++ {
		if lines[i] == "fi" {
			return strings.Join(lines[start:i+1], "\n")
		}
	}
	t.Fatal("the start decision has no closing fi at column zero")
	return ""
}

// runDecision runs the block against a state file, and reports what it printed
// and every docker command it would have run.
//
// `docker` is a shell function rather than a stub on PATH so the block runs
// exactly as written -- a stub binary would also test that PATH lookup works,
// which is not in question, and would need a temp dir on PATH for a test about
// a marker file.
func runDecision(t *testing.T, block, record string) (out string, dockerRan []string) {
	t.Helper()
	dir := t.TempDir()
	state := filepath.Join(dir, "web.env")
	if record != "" {
		if err := os.WriteFile(state, []byte(record), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	log := filepath.Join(dir, "docker.log")

	// The values the block reads that are set further up the real script. Only
	// these: anything else it touched would be a dependency this test would
	// rather find out about now than on a box.
	prelude := "set -eu\n" +
		"APP_NAME=web\n" +
		"version=abc1234\n" +
		"ref=registry.example/web-config:abc1234\n" +
		"STATE_FILE=" + state + "\n" +
		"docker() { printf '%s\\n' \"docker $*\" >> " + log + "; }\n"

	cmd := exec.Command("sh", "-c", prelude+block)
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the start decision failed to run: %v\n%s", err, b)
	}
	ran, _ := os.ReadFile(log)
	for _, ln := range strings.Split(strings.TrimSpace(string(ran)), "\n") {
		if ln != "" {
			dockerRan = append(dockerRan, ln)
		}
	}
	return string(b), dockerRan
}

func TestADeployDoesNotStartAnAppThatWasStopped(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	block := startDecision(t, deployBody(t))

	// A record with everything else in it, so what decides is the marker and
	// not the shape of the file.
	const base = "# Written by komizo.\nAPP_NAME=web\nAPP_DIR=/srv/web\nCI_USER=komizo-web\nCONFIG_IMAGE=registry.example/web-config\nKNOWN_AS=web\n"

	for _, tc := range []struct {
		name   string
		record string
		start  bool
	}{
		// The bug, and the fix.
		{"stopped on purpose", base + "STOPPED=1\nSTOPPED_BY=cli\nSTOPPED_AT=2026-01-01T00:00:00Z\n", false},
		{"running", base, true},

		// A CR is invisible in an editor and this is a comparison against a
		// literal. A record that picked up CRLF -- edited on another machine,
		// restored from a backup taken on one -- reads back as "1\r", which is
		// not "1", and the app gets started with the marker still set. Same
		// argument the `komizo add` block makes about carrying the marker
		// across a re-run.
		{"stopped, in a record with CRLF line endings", strings.ReplaceAll(base+"STOPPED=1\n", "\n", "\r\n"), false},

		// First-wins, which is what every other reader of these records does:
		// readState in paths.go, the cross-app scan in this same script, and
		// box/stopped.go's rewrite. A reader here that took the LAST line would
		// disagree with all of them about the same file, and the disagreement
		// would show up as an app that starts itself.
		{"stopped, with a later line contradicting it", base + "STOPPED=1\nSTOPPED=0\n", false},

		// Anchored at the start of the line. A key that merely ends in STOPPED
		// is a different key, and matching it would leave an app that cannot be
		// deployed to for a reason nobody could find.
		{"a record with a similarly named key", base + "LAST_STOPPED=1\n", true},

		// Hand-written, and it says the app is not stopped. ClearStopped
		// removes the key rather than writing a 0, so this only arrives from a
		// person -- and refusing to start on it would read their "no" as a yes.
		{"a hand-written STOPPED=0", base + "STOPPED=0\n", true},

		// No record at all. Deploys carry on, deliberately: an app with no
		// record does not appear in the report either, so app_down cannot fire
		// for it and there is no page to protect. Refusing here would instead
		// break every deploy on a box whose state directory went missing, which
		// is a failure with a much wider blast radius than the one it prevents.
		{"no record", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, ran := runDecision(t, block, tc.record)

			started := false
			for _, c := range ran {
				if strings.HasPrefix(c, "docker compose up") {
					started = true
				}
			}
			if started != tc.start {
				t.Errorf("started = %v, want %v\ndocker: %v\noutput:\n%s", started, tc.start, ran, out)
			}

			// It has to SAY which it did. A deploy that deliberately leaves an
			// app down and a deploy that failed are both green in a CI log
			// otherwise, and the difference only shows up in a `compose ps`
			// somebody has to already suspect something to go and read.
			want := "started=no"
			if tc.start {
				want = "started=yes"
			}
			if !strings.Contains(out, "deploy: "+want) {
				t.Errorf("output does not say %q:\n%s", want, out)
			}

			// The start is `up -d --remove-orphans`, not `compose start`. A
			// stopped app whose image has since been deployed would come back
			// on the OLD one under `compose start`, which is the same class of
			// silent wrong version this whole change is about -- see
			// composeArgs in cmd/komizo-box/app.go, which makes the argument
			// for the other path that starts an app.
			if tc.start && (len(ran) != 1 || ran[0] != "docker compose up -d --remove-orphans") {
				t.Errorf("started with %v, want exactly `docker compose up -d --remove-orphans`", ran)
			}
			// Nothing at all is run when the app stays down. Not even a
			// `compose start` of one service: the app is down on purpose.
			if !tc.start && len(ran) != 0 {
				t.Errorf("an app that was left stopped still ran %v", ran)
			}
		})
	}
}

// The pull and the version commit happen ANYWAY, and that is the whole point of
// pulling without starting.
//
// A deploy to a stopped app is meant to leave the box able to bring up the new
// version later: `komizo start` runs `docker compose up -d`, which resolves
// images from ${APP_VERSION} in the app's .env and finds the layers already on
// disk. Move either of those below the start decision -- or inside its else --
// and a start after a deploy silently brings up the previous version, or tries
// to pull a private image with no registry credentials, because the credentials
// only exist for the length of a deploy.
//
// Asserted by ORDER in the source, which is what the shell will do with it. The
// test above cannot see this: it runs the decision block alone, so anything
// moved into it would still pass there.
func TestAStoppedAppStillGetsThePullAndTheVersion(t *testing.T) {
	body := deployBody(t)

	decision := strings.Index(body, "\nstopped=")
	if decision < 0 {
		t.Fatal("the deploy script never reads the stop marker (komizo#54)")
	}
	for _, step := range []struct{ what, line string }{
		{"the image pull", "if ! docker compose pull; then"},
		{"the APP_VERSION commit", "printf 'APP_VERSION=%s\\n' \"$version\" >> .env"},
	} {
		i := strings.Index(body, step.line)
		if i < 0 {
			t.Fatalf("could not find %s (%q) -- has the deploy script been reshaped?", step.what, step.line)
		}
		if i > decision {
			t.Errorf("%s happens after the start decision, so a deploy to a stopped app does not leave the new version ready to come up", step.what)
		}
	}

	// ONE place containers come up, AND IT IS INSIDE THE GUARD. Every failure
	// path in this script reverts files and exits saying "nothing restarted";
	// the day one of them grows a `docker compose up` to put the previous
	// version back, it becomes a second way to start an app somebody stopped --
	// and the worse one to notice, because it only runs when something else has
	// already gone wrong.
	//
	// Both halves are needed, and the second is the one the test above cannot
	// make. That test lifts the guarded block out and runs it, so a `docker
	// compose up` moved one line PAST the closing `fi` disappears from what it
	// executes -- an unconditional start that the run would see as no start at
	// all. Here it is a position in the file, which cannot be moved out of the
	// guard without being seen.
	//
	// Comment lines are skipped, and several of them do say `docker compose up`
	// -- this file argues about that command at length, and a check that
	// counted the arguments as well as the code would be a check nobody could
	// leave a note beside.
	end := strings.Index(body[decision:], "\nfi\n")
	if end < 0 {
		t.Fatal("the start decision has no closing fi at column zero")
	}
	end += decision
	ups := 0
	for _, ln := range strings.Split(body, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "#") || !strings.Contains(ln, "docker compose up") {
			continue
		}
		ups++
		at := strings.Index(body, ln)
		if at < decision || at > end {
			t.Errorf("`%s` starts containers from outside the stop check, so a deploy would start an app somebody stopped", strings.TrimSpace(ln))
		}
	}
	if ups != 1 {
		t.Errorf("the deploy script has %d ways to start containers; exactly one may exist, and it is the one that reads the stop marker", ups)
	}
}
