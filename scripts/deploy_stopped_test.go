package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
// Nesting is counted rather than stopping at the first `fi`, because the read
// itself is guarded by one. Stopping early truncated the block to the read alone
// and every case then reported "nothing started", which is the answer four of
// them wanted -- a green suite for a block the test was no longer running.
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
	guard := -1
	for i := start; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], `if [ "$stopped"`) {
			guard = i
			break
		}
	}
	if guard < 0 {
		t.Fatal("the deploy script reads the stop marker and then never branches on it (komizo#54)")
	}
	// From the GUARD, not from the read -- the read has an `if` of its own now,
	// and starting the count at the read would close the block on the read's own
	// `fi`.
	return strings.Join(lines[start:closingFi(t, lines, guard, "the start decision")+1], "\n")
}

// closingFi is the index of the `fi` that ends the column-zero `if` at open.
//
// Column zero only. Everything nested inside these blocks is indented with tabs,
// so this counts the structure the decision is made of and not the structure
// inside it.
//
// On the shape of the script TODAY the nesting count is not what makes this
// correct -- the callers both open on a column-zero `if` whose body is entirely
// indented, so stopping at the first column-zero `fi` would find the same line,
// and reverting the count leaves the suite green. Said plainly because the
// earlier version of this comment credited the count with a fix that was
// actually made by moving startDecision's call site from the marker READ to the
// GUARD. That was the bug: extraction began at the read, the read had acquired
// an `if [ -f ]` of its own, and the block ended at the read's own `fi` -- the
// branch, the `docker compose up` and every printed line fell outside it, so
// every case observed "nothing was started", which is the answer four of the
// seven wanted. A green suite over a block that no longer contained the
// decision it was named for.
//
// The count stays because it makes the helper correct for a caller that opens
// on an `if` containing another column-zero `if` -- which is a shape this script
// does not have and has no rule against -- and because a helper that is only
// right for the two call sites it happens to have is a trap for the third.
func closingFi(t *testing.T, lines []string, open int, what string) int {
	t.Helper()
	depth := 0
	for i := open; i < len(lines); i++ {
		switch {
		case strings.HasPrefix(lines[i], "if "):
			depth++
		case lines[i] == "fi":
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	t.Fatalf("%s has no closing fi at column zero", what)
	return 0
}

// versionCommit is the block that records the version this deploy delivered:
// the `if grep -q '^APP_VERSION='` that rewrites the key when .env already has
// one and appends it when it does not.
//
// BOTH BRANCHES, which is the point of lifting the whole block rather than
// naming a line. The append branch runs once in an app's life; the rewrite
// branch runs on every deploy after the first, which is very nearly all of them
// -- so the branch that was pinned was the rare one and the branch that carries
// production was unchecked. Deleting the `sed`, pointing it at the wrong
// variable, or unanchoring its pattern all left `go test ./scripts/` green.
func versionCommit(t *testing.T, body string) (block string, at, end int) {
	t.Helper()
	lines := strings.Split(body, "\n")
	open := -1
	for i, ln := range lines {
		if strings.HasPrefix(ln, "if grep -q '^APP_VERSION='") {
			open = i
			break
		}
	}
	if open < 0 {
		t.Fatal("the deploy script never records APP_VERSION, so a start after a deploy brings up the previous version")
	}
	close := closingFi(t, lines, open, "the APP_VERSION commit")
	block = strings.Join(lines[open:close+1], "\n")
	at = strings.Index(body, block)
	return block, at, at + len(block)
}

// startsContainers reports whether a line of shell would bring containers up.
//
// TWO LOOSE CONDITIONS ANDED, deliberately, rather than one tight pattern.
// It was `\bdocker\s+(compose\s+)?(up|start|restart|run)\b` -- the verb required
// to sit immediately after `docker` or `compose` -- and any flag in between made
// a start invisible. `docker compose -f compose.yml up -d`, appended to the end
// of the deploy script, outside the guard, unconditional on every deploy, left
// `go test ./scripts/` green. That is komizo#54 restored in full by a line the
// check could not see.
//
// And it is not a contrived spelling: it is THIS REPO'S HOUSE STYLE. The real
// container start in alpine-proxy.sh is `docker compose -p "$PROXY_PROJECT" up
// -d --remove-orphans`, alpine-remove.sh uses `compose -f ... --project-directory
// ...`, and so does every compose call in cmd/komizo-box. So the tight pattern
// watched the one spelling this file happens to use and was blind to the one
// the rest of the tree uses -- the check was fitted to the code in front of it
// rather than to the act it is named for.
//
// So: does the line invoke docker at all, and does it name a start verb as a
// bare word. Being loose is the point. A pattern precise about argument order
// is a pattern that only matches the arrangement somebody thought of, and the
// whole failure being guarded against is an arrangement nobody thought of.
//
// The false-positive risk is real and is the right trade. Every non-comment
// docker line in the deploy script was checked against this: `login`, `pull -q`,
// `create --entrypoint`, `cp`, `rm -v`, `compose config -q`, `ps --format`,
// `exec ... caddy validate`, `compose pull`, `exec ... caddy reload` and
// `compose ps` are all correctly ignored, and the `echo` mentioning "nothing
// restarted" is ignored too because `restarted` is not `restart` as a bare word.
// Exactly one line matches. If a future line matches spuriously, the count fails
// and somebody has to decide about it, which is the correct outcome for a line
// that reads like it starts a container.
func startsContainers(line string) bool {
	return dockerCall.MatchString(line) && startVerb.MatchString(line)
}

var (
	dockerCall = regexp.MustCompile(`\bdocker\b`)
	startVerb  = regexp.MustCompile(`\b(up|start|restart|run)\b`)
)

// stateFileLine is the deploy script's OWN assignment of the record it reads.
//
// Lifted rather than restated, because a test that names the path itself tests
// nothing about the path. Point the shipped `STATE_FILE=` at a file that never
// exists on a box -- a plausible typo, or a rename that misses this line -- and
// a test with its own definition stays green while every deploy reads no marker
// and starts every stopped app. That is komizo#54 restored in full, past both
// tests here and past alpine.sh's leftover-placeholder guard, which is happy as
// long as SOME placeholder was substituted.
//
// The placeholders are substituted the way alpine.sh substitutes them, with the
// state directory pointed at the test's own. Anything else in the line -- a
// third placeholder, a directory this does not know about -- survives as literal
// text, the record is not found, and the stopped cases fail. Which is the point:
// this test only passes for a path built out of the two values it can supply.
// EXACTLY ONE assignment, and that is an assertion rather than a convenience.
// Taking the first match would disagree with the shell, which obeys the LAST --
// so a second `STATE_FILE=` added anywhere below (a rename half-applied, a
// well-meant "make sure it is set" line) would leave this reading the old path,
// every stopped case still passing, and every real deploy reading a file that is
// not the record. The test would be pinned to an assignment the box ignores.
// Two spellings of this path in one script is the exact thing the comment above
// the assignment in alpine.sh says it exists to prevent.
func stateFileLine(t *testing.T, body, stateDir, app string) string {
	t.Helper()
	var found []string
	for _, ln := range strings.Split(body, "\n") {
		if strings.HasPrefix(ln, "STATE_FILE=") {
			found = append(found, ln)
		}
	}
	switch len(found) {
	case 0:
		t.Fatal("the deploy script never says which record it reads (no STATE_FILE= at column zero)")
	case 1:
	default:
		t.Fatalf("the deploy script assigns STATE_FILE %d times (%q) -- the shell obeys the last and this test would read the first, so they would disagree about which file decides whether an app starts", len(found), found)
	}
	ln := strings.ReplaceAll(found[0], "__STATE_DIR__", stateDir)
	ln = strings.ReplaceAll(ln, "__APP_NAME__", app)

	// The substitution ACTUALLY HAPPENED and landed on the fixture. Without
	// this, a placeholder renamed in alpine.sh leaves the line untouched, the
	// record is simply never found, and the failure arrives as four stopped
	// cases reporting that the app started -- which reads like the guard broke
	// rather than like the test lost track of the file. Same failure, said in
	// the words of what is actually wrong.
	if want := filepath.Join(stateDir, app+".env"); !strings.Contains(ln, want) {
		t.Fatalf("STATE_FILE is %q, which does not resolve to %q -- the placeholders in it are not the ones alpine.sh substitutes (__STATE_DIR__ and __APP_NAME__), so this test can no longer find the record the deploy reads", ln, want)
	}
	return ln
}

// runDecision runs the block against a state file, and reports what it printed
// and every docker command it would have run.
//
// `docker` is a shell function rather than a stub on PATH so the block runs
// exactly as written -- a stub binary would also test that PATH lookup works,
// which is not in question, and would need a temp dir on PATH for a test about
// a marker file.
// how is one run: the record to lay down, and the two ways a box can be
// unhelpful about it. A struct rather than a parameter list because every one
// of these is a rare case and a call site reading `false, false` says nothing
// about which.
type how struct {
	record string
	// dockerFails: the start is attempted and does not work.
	dockerFails bool
	// unreadable: the record exists and this process cannot open it, which is
	// what a damaged mode or ownership looks like from here.
	unreadable bool
}

func runDecision(t *testing.T, body, block string, h how) (out string, dockerRan []string, err error) {
	t.Helper()
	dir := t.TempDir()
	// AppsDir holds one file per app, named for the app -- see box/paths.go and
	// the record alpine.sh writes. The test lays the fixture out that way and
	// lets the script's own STATE_FILE line decide where to look for it.
	state := filepath.Join(dir, "web.env")
	if h.record != "" {
		if err := os.WriteFile(state, []byte(h.record), 0o600); err != nil {
			t.Fatal(err)
		}
		if h.unreadable {
			if err := os.Chmod(state, 0); err != nil {
				t.Fatal(err)
			}
		}
	}
	log := filepath.Join(dir, "docker.log")

	// The values the block reads that are set further up the real script. Only
	// these: anything else it touched would be a dependency this test would
	// rather find out about now than on a box.
	//
	// `set -f` is here because the real script sets it at the top and never
	// turns it back on after the one place it is off. A block that only works
	// with pathname expansion enabled would pass here without it and behave
	// differently on a box.
	fail := ""
	if h.dockerFails {
		fail = " return 1;"
	}
	prelude := "set -euf\n" +
		"APP_NAME=web\n" +
		"version=abc1234\n" +
		"ref=registry.example/web-config:abc1234\n" +
		stateFileLine(t, body, dir, "web") + "\n" +
		"docker() { printf '%s\\n' \"docker $*\" >> " + log + ";" + fail + " }\n"

	cmd := exec.Command("sh", "-c", prelude+block)
	b, err := cmd.CombinedOutput()
	ran, _ := os.ReadFile(log)
	for _, ln := range strings.Split(strings.TrimSpace(string(ran)), "\n") {
		if ln != "" {
			dockerRan = append(dockerRan, ln)
		}
	}
	return string(b), dockerRan, err
}

func TestADeployDoesNotStartAnAppThatWasStopped(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	body := deployBody(t)
	block := startDecision(t, body)

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

		// EXACTLY "1". A hand-edited record can pick up a trailing space, and
		// this side and box/probe.go must make the same nothing of it -- see
		// TestTheReportAndTheDeployReadTheMarkerTheSameWay, which runs these
		// same cases against the Go reader. A comparison either side loosened
		// to "contains a 1" would have the report and the deploy disagreeing
		// about the same file.
		{"a value that merely contains a 1", base + "STOPPED=1 \n", true},

		// No record at all. Deploys carry on, deliberately: an app with no
		// record does not appear in the report either, so app_down cannot fire
		// for it and there is no page to protect. Refusing here would instead
		// break every deploy on a box whose state directory went missing, which
		// is a failure with a much wider blast radius than the one it prevents.
		{"no record", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, ran, err := runDecision(t, body, block, how{record: tc.record})
			if err != nil {
				t.Fatalf("the start decision failed to run: %v\n%s", err, out)
			}

			started := false
			for _, c := range ran {
				// Any verb that would run a container, for the reason
				// startsContainers gives at length.
				if startsContainers(c) {
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
			//
			// And it must not say BOTH, which is why the other one is checked
			// for as well. A branch that printed the pair would satisfy a
			// contains-check on either line while telling a caller that parses
			// `started=` two contradictory things -- and the last one wins,
			// which is whichever the script happens to print second.
			want, wrong := "started=no", "started=yes"
			if tc.start {
				want, wrong = wrong, want
			}
			if !strings.Contains(out, "deploy: "+want) {
				t.Errorf("output does not say %q:\n%s", want, out)
			}
			if strings.Contains(out, "deploy: "+wrong) {
				t.Errorf("output also says %q, so a caller parsing started= is told both:\n%s", wrong, out)
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

	// The same block the test above runs, located in the file, so the two
	// cannot end up disagreeing about where the decision is.
	decision := strings.Index(body, startDecision(t, body))
	end := decision + len(startDecision(t, body))
	{
		i := strings.Index(body, "if ! docker compose pull; then")
		if i < 0 {
			t.Fatal("could not find the image pull -- has the deploy script been reshaped?")
		}
		if i > decision {
			t.Error("the image pull happens after the start decision, so a deploy to a stopped app does not leave the new version ready to come up")
		}
	}

	// The WHOLE version-commit block, not one of its two branches. Naming the
	// `printf` line put the ordering assertion on the branch that runs once in
	// an app's life and left the `sed` branch -- every deploy after the first --
	// free to sit below the decision.
	if _, _, end := versionCommit(t, body); end > decision {
		t.Error("the APP_VERSION commit is not finished before the start decision, so a deploy to a stopped app does not leave the new version ready to come up")
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
	// -- this file argues about that command at length, and a check that counted
	// the arguments as well as the code would be a check nobody could leave a
	// note beside.
	found := 0
	at := 0
	for _, ln := range strings.Split(body, "\n") {
		// The line's own offset, kept as we go. strings.Index would answer with
		// the FIRST place that text appears, which for a line that occurs twice
		// is the wrong one -- and the wrong one is inside the guard, so the
		// second copy would be judged by the position of the first.
		here := at
		at += len(ln) + 1
		if strings.HasPrefix(strings.TrimSpace(ln), "#") || !startsContainers(ln) {
			continue
		}
		found++
		if here < decision || here > end {
			t.Errorf("`%s` starts containers from outside the stop check, so a deploy would start an app somebody stopped", strings.TrimSpace(ln))
		}
	}
	if found != 1 {
		t.Errorf("the deploy script has %d ways to start containers; exactly one may exist, and it is the one that reads the stop marker", found)
	}
}

// A START THAT FAILED MUST NOT REPORT THAT IT STARTED.
//
// `deploy: started=yes` is the line a caller parses, and the deploy script runs
// under `set -e` -- so a `docker compose up -d` that fails ends the script right
// there. Printed before the start, the last thing a CI log would carry is a
// machine-readable claim that the app came up, immediately above compose's
// output saying it did not. The stopped branch prints its line first because
// nothing in it can fail.
func TestAFailedStartDoesNotClaimTheAppStarted(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	body := deployBody(t)
	out, ran, err := runDecision(t, body, startDecision(t, body), how{record: "APP_DIR=/srv/web\n", dockerFails: true})
	if err == nil {
		t.Errorf("a failing `docker compose up` left the script succeeding:\n%s", out)
	}
	if len(ran) == 0 {
		t.Fatalf("nothing was even attempted:\n%s", out)
	}
	if strings.Contains(out, "started=yes") {
		t.Errorf("the start failed and the script said started=yes anyway:\n%s", out)
	}
}

// A RECORD THAT CANNOT BE READ SAYS SO.
//
// The read used to be `sed ... 2>/dev/null`, which turned two different states
// into one silent empty answer: "this app has no record", which is ordinary,
// and "this box's state directory is broken", which is not. Both came out as
// "not stopped" and started the app, and only one of them should pass without
// comment. The `[ -f ]` guard means a missing record asks nothing, and anything
// else leaves sed's complaint in the deploy log where somebody will meet it.
//
// The direction is unchanged, deliberately: an unreadable record still starts
// the app, because refusing to deploy on a box whose state directory has gone
// is a far wider failure than the one it would prevent, and an app with no
// readable record is not in the report and cannot page anyway. What is tested
// here is that it is not silent about it.
func TestAnUnreadableRecordIsNotSilent(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	if os.Geteuid() == 0 {
		// root opens a mode-0 file, so there is no unreadable record to make.
		t.Skip("running as root")
	}
	body := deployBody(t)
	out, ran, err := runDecision(t, body, startDecision(t, body),
		how{record: "APP_DIR=/srv/web\nSTOPPED=1\n", unreadable: true})
	if err != nil {
		t.Fatalf("the start decision failed to run: %v\n%s", err, out)
	}
	// It starts -- the record said STOPPED, and the script could not read it to
	// find that out. Asserted so the trade is written down rather than assumed.
	if len(ran) == 0 {
		t.Errorf("an unreadable record stopped the deploy instead of starting the app:\n%s", out)
	}
	// And it complains, which is the whole point.
	if !strings.Contains(out, "web.env") {
		t.Errorf("a record that could not be read produced no complaint naming it:\n%s", out)
	}
}

// THE VERSION THIS DEPLOY DELIVERED IS RECORDED ON EVERY DEPLOY, NOT JUST THE
// FIRST.
//
// `.env` is the only place the box records what was deployed: `komizo start`
// runs `docker compose up -d`, which resolves every image through
// ${APP_VERSION}. So for a stopped app this file IS the deploy -- the containers
// were never recreated, and the whole promise of pulling without starting is
// that a later start brings up what this deploy fetched. Leave APP_VERSION at
// the old value and the pull was wasted work: the next start quietly returns the
// previous version, from a box whose compose.yml and images are the new one's.
//
// TWO BRANCHES, and the ordering test above could only see one of them. An app's
// first deploy appends the key; every deploy after that rewrites it in place --
// so the branch that was pinned by name runs once, and the branch that carries
// production ran unchecked. Deleting the `sed`, pointing it at `$ref` instead of
// `$version`, or dropping the `^` from its pattern each left the suite green.
//
// The block is lifted and RUN, for the same reason the start decision is: what
// is in question here is what the shell does to a file, and a substring match
// cannot tell a working rewrite from a broken one.
func TestTheDeployedVersionIsRecordedOnEveryDeploy(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	block, _, _ := versionCommit(t, deployBody(t))

	for _, tc := range []struct {
		name string
		env  string
		want string
	}{
		// An app's FIRST deploy: nothing to rewrite, so the key is appended and
		// everything already in the file is left alone.
		{
			"a first deploy, with no APP_VERSION yet",
			"COMPOSE_PROJECT_NAME=web\n",
			"COMPOSE_PROJECT_NAME=web\nAPP_VERSION=abc1234\n",
		},

		// EVERY DEPLOY AFTER THE FIRST, which is very nearly all of them. The
		// old value must be gone, not merely followed by a newer one -- compose
		// takes the last assignment, but a file with two is a file two readers
		// disagree about, and `komizo report` reads it with first-wins.
		{
			"a redeploy, over an existing APP_VERSION",
			"COMPOSE_PROJECT_NAME=web\nAPP_VERSION=old9999\n",
			"COMPOSE_PROJECT_NAME=web\nAPP_VERSION=abc1234\n",
		},

		// The key in the middle of the file, with lines after it. An append-only
		// rewrite would leave the stale one above the new one.
		{
			"a redeploy, with the key above other settings",
			"APP_VERSION=old9999\nCOMPOSE_PROJECT_NAME=web\n",
			"APP_VERSION=abc1234\nCOMPOSE_PROJECT_NAME=web\n",
		},

		// ANCHORED. A key that merely ends in APP_VERSION is somebody else's
		// key, and an unanchored `s|APP_VERSION=.*|` rewrites it too -- silently
		// destroying a value this script was never asked to touch, in the one
		// file the app's whole configuration comes from.
		{
			"a redeploy, beside a key that ends in APP_VERSION",
			"PREV_APP_VERSION=old9999\nAPP_VERSION=old9999\n",
			"PREV_APP_VERSION=old9999\nAPP_VERSION=abc1234\n",
		},

		// The same, where the similarly named key is the ONLY one. `grep -q` is
		// anchored too, so this takes the append branch -- and a `grep` that
		// matched here would take the rewrite branch and never write the key at
		// all.
		{
			"a first deploy, beside a key that ends in APP_VERSION",
			"PREV_APP_VERSION=old9999\n",
			"PREV_APP_VERSION=old9999\nAPP_VERSION=abc1234\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			env := filepath.Join(dir, ".env")
			if err := os.WriteFile(env, []byte(tc.env), 0o600); err != nil {
				t.Fatal(err)
			}
			// `ref` is set because it is in scope at this point in the real
			// script and is the value a slip would most plausibly reach for --
			// it is the thing that was just pulled. It must not end up in .env:
			// APP_VERSION is a tag, and compose substitutes it into image
			// references that already carry a registry and a repository.
			prelude := "set -euf\n" +
				"version=abc1234\n" +
				"ref=registry.example/web-config:abc1234\n" +
				"cd " + dir + "\n"

			cmd := exec.Command("sh", "-c", prelude+block)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("the APP_VERSION commit failed to run: %v\n%s", err, out)
			}

			got, err := os.ReadFile(env)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf(".env is\n%q\nwant\n%q", got, tc.want)
			}
		})
	}
}
