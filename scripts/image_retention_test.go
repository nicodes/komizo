package scripts

import (
	"strings"
	"testing"
)

// Reclaiming images no container is using.
//
// Nothing ever removed the image a deploy replaced. Every deploy and every
// preview pulls one tagged by commit, so two boxes reached 162 and 172
// images with 15 and 8 in use -- gdam alone holding fourteen copies of the
// same 157MB gate image from a single day. The capacity floor refused a
// preview before the disk filled, which is the only reason it surfaced as a
// failed preview rather than an outage.
//
// The app script says why it is not the place for this ("Disk is a SERVER
// concern. It belongs wherever server-wide upkeep ends up living") and this
// is that place.

func TestPruneIsServerLevelNotPerApp(t *testing.T) {
	// A machine-wide prune must not be reachable from the per-app path: that
	// one runs under a deploy key, and one app's deploy has no business
	// reaching across every other app on the box.
	//
	// CODE only. alpine.sh discusses `docker image prune` at length in a
	// comment explaining why it does not run one, and the first version of
	// this test matched that comment and failed on prose.
	for _, line := range strings.Split(AlpineScript, "\n") {
		if strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
			continue
		}
		if strings.Contains(line, "image prune") {
			t.Errorf("the per-app script runs a machine-wide image prune, which a "+
				"deploy key can invoke: %s", strings.TrimSpace(line))
		}
	}
	if !strings.Contains(AlpineInitScript, "docker image prune -af") {
		t.Error("the server script does not reclaim images")
	}
}

// -af, not -f. A bare `docker image prune` collects only DANGLING images,
// and a komizo deploy leaves none: every image it replaces is still tagged
// by its commit. The per-app script's own comment makes exactly this point.
func TestPruneCollectsTaggedImagesNotJustDangling(t *testing.T) {
	line := ""
	for _, l := range strings.Split(AlpineInitScript, "\n") {
		if strings.Contains(l, "docker image prune") {
			line = l
		}
	}
	if line == "" {
		t.Fatal("no prune line found")
	}
	if !strings.Contains(line, "-af") {
		t.Errorf("prune must be -af; a bare prune collects only dangling images "+
			"and komizo leaves none: %s", line)
	}
	// No `until=` filter: the rule is "referenced by a container", not an age.
	// An age window keeps whatever happens to be recent, which is neither the
	// thing that is needed nor the thing that is safe.
	if strings.Contains(line, "until=") {
		t.Errorf("prune should keep what containers reference, not what is recent: %s", line)
	}
}

// The assumption underneath all of this -- that an image referenced by a
// STOPPED container survives `docker image prune -af`, so an app somebody
// stopped keeps the image it will start again with -- is Docker's documented
// behaviour, and was verified by hand against a real daemon before this
// landed. It is not re-tested here: doing so costs two minutes of CI to
// assert something Docker guarantees, and a test that slow gets skipped.

// Once is not a schedule.
//
// The reclaim above was correct and ran exactly one time per box: at `komizo
// init`. What it defends against is accumulation over weeks, so a box built
// in August was unprotected by September. One drifted to 92% full, crossed
// the capacity floor the deploy script enforces, and every app on it then
// refused to deploy -- with no path back but an operator at an SSH prompt,
// because nothing in komizo would ever reclaim again. A floor with nothing
// holding the box above it turns a slow problem into a hard stop.
func TestReclaimIsScheduledNotJustRunOnce(t *testing.T) {
	if !strings.Contains(AlpineInitScript, "/etc/periodic/daily/komizo-reclaim") {
		t.Error("init does not install a periodic reclaim job; the prune would run " +
			"only at init and never again")
	}
	// busybox crond is what executes /etc/periodic. It ships with Alpine but
	// is not started on a minimal install, and an unstarted crond makes the
	// job a file nobody runs -- the same bug, just quieter.
	if !strings.Contains(AlpineInitScript, "rc-update add crond") {
		t.Error("init installs a periodic job without enabling crond, so nothing runs it")
	}
}

// One definition, both callers.
//
// The scheduled job and the init-time run must be the same script. Two copies
// of a prune drift, and the one that drifts is the one nobody watches.
func TestInitRunsTheSameScriptItInstalls(t *testing.T) {
	prunes := 0
	for _, l := range strings.Split(AlpineInitScript, "\n") {
		if strings.HasPrefix(strings.TrimLeft(l, " \t"), "#") {
			continue
		}
		if strings.Contains(l, "docker image prune") {
			prunes++
		}
	}
	if prunes != 1 {
		t.Errorf("found %d prune invocations in the init script; there must be exactly "+
			"one definition, invoked by both the daily job and init", prunes)
	}
	if !strings.Contains(AlpineInitScript, `"$RECLAIM_BIN"`) {
		t.Error("init does not invoke the reclaim script it installed")
	}
}

// A periodic job that exits non-zero is noise an operator cannot act on, and
// busybox run-parts reports it every night. A prune that could not run today
// runs tomorrow.
func TestReclaimJobNeverFails(t *testing.T) {
	job := reclaimJob(t)
	if strings.Contains(job, "set -e") {
		t.Error("the reclaim job uses set -e; an unattended nightly job must not " +
			"fail on a transient docker hiccup")
	}
	if !strings.Contains(job, "docker image prune -af >/dev/null 2>&1 || true") {
		t.Error("the reclaim job's prune is not guarded with || true")
	}
	if !strings.HasSuffix(strings.TrimSpace(job), "exit 0") {
		t.Error("the reclaim job does not end in an explicit exit 0")
	}
}

// The log is the only evidence the job ran at all, and it is append-only on a
// box whose whole problem is disk.
func TestReclaimLogIsTrimmed(t *testing.T) {
	job := reclaimJob(t)
	if !strings.Contains(job, "/var/log/komizo-reclaim.log") {
		t.Error("the reclaim job records nothing, so a box cannot show whether it ran")
	}
	if !strings.Contains(job, "tail -n") {
		t.Error("the reclaim log is never trimmed; an append-only file on a disk-pressure " +
			"box is the wrong shape")
	}
}

// reclaimJob returns the body of the heredoc that init writes to
// /etc/periodic/daily/komizo-reclaim.
func reclaimJob(t *testing.T) string {
	t.Helper()
	const open, close = "KOMIZO_RECLAIM_EOF'\n", "\nKOMIZO_RECLAIM_EOF"
	i := strings.Index(AlpineInitScript, open)
	if i < 0 {
		t.Fatal("no KOMIZO_RECLAIM_EOF heredoc in the init script")
	}
	rest := AlpineInitScript[i+len(open):]
	j := strings.Index(rest, close)
	if j < 0 {
		t.Fatal("unterminated KOMIZO_RECLAIM_EOF heredoc")
	}
	return rest[:j]
}

// Previews are reaped on the same schedule, and before the prune.
//
// `preview gc` had the same defect as the image prune: written, correct, and
// scheduled nowhere. CI tears a preview down when its PR closes, which is the
// common path -- gc is the backstop for the PR left open for a month and the
// teardown job that failed. Ordering it before the prune means a preview
// released tonight has its image collected tonight.
func TestPreviewGCRunsDailyBeforeThePrune(t *testing.T) {
	job := reclaimJob(t)
	gc := strings.Index(job, "preview gc")
	if gc < 0 {
		t.Fatal("the daily job does not reap previews; abandoned stacks hold their " +
			"images against the prune forever")
	}
	prune := strings.Index(job, "docker image prune")
	if prune < 0 {
		t.Fatal("no prune in the daily job")
	}
	if gc > prune {
		t.Error("previews are reaped after the prune, so a stack released tonight " +
			"keeps its image until tomorrow")
	}
	// A box with no previews configured has no komizo-box, and a daily job
	// must not log a failure every night for a feature nobody turned on.
	if !strings.Contains(job, "[ -x /usr/local/bin/komizo-box ]") {
		t.Error("preview gc is not guarded on the binary existing")
	}
}
