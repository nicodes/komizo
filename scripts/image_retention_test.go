package scripts

import (
	"strings"
	"testing"
)

// Tagged images accumulate after deploys and previews. Reclamation is
// scheduled by the host but implemented by each app's fixed root-owned
// command. A global prune would discard unreferenced rollback tags.
func TestNeitherInstallerRunsGlobalImagePrune(t *testing.T) {
	for name, body := range map[string]string{"app": AlpineScript, "host": AlpineInitScript} {
		for _, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
				continue
			}
			for _, forbidden := range []string{"docker image prune", "docker system prune", "docker volume prune", "docker image rm -f"} {
				if strings.Contains(line, forbidden) {
					t.Errorf("%s installer contains broad cleanup %q: %s", name, forbidden, line)
				}
			}
		}
	}
}

func TestHostDispatchesOnlyInstalledScopedPruners(t *testing.T) {
	job := reclaimJob(t)
	for _, required := range []string{
		"for prune in /usr/local/bin/prune-*; do",
		`[ -f "$prune" ] && [ ! -L "$prune" ] && [ -x "$prune" ]`,
		`if out="$("$prune" 2>&1)"; then`,
		"no app-scoped image retention commands installed",
	} {
		if !strings.Contains(job, required) {
			t.Errorf("nightly job missing %s", required)
		}
	}
}

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
	if strings.Count(AlpineInitScript, `if out="$("$prune" 2>&1)"; then`) != 1 {
		t.Error("app retention dispatch must have exactly one definition")
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
	if !strings.Contains(job, `if out="$("$prune" 2>&1)"; then`) || !strings.Contains(job, `: failed: $(printf`) {
		t.Error("the nightly job must log scoped prune failures and continue")
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
	prune := strings.Index(job, "for prune in /usr/local/bin/prune-*")
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
