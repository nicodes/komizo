package workflows

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// THE JOB CEILING IS A BACKSTOP, AND THE COMMENTS SAY SO. This checks it.
//
// nicodes/komizo-be#147 moved the timeout off the job and onto the steps, because a job's
// timeout-minutes INCLUDES QUEUE TIME and a step's does not -- three runs were
// killed during the 2026-08-06 Actions incident having done no work at all.
//
// ci.yml then carried a sentence claiming the remaining job number is
// "deliberately larger than the sum of them, so it can only fire when one of
// them has failed to". THE SENTENCE WAS FALSE: 55 minutes of step bounds under
// a 45-minute job. So a run that queued a little and ran slowly could still be
// killed by the job while every step was inside its own bound -- the same
// defect #147 exists to remove, one size smaller, shipped in the fix for it.
//
// It also missed release.yml entirely, where a kill lands somewhere particular:
// that job creates a TAG, and a Go module version is permanent once anything
// has fetched it.
//
// It is a check rather than a corrected comment because the arithmetic changes
// every time somebody adds a step, and a comment cannot notice that.

// A RANGE, not just an ordering. The backstop has to exceed the sum, or it is
// not a backstop -- and it must not exceed it by so much that a genuinely stuck
// job holds a runner for hours, which is the thing the job number is for.
const maxSlackMinutes = 60

func TestTheJobCeilingIsLargerThanEverythingItBacksUp(t *testing.T) {
	files, err := filepath.Glob("../../.github/workflows/*.yml")
	if err != nil {
		t.Fatal(err)
	}
	// A GLOB THAT MATCHES NOTHING PASSES EVERY LOOP BELOW, which is the shape
	// the reviewing standard opens with -- so it is refused here rather than reported
	// as success.
	if len(files) == 0 {
		t.Fatal("no workflows found, so this checked nothing -- the path moved or the glob is wrong")
	}

	checked := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		job, steps, n := timeouts(string(b))
		if job == 0 {
			// A workflow with no job ceiling at all is a separate question and
			// not this one's. Said rather than skipped silently.
			t.Logf("%s has no job timeout-minutes", filepath.Base(f))
			continue
		}
		checked++
		if n == 0 {
			t.Errorf("%s bounds the job (%dm) and no step, so the ceiling still counts queue time -- #147",
				filepath.Base(f), job)
			continue
		}
		if job <= steps {
			t.Errorf("%s: job ceiling %dm does not exceed its %d step bounds totalling %dm, "+
				"so it can fire while every step is inside its own -- which is the job ceiling "+
				"measuring something other than a hang", filepath.Base(f), job, n, steps)
		}
		if job-steps > maxSlackMinutes {
			t.Errorf("%s: job ceiling %dm is %dm above its step bounds (%dm) -- a backstop that "+
				"loose lets a stuck job hold a runner for most of an hour after every step has "+
				"given up", filepath.Base(f), job, job-steps, steps)
		}
	}
	if checked == 0 {
		t.Error("no workflow had both a job ceiling and step bounds, so nothing above ran")
	}
}

// timeouts reads the job's ceiling and the sum of the step bounds.
//
// BY INDENTATION, which is what tells them apart: a job's key sits at four
// spaces and a step's at eight. Crude on purpose -- pulling in a YAML parser to
// read two integers is a dependency in the repository that holds a signing key,
// and the failure mode of getting it wrong here is a spurious red rather than a
// missed one.
func timeouts(src string) (job, steps, n int) {
	for _, ln := range strings.Split(src, "\n") {
		t := strings.TrimSpace(ln)
		if !strings.HasPrefix(t, "timeout-minutes:") || strings.HasPrefix(t, "#") {
			continue
		}
		v, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(t, "timeout-minutes:")))
		if err != nil {
			continue
		}
		switch len(ln) - len(strings.TrimLeft(ln, " ")) {
		case 4:
			job = v
		case 8:
			steps += v
			n++
		}
	}
	return job, steps, n
}
