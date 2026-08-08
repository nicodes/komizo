package app

import (
	"os"
	"strings"
	"testing"

	"github.com/nicodes/komizo/box"
)

// `komizo report` says whether the agent on a box is BEHIND, not just what it is.
//
// The interface answered this on its server row and this command did not: it
// printed the box's version and left the comparison to a reader who would have
// to know this binary's own version to make it. Deleting the interface
// (nicodes/komizo-be#55) without moving the answer would have deleted a
// capability, which is the one thing the parity rule forbids.
//
// Each case names a box shape and the sentence it has to produce.
func TestReportSaysWhenTheAgentOnABoxIsBehind(t *testing.T) {
	current := box.KomizoInstall{
		Installed: true,
		Version:   versionText(),
		Stamp:     komizoStamp(),
	}

	for _, tc := range []struct {
		name   string
		k      box.KomizoInstall
		want   string // a phrase the sentence must carry, or "" for silence
		remedy string
	}{
		{
			name:   "never set up",
			k:      box.KomizoInstall{Installed: false},
			want:   "no komizo agent",
			remedy: "komizo init --host root@box",
		},
		{
			// Set up by a komizo old enough to have recorded only a stamp.
			// Nothing to compare, and the update is what starts recording a
			// version -- so it is always worth running.
			name:   "no version recorded",
			k:      box.KomizoInstall{Installed: true, Stamp: komizoStamp()},
			want:   "records no komizo version",
			remedy: "komizo update --host root@box",
		},
		{
			// The stamp catches what the version misses: a build calling itself
			// "dev" has the same version forever while its content changes.
			name:   "same version, different agent",
			k:      box.KomizoInstall{Installed: true, Version: versionText(), Stamp: "0badc0ffee11"},
			want:   "differs from the one this komizo installs",
			remedy: "komizo update --host root@box",
		},
		{
			// And the version catches what the stamp misses: a script or a doas
			// rule changed between releases, and the agent binary did not.
			name:   "same agent, older release",
			k:      box.KomizoInstall{Installed: true, Version: "0.0.1", Stamp: komizoStamp()},
			want:   "set up by komizo 0.0.1",
			remedy: "komizo update --host root@box",
		},
		{
			name: "current",
			k:    current,
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, remedy := agentBehind(tc.k, "root@box")
			if tc.want == "" {
				if got != "" {
					t.Errorf("a current box was reported as behind: %q", got)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("agentBehind = %q, want it to say %q", got, tc.want)
			}
			if remedy != tc.remedy {
				t.Errorf("remedy = %q, want %q", remedy, tc.remedy)
			}
		})
	}
}

// AND THE SENTENCE REACHES THE PAGE. agentBehind returning the right words is
// half of it; a printReport that never calls it produces exactly the output
// this change was made to fix, with the whole test above still green.
func TestTheReportPrintsThatTheAgentIsBehind(t *testing.T) {
	r := box.Report{}
	r.Server.State = "ready"
	r.Server.Komizo = box.KomizoInstall{Installed: true, Version: "0.0.1", Stamp: komizoStamp()}

	out := capture(t, func() { printReport(r, "root@box", false) })

	if !strings.Contains(out, "set up by komizo 0.0.1") {
		t.Errorf("the report does not say the box is behind:\n%s", out)
	}
	if !strings.Contains(out, "komizo update --host root@box") {
		t.Errorf("the report says the box is behind and does not say what to run:\n%s", out)
	}
}

// A CURRENT BOX IS SAID NOTHING ABOUT. The check above passes just as well if
// the sentence is printed unconditionally, and a warning on every healthy box
// is a warning nobody reads on the one box that has it coming.
func TestTheReportIsSilentAboutABoxThatIsUpToDate(t *testing.T) {
	r := box.Report{}
	r.Server.State = "ready"
	r.Server.Komizo = box.KomizoInstall{
		Installed: true, Version: versionText(), Stamp: komizoStamp(),
	}

	out := capture(t, func() { printReport(r, "root@box", false) })

	if strings.Contains(out, "komizo update --host") {
		t.Errorf("a box running this komizo was told to update:\n%s", out)
	}
}

// capture is everything f writes to the terminal -- BOTH streams.
//
// Not stdout alone, which is what the first version of this did and what made
// the two tests above fail against working code. printReport puts the report on
// stdout and its warnings on stderr, and a reader watching a terminal sees one
// thing. Asserting on half of it means an assertion that passes or fails on
// which stream a sentence happens to take, which is not what either test is
// about.
func capture(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outOrig, errOrig := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		done <- b.String()
	}()
	f()
	w.Close()
	os.Stdout, os.Stderr = outOrig, errOrig
	return <-done
}
