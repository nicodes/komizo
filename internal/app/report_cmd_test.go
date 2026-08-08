package app

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/internal/agent"
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
	// DEFERRED, so a panic in f does not leave the globals pointing at a closed
	// pipe for the rest of the package. Review 1's (h): safe today only because
	// nothing here uses t.Parallel(), which is not a property to depend on.
	defer func() { os.Stdout, os.Stderr = outOrig, errOrig }()
	defer r.Close()
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
	return <-done
}

// THE THREE THINGS ONLY THE INTERFACE COULD SAY.
//
// Review 1 on nicodes/komizo-be#55 walked the deleted screens rather than the
// diff and found three classes of information with no surviving command: an
// app's volume sizes, whether the box is busy, and how many requests each app
// served and how many failed. The decoders for all three survived the deletion
// and became unreachable, which is exactly why the source still looked like it
// could answer -- and why these are asserted through the real command rather
// than by calling the decoders directly.

// stubBox answers for the box, and records what it was asked.
func stubBox(t *testing.T, answer func(args []string) ([]byte, error)) *[][]string {
	t.Helper()
	var asked [][]string
	orig := askBox
	askBox = func(_ target, args ...string) ([]byte, error) {
		asked = append(asked, args)
		return answer(args)
	}
	t.Cleanup(func() { askBox = orig })
	return &asked
}

func TestReportAsksTheBoxToMeasureVolumesOnlyWhenAsked(t *testing.T) {
	for _, tc := range []struct {
		name, arg string
		want      bool
	}{
		{"without the flag", "", false},
		{"with the flag", "--volumes", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reachable(t)
			reachable(t)
			asked := stubBox(t, func([]string) ([]byte, error) {
				return []byte(`{"v":1,"server":{"state":"ready"},"apps":[]}`), nil
			})
			args := []string{"--host", "root@box"}
			if tc.arg != "" {
				args = append(args, tc.arg)
			}
			if err := RunReport(args); err != nil {
				t.Fatalf("komizo report %v = %v", args, err)
			}
			if len(*asked) == 0 {
				t.Fatal("the box was never asked anything")
			}
			got := false
			for _, a := range (*asked)[0] {
				if a == "--volumes" {
					got = true
				}
			}
			if got != tc.want {
				// MEASURING COSTS A WALK OF EVERY VOLUME, so asking always is a
				// slow report; never asking is the capability being gone.
				t.Errorf("asked the box for volumes = %v, want %v (%v)", got, tc.want, (*asked)[0])
			}
		})
	}
}

func TestReportPrintsTheVolumeSizesTheBoxMeasured(t *testing.T) {
	reachable(t)
	stubBox(t, func([]string) ([]byte, error) {
		return []byte(`{"v":1,"server":{"state":"ready"},"apps":[{"name":"blog"}],
			"system":{"volumes":[
				{"app":"blog","service":"web","name":"blog_data","bytes":1048576},
				{"app":"blog","service":"worker","name":"blog_data","bytes":1048576}]}}`), nil
	})
	out := capture(t, func() { _ = RunReport([]string{"--host", "root@box", "--volumes"}) })

	if !strings.Contains(out, "blog") || !strings.Contains(out, "1.0M") {
		t.Errorf("the volume sizes are not on the page:\n%s", out)
	}
	// SHARED VOLUMES COUNTED ONCE. Two services of one app mounting the same
	// volume is one volume, and summing the rows would say 2 MiB about 1 MiB of
	// disk.
	if strings.Contains(out, "2.0M") {
		t.Errorf("a volume two services share was counted twice:\n%s", out)
	}
}

func TestReportSaysWhetherTheBoxIsBusyAndWhatItServed(t *testing.T) {
	now := time.Now()
	reachable(t)
	stubBox(t, func(args []string) ([]byte, error) {
		if args[0] == "monitor" {
			// Two readings a minute apart: 6000 jiffies elapsed, 3000 idle, so
			// the box was half busy. One reading cannot say -- System.CPU is
			// cumulative since boot, which is why this asks for history at all.
			a := now.Add(-time.Minute).Format(time.RFC3339)
			b := now.Format(time.RFC3339)
			minute := now.Add(-2*time.Minute).Unix() / 60 * 60
			return []byte(`{"v":1,"metrics":{"span":{"from":1,"to":2},"rows":[
				{"minute":` + strconv.FormatInt(minute, 10) + `,"app":"blog","c2":7,"c5":3}]},
				"history":[
				{"at":"` + a + `","system":{"cores":2,"cpu":{"total":10000,"idle":5000}}},
				{"at":"` + b + `","system":{"cores":2,"cpu":{"total":16000,"idle":8000}}}]}`), nil
		}
		return []byte(`{"v":1,"server":{"state":"ready"},"apps":[]}`), nil
	})
	out := capture(t, func() { _ = RunReport([]string{"--host", "root@box", "--usage"}) })

	if !strings.Contains(out, "processor 50%") {
		t.Errorf("the report does not say whether the box is busy:\n%s", out)
	}
	if !strings.Contains(out, "blog") {
		t.Errorf("the report does not say what each app served:\n%s", out)
	}
	// REQUESTS AND FAILURES SEPARATELY. "Is anything reaching this" and "is any
	// of it failing" are different questions and one total answers neither.
	if !strings.Contains(out, "10") || !strings.Contains(out, "3") {
		t.Errorf("the counts are not split into served and failed:\n%s", out)
	}
}

// A BOX THAT WAS NEVER ASKED IS NOT A BOX THAT SERVED NOTHING. Without --usage
// no second call happens at all, and a zero here would be an answer to a
// question nobody put.
func TestReportSaysNothingAboutUsageUnlessAsked(t *testing.T) {
	reachable(t)
	asked := stubBox(t, func([]string) ([]byte, error) {
		return []byte(`{"v":1,"server":{"state":"ready"},"apps":[]}`), nil
	})
	out := capture(t, func() { _ = RunReport([]string{"--host", "root@box"}) })

	for _, a := range *asked {
		if a[0] == "monitor" {
			t.Error("a plain report asked the box for a window of history it was not asked for")
		}
	}
	if strings.Contains(out, "processor") {
		t.Errorf("a plain report claimed something about the processor:\n%s", out)
	}
}

// AND READING KOMIZO_KNOWN_HOSTS COSTS NOTHING. It used to cost a key rotation:
// formatKnownHosts was reachable only through `komizo add`, so somebody who had
// lost the secret re-provisioned the app to get it back and invalidated the
// repo's deploy key doing it.
func TestReportPrintsTheKnownHostsValueWithoutTouchingTheBox(t *testing.T) {
	reachable(t)
	asked := stubBox(t, func([]string) ([]byte, error) {
		return []byte(`{"v":1,"server":{"state":"ready",
			"host_keys":[{"type":"ssh-ed25519","key":"AAAAC3Nz"}]},
			"apps":[{"name":"blog","known_as":["blog.example.com"]}]}`), nil
	})
	out := capture(t, func() { _ = RunReport([]string{"--host", "root@box", "--known-hosts"}) })

	if !strings.Contains(out, "blog.example.com ssh-ed25519 AAAAC3Nz") {
		t.Errorf("the value CI pins is not on the page:\n%s", out)
	}
	// PER APP and scoped to that app's names: known_hosts matches the exact
	// string the client dialled, and each repo dials one.
	if !strings.Contains(out, "box ssh-ed25519 AAAAC3Nz") {
		t.Errorf("the name we connected on is missing from the value:\n%s", out)
	}
	// ONE READ, no write. A second call would be this command changing the box
	// it was asked to describe.
	if len(*asked) != 1 || (*asked)[0][0] != "report" {
		t.Errorf("reading known_hosts did more than read: %v", *asked)
	}
}

// reachable stands in for the preflight, which otherwise opens a real SSH
// connection and makes every test above a test of DNS.
func reachable(t *testing.T) {
	t.Helper()
	orig := ensureReachable
	ensureReachable = func(target, bool) error { return nil }
	t.Cleanup(func() { ensureReachable = orig })
}

// A BOX SET UP BY A `go run` KOMIZO IS NOT PERMANENTLY OUT OF DATE.
//
// nicodes/komizo-be#177. A komizo carrying embedded agents stamps by CONTENT; one
// that compiled its agent on demand stamps by VERSION, prefixed "v:". Comparing a
// hash to a version string always differs, so without this the two would read each
// other's boxes as out of date forever -- a never-settling false alarm on the one
// screen that exists to say when to act.
func TestAVersionStampedBoxIsNotReportedOutOfDateForever(t *testing.T) {
	k := box.KomizoInstall{
		Installed: true,
		Version:   versionText(),
		Stamp:     agent.BuiltStamp(versionText()),
	}
	if s, _ := agentBehind(k, "root@box"); s != "" {
		t.Errorf("a box set up by a source-built komizo of THIS version reads as behind: %q", s)
	}

	// AND THE COMPARISON IS NOT SIMPLY SWITCHED OFF. A version-stamped box on an
	// older version must still be reported -- the stamp abstains, the version does
	// not.
	old := k
	old.Version = "0.0.1"
	if s, _ := agentBehind(old, "root@box"); s == "" {
		t.Error("a version-stamped box on an older komizo was reported as current")
	}

	// AND TWO CONTENT HASHES STILL DISAGREE, or the check has stopped working for
	// the release path it was written for.
	hashed := k
	hashed.Stamp = "0badc0ffee11"
	if s, _ := agentBehind(hashed, "root@box"); s == "" {
		t.Error("a box carrying a different agent was reported as current")
	}
}
