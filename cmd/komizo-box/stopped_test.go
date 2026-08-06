package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/box"
)

// stoppedLine is the marker as it appears in the file, written out by hand.
//
// A LITERAL, not box's own constant. The constants in box/stopped.go exist so
// that the writer and the reader cannot drift apart; a test that reused them
// would drift with them, and rename the key on both sides in silence. This is
// the string probe.go, the provisioning script and a person with `cat` all
// look for, so it is spelled the way they spell it.
//
// Leading newline so it cannot match a longer key ending in STOPPED. The
// managed keys are appended at the end of the record and never first, so there
// is always a newline in front of this one.
const stoppedLine = "\nSTOPPED=1"

// A stop has to be WRITTEN, and read back by the thing that diagnoses the box.
//
// komizo#48. probe.go, diagnose.go, report_cmd.go and komizo-be's
// appsFromReport all read STOPPED out of an app's record, and nothing anywhere
// in the repository wrote it -- four readers, no writer. It survived a release
// because every test that read the field also created the file by hand, so
// every one of them passed against a box where `komizo stop` left no trace: the
// app went down, the report called it app_down, and it stayed a problem for as
// long as it stayed stopped.
//
// So nothing in this file writes a marker. Each subtest runs the stop the way a
// person does, through the entry point of one of the two routes that reach a
// box, and then asks the REPORT what happened -- probe.go's own parse and
// diagnose.go's own rule. Remove the write and both fail; write it on one route
// only, which is the shape app-only.md §9 forbids, and the other one fails.
func TestAStopIsRecordedWhereTheReportReadsIt(t *testing.T) {
	for _, r := range routes() {
		t.Run(r.name, func(t *testing.T) {
			captureCompose(t)
			f := stoppedFixture(t)

			var by string
			withRoot(t, f.root, func() { by = r.stop(t, "web") })

			a := f.app(t)
			if !a.Stopped {
				t.Fatalf("the report does not know %s was stopped: %+v", a.Name, a)
			}
			if a.StoppedBy != by {
				t.Errorf("stopped_by = %q, want %q", a.StoppedBy, by)
			}
			if d := time.Since(a.StoppedAt); d < 0 || d > time.Hour {
				t.Errorf("stopped_at = %v, which is not now", a.StoppedAt)
			}

			// AND IT NO LONGER PAGES, which is the whole point of recording it.
			// The app has a container and none of it is running -- the exact
			// shape app_down fires on -- so this assertion is only satisfiable
			// by the marker having been written and read.
			for _, p := range f.report(t).Problems {
				if p.Kind == box.ProblemAppDown {
					t.Errorf("a deliberate stop is still a problem: %q", p.Detail)
				}
			}
		})
	}
}

// And starting it again takes the marker off.
//
// The inverse matters as much: a marker that is never cleared is an app that
// has stopped paging permanently, which is a worse failure than the one this
// fixes because nothing about it is visible until the day it is needed.
func TestStartingAnAppTakesTheMarkerOff(t *testing.T) {
	for _, r := range routes() {
		t.Run(r.name, func(t *testing.T) {
			captureCompose(t)
			f := stoppedFixture(t)

			withRoot(t, f.root, func() {
				r.stop(t, "web")
				r.start(t, "web")
			})

			if a := f.app(t); a.Stopped || a.StoppedBy != "" || !a.StoppedAt.IsZero() {
				t.Errorf("a started app still carries a stop: %+v", a)
			}
			// Read back through the report rather than by parsing the file,
			// because "cleared" has to mean cleared to the READER: a STOPPED_BY
			// left behind on its own would be invisible to a test that only
			// checked STOPPED.
		})
	}
}

// A stop that did not happen must not be recorded as one.
//
// The marker is written BEFORE compose runs, so that a stop in progress cannot
// be reported as a fault while it is happening -- see runVerb. That ordering is
// only safe if a compose that fails takes the marker back off, and the failure
// it prevents is an app which is running, is recorded as stopped, and will
// therefore never page when it does go down.
func TestAStopThatFailedIsNotRecorded(t *testing.T) {
	orig := execCompose
	execCompose = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "false")
	}
	t.Cleanup(func() { execCompose = orig })

	f := stoppedFixture(t)
	var err error
	withRoot(t, f.root, func() { err = runApp([]string{"stop", "--app", "web"}) })
	if err == nil {
		t.Fatal("a compose that exited non-zero was reported as a successful stop")
	}
	if a := f.app(t); a.Stopped {
		t.Errorf("a stop that failed was recorded anyway: %+v", a)
	}
}

// The marker is on the record BEFORE compose is told to stop anything.
//
// This is the central design claim of the whole change, and until this test it
// was the one thing with nothing behind it: moving box.MarkStopped from before
// the compose call to after a SUCCESSFUL one left every other test in this file
// green. TestAStopThatFailedIsNotRecorded does not catch it, because it only
// inspects the end state, and the end state of the two orderings is identical.
//
// The failure the ordering prevents is a window, not a wrong answer. `compose
// stop` sends SIGTERM and waits out a grace period, so there are seconds in
// which containers exit one by one while the box keeps reporting on its own
// tick. Write the marker after that returns and there is an interval where
// every container has exited and nothing yet says the stop was deliberate --
// which is a real app_down problem, published to the registry and paged on, for
// an app somebody stopped on purpose. That is komizo#48 again, narrowed from
// forever to a few seconds, and an alert that fires occasionally is worse to
// live with than one that fires every time: it teaches people to ignore it.
//
// Asserted at the moment compose is invoked, because that is the only place the
// ordering is observable at all. Both routes, because runVerb is reached from
// each of them and app-only.md §9 does not let a guarantee exist on one.
func TestTheStopIsOnTheRecordBeforeTheContainersAreToldToGo(t *testing.T) {
	for _, r := range routes() {
		t.Run(r.name, func(t *testing.T) {
			f := stoppedFixture(t)
			seen := recordAtCompose(t, f.root, "web")

			withRoot(t, f.root, func() { r.stop(t, "web") })

			// Nothing reached docker means the assertion below has no subject,
			// and a loop over an empty slice passes. The stop is supposed to
			// stop something.
			if len(*seen) == 0 {
				t.Fatal("nothing reached docker, so there was no moment to observe the record at")
			}
			for i, rec := range *seen {
				if !strings.Contains(rec, stoppedLine) {
					t.Errorf("docker call %d ran while the record still read:\n%s", i, rec)
				}
			}
		})
	}
}

// And it stays on the record until the app is actually back UP.
//
// The mirror of the rule above, and the reason `start` clears LAST rather than
// first. `up -d` may pull an image over a slow link and take minutes; clear the
// marker before that and the app is down, no longer recorded as deliberately
// down, and paging for the whole of it -- the same false page as above, from
// the other end and lasting longer.
//
// Untested, this ordering is as invisible as the stop one was: clearing first
// and clearing last leave the same file behind.
func TestTheMarkerStaysOnUntilTheAppIsBackUp(t *testing.T) {
	for _, r := range routes() {
		t.Run(r.name, func(t *testing.T) {
			f := stoppedFixture(t)
			captureCompose(t)
			withRoot(t, f.root, func() { r.stop(t, "web") })

			seen := recordAtCompose(t, f.root, "web")
			withRoot(t, f.root, func() { r.start(t, "web") })

			if len(*seen) == 0 {
				t.Fatal("nothing reached docker, so the app was never asked to start")
			}
			for i, rec := range *seen {
				if !strings.Contains(rec, stoppedLine) {
					t.Errorf("docker call %d ran with the stop already taken off:\n%s", i, rec)
				}
			}
			// And once it is up, it is gone -- otherwise this test would pass
			// against a start that never cleared the marker at all.
			if a := f.app(t); a.Stopped {
				t.Errorf("the app came up still recorded as stopped: %+v", a)
			}
		})
	}
}

// recordAtCompose captures the app's record as it stood at each docker call.
//
// The exec seam is the clock here. Reading the file after runVerb returns can
// only ever see the end state, which both orderings agree on; reading it from
// inside the stub reads it at the one instant that distinguishes them.
//
// Bytes rather than a parse, so what is asserted is what a reader on the box
// would actually find in the file at that moment.
func recordAtCompose(t *testing.T, root, app string) *[]string {
	t.Helper()
	var seen []string
	orig := execCompose
	execCompose = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		b, err := os.ReadFile(filepath.Join(root, box.AppsDir, app+".env"))
		if err != nil {
			// Not fatal from a goroutine-safe distance -- recorded, so the
			// assertion sees an empty record and says so with the same message.
			seen = append(seen, "<unreadable: "+err.Error()+">")
		} else {
			seen = append(seen, string(b))
		}
		return exec.CommandContext(ctx, "true")
	}
	t.Cleanup(func() { execCompose = orig })
	return &seen
}

// Stopping ONE SERVICE is not a decision to stop the app.
//
// The conservative half of the rule in runVerb. An app whose other services are
// still expected to run must keep its ability to page for them, and a marker
// written here would switch that off on behalf of somebody who only ever named
// one container.
func TestStoppingOneServiceDoesNotStopTheApp(t *testing.T) {
	captureCompose(t)
	f := stoppedFixture(t)

	withRoot(t, f.root, func() {
		if err := runApp([]string{"stop", "--app", "web", "--service", "sidecar"}); err != nil {
			t.Fatalf("stop --service = %v", err)
		}
	})
	if a := f.app(t); a.Stopped {
		t.Errorf("stopping one service recorded the whole app as stopped: %+v", a)
	}
}

// The shared proxy has no record, and asking for one would be a lookup for a
// file that has never existed. Its own down-ness is diagnosed as proxy_stopped.
func TestStoppingTheProxyRecordsNothing(t *testing.T) {
	captureCompose(t)
	f := stoppedFixture(t)

	withRoot(t, f.root, func() {
		if err := runApp([]string{"stop", "--proxy"}); err != nil {
			t.Fatalf("stop --proxy = %v", err)
		}
	})
	if a := f.app(t); a.Stopped {
		t.Errorf("stopping the proxy recorded an app as stopped: %+v", a)
	}
}

// route is one of the two ways an instruction reaches a box.
//
// BOTH, ALWAYS. komizo-be design/app-only.md §9 keeps the CLI entire, so a
// capability that exists on one of these and not the other is a capability that
// disappears with whichever half somebody deletes. Each entry drives its route
// from its OWN entry point -- runApp is what `komizo stop` pipes over SSH,
// applyPending is what rootd runs against its inbox -- rather than from the
// shared function underneath them, because what is being tested is that both
// arrive there carrying who asked.
type route struct {
	name string
	// stop and start return who the box should have recorded it for.
	stop  func(t *testing.T, app string) string
	start func(t *testing.T, app string) string
}

func routes() []route {
	return []route{{
		name: "over ssh",
		// `komizo stop --host HOST --app web` becomes `komizo-box app stop
		// --app web`, piped over the SSH connection -- see
		// internal/app/lifecycle.go's boxCmd. This is that line.
		stop:  func(t *testing.T, app string) string { return runAppOK(t, "stop", app) },
		start: func(t *testing.T, app string) string { return runAppOK(t, "start", app) },
	}, {
		name:  "signed",
		stop:  func(t *testing.T, app string) string { return applyOK(t, box.OpAppStop, app) },
		start: func(t *testing.T, app string) string { return applyOK(t, box.OpAppStart, app) },
	}}
}

func runAppOK(t *testing.T, verb, app string) string {
	t.Helper()
	if err := runApp([]string{verb, "--app", app}); err != nil {
		t.Fatalf("komizo-box app %s --app %s = %v", verb, app, err)
	}
	return box.StoppedByCLI
}

// applyOK signs a command, drops it in an inbox and lets rootd find it.
//
// The whole applier, not perform: which device asked is established by
// VerifyCommand inside applyOne, and a test that called perform with an
// identity it made up itself would keep passing if that plumbing were removed.
func applyOK(t *testing.T, op, app string) string {
	t.Helper()
	pub, priv := device(t)
	id, err := box.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	inbox, results := t.TempDir(), t.TempDir()
	drop(t, inbox, priv, box.Command{ID: id, Srv: "srv_mine", Op: op,
		Exp:  time.Now().Add(time.Minute).Unix(),
		Args: map[string]string{"app": app}})

	applyPending(context.Background(), box.AgentConf{ServerID: "srv_mine",
		OperatorKeys: []string{box.FormatDeviceKey(pub)}}, inbox, results)

	// The result, read back. applyPending returns nothing and logs its
	// refusals, so a command rejected before it reached the machine would
	// otherwise leave every assertion downstream measuring an app that nothing
	// ever touched -- which passes, silently, for the wrong reason.
	res, found, err := box.ReadResult(results, id)
	// The third answer matters here as much as at the route. A result this box
	// wrote and cannot read back is not "not applied yet" -- komizo#53 -- and a
	// test that folded it into `!found` would report the interesting failure as
	// the boring one.
	if err != nil {
		t.Fatalf("the result of the signed %s could not be read: %v", op, err)
	}
	if !found || !res.OK {
		t.Fatalf("the signed %s was not applied: %+v", op, res)
	}

	// THE IDENTITY IS SPELLED OUT HERE, not asked for.
	//
	// This line used to read `return box.StoppedByDevice(pub)`, which made the
	// assertion downstream compare the function under test against itself. The
	// consequence was not theoretical: `func StoppedByDevice(pub) string {
	// return "" }` left the ENTIRE SUITE GREEN. An empty value is removed by
	// setStateValues rather than written, probe.go then leaves StoppedBy empty,
	// and both sides of the comparison read "" -- a test agreeing with a
	// mutation instead of catching it.
	//
	// And the state that mutation produces is the one thing StoppedByDevice's
	// own comment says must never exist: STOPPED=1 with no STOPPED_BY, which
	// omitempty renders as "a stop nobody made". The single fact this route
	// exists to establish -- that the box records WHICH VERIFIED DEVICE asked,
	// because revoking one later means knowing that -- had no test behind it.
	//
	// So the expectation is built from the key by hand, in the shape a person
	// reading the report sees: the literal "device ", then the first and last
	// eight characters of the key as it is carried. It duplicates
	// Fingerprint's rule on purpose. Changing how a device is rendered now has
	// to be done twice, deliberately, and cannot be done by accident at all.
	body := b64url(pub)
	return "device " + body[:8] + "…" + body[len(body)-8:]
}

// stoppedFixture is a box with one app on it, deployed and not running.
//
// The container is EXITED and there is exactly one, which is the state
// `compose stop` leaves behind and the exact shape diagnose.go fires app_down
// on. An app with no containers, or one still running, would satisfy the
// app_down assertion without the marker existing at all -- so the fixture is
// the part that makes that assertion mean something.
type fixture struct {
	root  string
	probe *box.Probe
}

func stoppedFixture(t *testing.T) fixture {
	t.Helper()
	root := appFixture(t, "web", "/srv/web")
	return fixture{root: root, probe: &box.Probe{
		Root: root,
		// The working_dir docker reports is UNPREFIXED even though Root is set:
		// Root is a fiction for the filesystem, and a real box reports the same
		// absolute path the app's record holds as APP_DIR. That equality is
		// what joins a container to its app.
		Docker: func(_ context.Context, args ...string) (string, error) {
			joined := strings.Join(args, " ")
			switch {
			case strings.Contains(joined, "--version"):
				return "Docker version 29.1.3, build f52814d", nil
			case strings.HasPrefix(joined, "info"):
				return "29.1.3", nil
			case strings.HasPrefix(joined, "ps -a"):
				return "cid1\tweb-web-1\texited\tExited (0) 2 seconds ago\tweb\tghcr.io/n/web:abc123\t/srv/web", nil
			case strings.HasPrefix(joined, "inspect"):
				return "cid1\t2026-08-05T09:00:00Z\t2026-08-05T10:00:00Z\t0\t0\t\t", nil
			}
			return "", fmt.Errorf("no docker reply for %q", joined)
		},
	}}
}

func (f fixture) report(t *testing.T) box.Report {
	t.Helper()
	r := f.probe.Report(context.Background())
	if !r.Server.Ready() {
		t.Fatalf("the fixture box is %q, so nothing below was read", r.Server.State)
	}
	return r
}

func (f fixture) app(t *testing.T) box.App {
	t.Helper()
	r := f.report(t)
	if len(r.Apps) != 1 {
		t.Fatalf("apps = %d, want 1", len(r.Apps))
	}
	return r.Apps[0]
}

// RESTART IS NOT A SECOND WAY TO START A STOPPED APP.
//
// komizo#54 is about the deploy script starting an app somebody stopped. The
// deploy is not the only thing on a box that can bring containers up, and
// `restart` is the closest neighbour: `docker compose restart` on exited
// containers starts them, and `marks` in runVerb deliberately excludes restart
// from the verbs that touch the marker. So a restart that reached compose on a
// fully stopped app would start it with STOPPED=1 still on the record -- the
// exact state komizo#57 describes, where the app runs, never pages, and nothing
// says alerting is off.
//
// runVerb already refuses it, by asking `compose ps -q` what is running and
// stopping there when the answer is nothing. NOTHING PINNED THAT. Deleting the
// refusal left the whole suite green, so the one guard standing between
// `restart` and a silently un-paged app was held up by a comment.
//
// Both directions are asserted. Refusing every restart would also pass a test
// that only checked the refusal, and would break the verb for everybody.
func TestRestartWillNotStartAnAppThatIsFullyStopped(t *testing.T) {
	f := stoppedFixture(t)

	// `true` produces no output, which is what `compose ps -q` looks like when
	// nothing is running.
	runs := captureCompose(t)
	var err error
	withRoot(t, f.root, func() { err = runApp([]string{"restart", "--app", "web"}) })

	if err == nil {
		t.Error("restart succeeded against an app with nothing running, so a stopped app can be brought up by a verb that never touches the marker")
	}
	for _, r := range *runs {
		for _, a := range r {
			if a == "restart" || a == "start" || a == "up" {
				t.Errorf("restart reached docker with %q despite nothing running: %v", a, r)
			}
		}
	}
}

// The other direction: an app that IS running restarts normally.
//
// Without this, the test above is satisfied by a `restart` that refuses
// everything -- which would pass, read as careful, and quietly remove the verb.
func TestRestartStillWorksWhenSomethingIsRunning(t *testing.T) {
	f := stoppedFixture(t)

	var runs [][]string
	orig := execCompose
	execCompose = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		runs = append(runs, append([]string{name}, args...))
		// `ps -q` answers with a container id, so the app is running.
		for i, a := range args {
			if a == "ps" && i+1 < len(args) && args[i+1] == "-q" {
				return exec.CommandContext(ctx, "echo", "c0ffee")
			}
		}
		return exec.CommandContext(ctx, "true")
	}
	t.Cleanup(func() { execCompose = orig })

	var err error
	withRoot(t, f.root, func() { err = runApp([]string{"restart", "--app", "web"}) })
	if err != nil {
		t.Fatalf("restart against a running app = %v", err)
	}
	restarted := false
	for _, r := range runs {
		for _, a := range r {
			if a == "restart" {
				restarted = true
			}
		}
	}
	if !restarted {
		t.Errorf("restart never reached docker for a running app: %v", runs)
	}
}

// Starting one service of a stopped app is refused, rather than leaving the app
// running and still recorded as stopped.
//
// komizo#66. `marks` excludes --service, which is the conservative choice for
// `stop` -- stopping one container is not a decision to stop the app, and a
// marker written for it would suppress app_down for the services still up. Read
// in the START direction the same exclusion inverts: `start --app web --service
// api` brings a container up and never clears the marker, so an operator can
// restore an app service by service and it stays recorded as stopped. app_down
// keys on that marker, so it never pages again -- for a real outage,
// indefinitely, with nothing saying alerting is off.
//
// Refused rather than cleared, which is #66's option 3: clearing on any
// `start --service` is over-broad, and clearing only when every service is up
// needs a definition of "every service" this box does not have yet. Refusing
// makes the state impossible rather than transient.
func TestStartingOneServiceOfAStoppedAppIsRefused(t *testing.T) {
	runs := captureCompose(t)
	f := stoppedFixture(t)

	withRoot(t, f.root, func() {
		if err := runApp([]string{"stop", "--app", "web"}); err != nil {
			t.Fatalf("stop --app = %v", err)
		}
	})
	// A POSITIVE CONTROL. Everything below is about an app that IS marked, and
	// an unmarked one would take the allowed path and pass for the wrong reason.
	if a := f.app(t); !a.Stopped {
		t.Fatalf("the fixture is not recorded as stopped, so this proves nothing: %+v", a)
	}

	var err error
	withRoot(t, f.root, func() { err = runApp([]string{"start", "--app", "web", "--service", "api"}) })
	if err == nil {
		t.Fatal("start --service on a stopped app was allowed: it would run the container and leave the app " +
			"recorded as stopped, which is an app that can never page again")
	}
	// AND THE MESSAGE NAMES THE WAY OUT. A refusal that does not say what to run
	// instead is a wall, and the operator's next move is to reach for something
	// that does work -- which here is the per-service start they just tried.
	if !strings.Contains(err.Error(), "komizo start --app web") {
		t.Errorf("the refusal does not name the command that works: %v", err)
	}

	// AND NOTHING RAN. The refusal has to happen before compose, or the
	// container is up and only the exit status says otherwise.
	for _, c := range *runs {
		if strings.Contains(strings.Join(c, " "), " up") {
			t.Errorf("the refusal came after compose had already started something: %v", *runs)
		}
	}
}

// And the same command on an app nobody stopped is ordinary and still works.
//
// The refusal above is scoped to the combination. Bringing one container back
// after it crashed is a normal thing to do, and refusing it would be a new
// obstruction bought for nothing.
func TestStartingOneServiceOfARunningAppIsAllowed(t *testing.T) {
	captureCompose(t)
	f := stoppedFixture(t)

	if a := f.app(t); a.Stopped {
		t.Fatalf("the fixture starts out stopped, so this proves nothing: %+v", a)
	}
	withRoot(t, f.root, func() {
		if err := runApp([]string{"start", "--app", "web", "--service", "api"}); err != nil {
			t.Fatalf("start --service on an app nobody stopped was refused: %v", err)
		}
	})
}
