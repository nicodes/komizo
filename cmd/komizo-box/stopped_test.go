package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/box"
)

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
	res, found := box.ReadResult(results, id)
	if !found || !res.OK {
		t.Fatalf("the signed %s was not applied: %+v", op, res)
	}
	return box.StoppedByDevice(pub)
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
