package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/box"
)

// RESTART ASKS WHAT IS RUNNING, AND AN UNANSWERED QUESTION IS NOT A YES.
//
// komizo#61. The guard in runVerb is the only thing standing between `restart`
// and komizo#57: `docker compose restart` starts exited containers, and `marks`
// deliberately excludes restart from the verbs that touch the stop marker, so a
// restart that got through on a deliberately stopped app leaves it running with
// STOPPED=1 still set -- up, never paging, and nothing anywhere saying alerting
// is off for it.
//
// The guard used to read
//
//	if out, err := composeOut(...); err == nil && strings.TrimSpace(out) == ""
//
// so the `err == nil` skipped it whenever the box could not say what was
// running. A malformed compose.yml, a daemon that is up but unhealthy, a
// timeout on the one-minute context: every one of them fell through to the
// restart, as root, on somebody's server. That is the case where assuming
// "something is running" is least justified, not most.
//
// All THREE answers to that one question are pinned here, in one table, because
// the refusals and the permission hold each other up. A test that only checked
// the refusals is satisfied by a `restart` that refuses everything -- which
// would read as careful and quietly remove the verb -- and a test that only
// checked the permission is satisfied by no guard at all, which is the bug.
//
// Both routes, always. komizo-be design/app-only.md §9: runVerb is reached from
// the SSH pipe and from a signed envelope, and a guarantee that exists on one
// of them is a guarantee that disappears with whichever half somebody deletes.
func TestRestartActsOnlyWhenTheBoxCanSaySomethingIsRunning(t *testing.T) {
	for _, c := range []struct {
		name string
		// ps is what `compose ps -q` does when it is asked.
		ps func(ctx context.Context) *exec.Cmd
		// restarts is whether compose should be told to restart anything.
		restarts bool
		// wants is what the refusal has to say, so an operator reading it knows
		// which of the two refusals they hit and what to do instead.
		wants []string
	}{{
		// The case komizo#61 is about, and the one nothing covered. `ps -q`
		// exits non-zero with a complaint on stderr -- what compose does when
		// the app's compose.yml will not parse, which is a file the operator
		// can edit and a state the daemon is perfectly happy in, so `restart`
		// still works and this window is genuinely reachable.
		name: "the box cannot say",
		ps: func(ctx context.Context) *exec.Cmd {
			return exec.CommandContext(ctx, "sh", "-c",
				`printf '%s\n' "validating /srv/web/compose.yml: services.web Additional property buidl is not allowed" >&2; exit 15`)
		},
		restarts: false,
		wants: []string{
			"could not tell what is running",
			// The instruction. `start` does the same thing AND clears the
			// marker, so the refusal is not a dead end.
			"start it instead",
			// AND DOCKER'S OWN COMPLAINT. Output() hangs stderr off the
			// ExitError and `%w` prints "exit status 15" alone, so without
			// composeOut folding it in, the operator is told a number about a
			// file they could have fixed in a second.
			"Additional property buidl is not allowed",
		},
	}, {
		// The answer the guard was written for: nothing running at all.
		name:     "nothing is running",
		ps:       func(ctx context.Context) *exec.Cmd { return exec.CommandContext(ctx, "true") },
		restarts: false,
		wants:    []string{"nothing is running here", "start it instead"},
	}, {
		// And the other direction, without which the two above are satisfied by
		// a verb that refuses everything.
		name: "something is running",
		ps: func(ctx context.Context) *exec.Cmd {
			return exec.CommandContext(ctx, "echo", "c0ffeec0ffee")
		},
		restarts: true,
	}} {
		for _, r := range restartRoutes() {
			t.Run(c.name+"/"+r.name, func(t *testing.T) {
				root := appFixture(t, "web", "/srv/web")
				runs := composeReplies(t, func(ctx context.Context, args []string) *exec.Cmd {
					if isPsQuery(args) {
						return c.ps(ctx)
					}
					return exec.CommandContext(ctx, "true")
				})

				var err error
				withRoot(t, root, func() { err = r.restart(t, "web") })

				// The question was asked at all. Without this, a guard deleted
				// outright would leave `restarts: true` passing and both
				// refusals failing for a reason nobody could read.
				if !sawPsQuery(*runs) {
					t.Fatalf("restart never asked what is running: %v", *runs)
				}

				if got := reachedDocker(*runs, "restart"); got != c.restarts {
					t.Errorf("compose restart reached docker = %v, want %v: %v", got, c.restarts, *runs)
				}
				if !c.restarts {
					if err == nil {
						t.Fatalf("restart succeeded, so a stopped app can be brought up by the one verb that never touches the stop marker")
					}
					for _, w := range c.wants {
						if !strings.Contains(err.Error(), w) {
							t.Errorf("the refusal does not mention %q:\n%v", w, err)
						}
					}
					return
				}
				if err != nil {
					t.Errorf("restart against a running app = %v", err)
				}
			})
		}
	}
}

// A restart that was refused must not have written anything down.
//
// `marks` excludes restart from the verbs that touch the marker, which is the
// property that makes the refusal necessary in the first place -- so a refusal
// that somehow recorded a stop would be a worse bug than the one being fixed:
// an app still running, recorded as deliberately down, and silent the day it
// dies for real. Cheap to assert and it pins the exclusion from the other side.
func TestARefusedRestartLeavesTheRecordAlone(t *testing.T) {
	root := appFixture(t, "web", "/srv/web")
	before := recordOf(t, root, "web")

	composeReplies(t, func(ctx context.Context, args []string) *exec.Cmd {
		if isPsQuery(args) {
			return exec.CommandContext(ctx, "false")
		}
		return exec.CommandContext(ctx, "true")
	})

	var err error
	withRoot(t, root, func() { err = runApp([]string{"restart", "--app", "web"}) })
	if err == nil {
		t.Fatal("the restart was not refused, so this test is measuring nothing")
	}
	if after := recordOf(t, root, "web"); after != before {
		t.Errorf("a refused restart rewrote the app's record:\n%s\nwant\n%s", after, before)
	}
}

// restartRoute is one of the two ways `restart` reaches runVerb.
//
// Driven from each route's OWN entry point -- runApp is the line `komizo
// restart` pipes over SSH, applyPending is what rootd runs against its inbox --
// rather than from runVerb underneath them, because a guard reached by only one
// of them is exactly the shape app-only.md §9 forbids.
//
// Kept here rather than added to routes() in stopped_test.go: that type carries
// a stop and a start, which return WHO the box recorded, and restart records
// nobody. What matters about a restart is whether it was refused.
type restartRoute struct {
	name    string
	restart func(t *testing.T, app string) error
}

func restartRoutes() []restartRoute {
	return []restartRoute{{
		name: "over ssh",
		restart: func(t *testing.T, app string) error {
			return runApp([]string{"restart", "--app", app})
		},
	}, {
		name:    "signed",
		restart: signedRestart,
	}}
}

// signedRestart signs an app.restart, drops it in an inbox and lets rootd find
// it, then reads the result back as its error.
//
// The whole applier rather than perform(), for the reason applyOK gives: the
// verification is part of what carries a command to runVerb, and a test that
// called perform directly would keep passing if that plumbing were removed.
//
// The refusal has to survive the round trip INTACT. rootd's answer to a device
// is the result file, so a refusal that reaches the box's log and not the
// result is, to the person who pressed the button, a restart that did nothing
// and said nothing.
func signedRestart(t *testing.T, app string) error {
	t.Helper()
	pub, priv := device(t)
	id, err := box.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	inbox, results := t.TempDir(), t.TempDir()
	drop(t, inbox, priv, box.Command{ID: id, Srv: "srv_mine", Op: box.OpAppRestart,
		Exp:  time.Now().Add(time.Minute).Unix(),
		Args: map[string]string{"app": app}})

	applyPending(context.Background(), box.AgentConf{ServerID: "srv_mine",
		OperatorKeys: []string{box.FormatDeviceKey(pub)}}, inbox, results)

	res, found, err := box.ReadResult(results, id)
	// A result this box wrote and cannot read back is not "not applied yet" --
	// komizo#53 -- and folding it into !found would report the interesting
	// failure as the boring one.
	if err != nil {
		t.Fatalf("the result of the signed restart could not be read: %v", err)
	}
	if !found {
		t.Fatalf("the signed restart produced no result at all, so it never reached the machine")
	}
	if res.OK {
		return nil
	}
	// Detail is the whole of what a device is told, so it is what the
	// assertions upstream read. If the reason were dropped on the way into the
	// result, this route would report a bare failure and the text checks would
	// catch that too.
	return errRestartRefused(res.Detail)
}

type errRestartRefused string

func (e errRestartRefused) Error() string { return string(e) }

// composeReplies replaces the exec seam with a decision made per invocation, and
// records every call.
//
// captureCompose in apply_test.go answers `true` to everything, and
// stubCompose in collect_test.go answers one fixed thing to everything; neither, which cannot
// express the case this file exists for: a `ps -q` that FAILS while `restart`
// itself still works. That combination is the reachable window komizo#61
// describes -- if the daemon were down, the restart would fail anyway -- so a
// stub that cannot produce it cannot test it.
func composeReplies(t *testing.T, reply func(ctx context.Context, args []string) *exec.Cmd) *[][]string {
	t.Helper()
	var runs [][]string
	orig := execCompose
	execCompose = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		runs = append(runs, append([]string{name}, args...))
		return reply(ctx, args)
	}
	t.Cleanup(func() { execCompose = orig })
	return &runs
}

// isPsQuery is `ps` immediately followed by `-q`, which is the one question
// runVerb asks itself.
//
// The pair rather than either word alone: `-q` is a flag on other subcommands
// and `ps` without it prints a table, so matching one of them would make this
// stub answer a question that was never asked.
func isPsQuery(args []string) bool {
	for i, a := range args {
		if a == "ps" && i+1 < len(args) && args[i+1] == "-q" {
			return true
		}
	}
	return false
}

func sawPsQuery(runs [][]string) bool {
	for _, r := range runs {
		if isPsQuery(r) {
			return true
		}
	}
	return false
}

// reachedDocker is whether any invocation carried verb as its own argument.
//
// Compared word by word rather than against a joined string, so a directory or
// a project name that happens to contain the verb cannot read as one.
func reachedDocker(runs [][]string, verb string) bool {
	for _, r := range runs {
		// composeBase's own arguments come first and none of them is a verb;
		// the verb is whatever composeArgs put after them.
		for _, a := range r {
			if a == verb {
				return true
			}
		}
	}
	return false
}

// recordOf is the app's record exactly as a reader on the box would find it.
//
// Bytes, not a parse: what is being asserted is that nothing wrote to the file,
// and a parse would forgive a key reordered or a value rewritten to the same
// thing.
func recordOf(t *testing.T, root, app string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, box.AppsDir, app+".env"))
	if err != nil {
		t.Fatalf("the fixture's record for %s is unreadable: %v", app, err)
	}
	return string(b)
}
