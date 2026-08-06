package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/nicodes/komizo/box"
)

// One app's lifecycle, run ON the box.
//
// komizo-be design/app-only.md §8 states the condition the whole plan depends
// on: the CLI over SSH and a signed command applied by rootd must end in the
// SAME implementation, or parity stops being Go against Go in one process and
// becomes Go against TypeScript across a network.
//
// This is that implementation. `komizo start` runs it over SSH; rootd will run
// it for a verified command. Neither of them knows how to stop an app -- they
// know how to ask this to.
//
// So EVERY value is checked here rather than at either caller. rootd builds its
// arguments from a signed envelope that never passes through the laptop's
// validation, and a check that lives only there protects only the path that
// does not need it.

// logTailMax bounds a log request.
//
// Logs are the only thing here that returns unbounded output, and the caller is
// on the other side of an SSH connection or an HTTPS route. A tail is what this
// is for -- see app-only.md §5, "tail, do not index".
const logTailMax = 2000

// ProxyProject is the compose project the shared proxy runs as.
//
// Named explicitly rather than derived from its directory, because that is what
// alpine-proxy.sh created it as and a project name is how compose finds a
// running stack.
const ProxyProject = "komizo-proxy"

func runApp(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: komizo-box app <start|stop|restart|logs> --app NAME")
	}
	verb := args[0]

	fs := flag.NewFlagSet("app "+verb, flag.ContinueOnError)
	name := fs.String("app", "", "which app")
	proxy := fs.Bool("proxy", false, "the shared proxy, rather than an app")
	tail := fs.Int("tail", 40, "how many log lines")
	svc := fs.String("service", "", "one service in the app, rather than all of them")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q -- every input is a flag", fs.Arg(0))
	}

	// The REQUEST is checked before anything is looked up, so an unknown verb or
	// an unbounded tail is refused on its own terms rather than incidentally, by
	// an app lookup that happened to fail first. That ordering is also what
	// keeps the tests about it honest.
	if !knownVerbs[verb] {
		return fmt.Errorf("%q is not something an app can be told to do", verb)
	}
	if *proxy == (*name != "") {
		return fmt.Errorf("give exactly one of --app and --proxy")
	}
	if *tail < 1 || *tail > logTailMax {
		return fmt.Errorf("--tail must be between 1 and %d", logTailMax)
	}
	if err := validService(*svc); err != nil {
		return err
	}

	// lookupRoot, not "". Empty in production, so this is the same path it has
	// always been; a fixture in tests, which is what lets the SSH route be
	// exercised end to end rather than only from `perform`. The two routes have
	// to be tested through their OWN entry points -- a marker written by one of
	// them says nothing about the other, and komizo#48 was a write that existed
	// in neither.
	sub, err := resolveSubject(lookupRoot, *name, *proxy)
	if err != nil {
		return err
	}

	ctx, stop := signalContext()
	defer stop()
	return runVerb(ctx, verb, sub, *tail, *svc, box.StoppedByCLI)
}

// subject is which stack a verb acts on.
//
// app and root carry what it takes to find the app's RECORD, not just its
// compose file: a deliberate stop is written into AppsDir/<app>.env, and by the
// time runVerb has a directory it has already thrown away the name that names
// the file. app is empty for the shared proxy, which has no record.
type subject struct{ dir, project, app, root string }

// resolveSubject turns a name into a stack, and is the one place that does.
//
// root prefixes the lookup so this is testable without a box, the same seam
// Probe.Root is.
func resolveSubject(root, name string, proxy bool) (subject, error) {
	if proxy {
		return subject{dir: box.ProxyDir, project: ProxyProject}, nil
	}
	dir, err := box.AppDir(root, name)
	if err != nil {
		return subject{}, err
	}
	if err := validDir(dir); err != nil {
		return subject{}, err
	}
	// No project name: compose derives one from the directory, which is what the
	// deploy path does too, so naming one here would resolve to a different
	// stack from the one that was deployed.
	return subject{dir: dir, app: name, root: root}, nil
}

// runVerb is what BOTH triggers end in.
//
// komizo-be design/app-only.md §8: the CLI over SSH and a signed command
// applied by rootd must end in the same implementation, or parity stops being
// Go against Go in one process and becomes Go against TypeScript across a
// network. This function is that promise, kept in one place -- runApp parses
// flags into it, and applyCommand parses a verified envelope into it.
func runVerb(ctx context.Context, verb string, sub subject, tail int, svc, by string) error {
	if verb == "restart" {
		// Restarting nothing succeeds silently, which is the failure paths.go
		// argues against in its own words: a command that "does nothing, and has
		// no reason to say so".
		//
		// It is also why restart never touches the stop marker. `compose ps -q`
		// lists what is RUNNING, so a fully stopped app cannot be restarted at
		// all -- it is refused right here -- and there is no path by which
		// restart brings a deliberately stopped app back up behind the marker's
		// back. Starting it is `start`, and that is where the marker comes off.
		out, err := composeOut(ctx, sub.dir, sub.project, "ps", "-q")
		if err != nil && errors.Is(ctx.Err(), context.Canceled) {
			// THE OPERATOR CANCELLED. Nothing failed and nothing was
			// unanswerable -- signalContext caught SIGINT or SIGTERM, which on
			// the CLI route is somebody pressing Ctrl-C and under rootd is
			// OpenRC stopping the service.
			//
			// Separated from the refusal below because that one ends by telling
			// you to run `start`, and `start` is the one verb that CLEARS the
			// stop marker. Advising it here would answer a cancelled restart by
			// pointing at the command that turns alerting suppression off, for
			// a person who asked for nothing to happen and got exactly that.
			//
			// Canceled SPECIFICALLY, not `ctx.Err() != nil`. Every context that
			// reaches runVerb today comes from signalContext and carries no
			// deadline, so the two are the same thing -- but a caller that
			// later bounds this would make DeadlineExceeded arrive here, and a
			// deadline is not somebody changing their mind. It is the box
			// taking too long to say what is running, which is exactly the
			// answer below.
			return fmt.Errorf("cancelled -- nothing was restarted")
		}
		if err != nil {
			// A QUESTION THAT COULD NOT BE ANSWERED IS NOT A YES.
			//
			// This used to read `if err == nil && strings.TrimSpace(out) == ""`,
			// which skipped the guard entirely whenever the box could not say
			// what was running -- a malformed compose.yml, a daemon that is up
			// but unhealthy, a timeout on the one-minute context -- and fell
			// straight through to the restart. The case where the answer is
			// unavailable is exactly the case where assuming "something is
			// running" is least justified, and the cost of being wrong is
			// komizo#57: an app brought up by a verb that never touches the stop
			// marker, so it runs with STOPPED=1 still set, never pages, and
			// nothing on it says alerting is off.
			//
			// The deploy script makes the OPPOSITE trade with its marker read --
			// an unreadable record starts the app -- and that is not a
			// contradiction. A deploy that refuses on a box whose record cannot
			// be read is a wider failure than the one it prevents, and the
			// script says so out loud. Here there is a narrower answer available
			// and it is one word away: `start` brings the app up whatever state
			// it is in, and takes the marker off on the way. It is not the same
			// operation -- `up -d` recreates on the committed image where
			// `restart` restarts the containers that are there -- which is the
			// point. The verb that can bring an app up is the one that also
			// records that it is meant to be up.
			//
			// The error is carried rather than summarised. Whatever compose said
			// about the compose file or the daemon is the thing the operator
			// needs; komizo#56 made the deploy script print sed's complaint for
			// the same reason.
			return fmt.Errorf("could not tell what is running here, so nothing was restarted -- start it instead if it is down: %w", err)
		}
		if strings.TrimSpace(out) == "" {
			return fmt.Errorf("nothing is running here -- start it instead")
		}
	}

	// marks is whether this call is a decision about the whole app, and so
	// something the box has to write down.
	//
	// --service is deliberately excluded, and this is the conservative half of
	// the rule. Stopping one service out of three is not a decision to stop the
	// app, and a marker written for it would suppress app_down for the other
	// two when they later fail -- a page silently turned off by a command that
	// never claimed to. An app with a single service stopped by name therefore
	// still reports as down, which is the honest reading: nobody said stop the
	// app, they said stop that container, and something ought to say so.
	//
	// The shared proxy is excluded because it has no record to write into. Its
	// own down-ness is diagnosed separately, as proxy_stopped.
	marks := sub.app != "" && svc == "" && (verb == "stop" || verb == "start")

	// AND THE SAME EXCLUSION READ IN THE START DIRECTION IS NOT CONSERVATIVE,
	// which is komizo#66 and the reason this refusal exists.
	//
	// For `stop`, not writing the marker is the safe answer: the app keeps its
	// ability to page. For `start` it inverts. `komizo start --app web --service
	// api` runs `up -d -- api` and never clears the marker, so an operator can
	// bring an app back up service by service and it stays recorded as stopped
	// -- box/diagnose.go keys app_down on !a.Stopped, so it never pages again,
	// for a real outage, indefinitely, with nothing saying alerting is off.
	// That is komizo#57's state reached through a third door, after a deploy
	// under an old script (#56) and the race in #62.
	//
	// The same condition produces the safe answer on one verb and the dangerous
	// one on the other, which is why one comment could not justify both.
	//
	// REFUSED RATHER THAN CLEARED, and #66 lays out the three options. Clearing
	// on any successful `start --service` is defensible and over-broad: starting
	// one service of three does not mean the app is up. Clearing only when
	// `compose ps` says every service is running is more faithful and has to
	// decide what "every service" means, which is a question with no answer here
	// yet. Refusing makes the state impossible rather than transient, costs
	// nothing to reason about, and leaves the faithful version available later
	// without having shipped a guess in between.
	//
	// SCOPED TO AN APP THAT IS ACTUALLY MARKED. `start --service` on an app
	// nobody stopped is an ordinary thing to do -- bringing one container back
	// after it crashed -- and refusing it would be a new obstruction in exchange
	// for nothing. Only the combination is refused.
	if verb == "start" && sub.app != "" && svc != "" {
		stopped, err := box.IsStopped(sub.root, sub.app)
		if err != nil {
			// REFUSED rather than started anyway, for the reason the stop path
			// gives: a box that cannot read its own record cannot tell whether
			// this start would leave a marker stranded, and starting into that
			// is choosing the defect deliberately.
			return fmt.Errorf("could not tell whether %s is recorded as stopped, so nothing was started: %w", sub.app, err)
		}
		if stopped {
			return fmt.Errorf(
				"%s is recorded as stopped, so starting one service would leave it marked stopped while it runs -- "+
					"and an app in that state never pages again. Start the whole app first: komizo start --app %s",
				sub.app, sub.app)
		}
	}

	if verb == "stop" && marks {
		// WRITTEN FIRST, and this ordering is the whole point of the marker.
		//
		// `compose stop` sends SIGTERM and waits out a grace period, so there
		// are seconds during which containers are exiting one by one. rootd
		// re-reports on its own tick throughout. Write the marker afterwards
		// and there is a window where every container has exited and nothing
		// has yet said the stop was deliberate -- which is a real app_down
		// problem, published, for an app somebody stopped on purpose. That is
		// the exact page komizo#48 is about, merely narrowed from forever to a
		// few seconds, and a false page that fires occasionally is worse to
		// live with than one that fires always.
		//
		// The cost of being early is an app marked stopped while it is still
		// shutting down, which suppresses nothing: app_down only fires when no
		// container is running, and they still are.
		if err := box.MarkStopped(sub.root, sub.app, by, time.Now()); err != nil {
			// REFUSED rather than stopped anyway. A box that cannot record the
			// stop is a box that will report this app as broken for as long as
			// it stays down, so stopping it here would be choosing the defect
			// deliberately. This is a local file written by root; failing to
			// write it means something is wrong with the box's state directory
			// and the operator needs to hear that instead of a stopped app.
			return fmt.Errorf("could not record that %s was stopped, so it was left running: %w", sub.app, err)
		}
	}

	if err := compose(ctx, sub.dir, sub.project, composeArgs(verb, tail, svc)...); err != nil {
		if verb == "stop" && marks {
			// The stop did not happen, so the record of it must not survive --
			// otherwise a running app carries a marker that will keep it from
			// paging the day it goes down for real. Best effort, and the
			// compose failure is still what comes back: losing the reason
			// behind a second error would answer a question nobody asked.
			_ = box.ClearStopped(sub.root, sub.app)
		}
		return err
	}

	if verb == "start" && marks {
		// CLEARED LAST, which is the mirror of the argument above rather than a
		// contradiction of it. `up -d` may pull an image over a slow link and
		// take minutes; clearing first would leave an app that is still down,
		// no longer marked stopped, and paging for the whole of it.
		//
		// A start that FAILS therefore leaves the marker on, which is the right
		// answer too: the app is still down, still down on purpose as far as
		// anything can tell, and the person who ran the command saw it fail.
		//
		// The cost of that choice is worth naming rather than leaving implied.
		// A `up -d` that fails PART WAY leaves the marker on with some services
		// running, so those services do not page until somebody starts the app
		// again successfully. The alternative -- clearing on failure -- pages
		// for an app that is deliberately down and stayed down, every time a
		// start fails, which is the noisier half of the same trade and the one
		// that trains people to ignore the alert.
		if err := box.ClearStopped(sub.root, sub.app); err != nil {
			// Said out loud even though the containers are up. An app running
			// while its record still claims a stop is an app that will not page
			// the next time it dies, and that is not something to leave silent.
			return fmt.Errorf("%s was started, but the box still has it recorded as stopped: %w", sub.app, err)
		}
	}
	return nil
}

// composeArgs is the arguments for one verb, and it is a pure function so that
// what this actually runs can be asserted rather than inferred.
//
// `up -d` for start, never `compose start`. A stopped app whose image has since
// been deployed would be brought back on the OLD one, silently -- alpine.sh
// persists APP_VERSION into the app's .env precisely so `up -d` recreates on
// the committed image, and architecture.md §6 makes the same point about why
// stopped is durable state.
//
// And never `down`, which removes the containers and the network rather than
// stopping them.
func composeArgs(verb string, tail int, svc string) []string {
	var a []string
	switch verb {
	case "start":
		a = []string{"up", "-d"}
	case "stop":
		a = []string{"stop"}
	case "restart":
		a = []string{"restart"}
	case "logs":
		a = []string{"logs", "--tail", strconv.Itoa(tail), "--no-color"}
	}
	if svc != "" {
		// After a `--`, so a service name can never be read as a flag of the
		// subcommand it follows. validService already refuses one that looks
		// like a flag; this is the second of the two, because the first is a
		// rule that could later relax.
		a = append(a, "--", svc)
	}
	return a
}

// validService refuses anything that is not a compose service name.
//
// THE FLAG CASE IS THE POINT. Go's flag package takes the next argument as a
// value without caring that it starts with a dash, so `--service -f` would have
// reached `docker compose logs` as `--follow`: unbounded output, blocking until
// the timeout, and logTailMax defeated entirely. `--dry-run` is a persistent
// flag on every compose subcommand, so the same hole would make a stop report
// success and do nothing.
//
// app-only.md §4 says it directly -- an op is a NAME and its args are
// structured, "never a shell string, never a path, never a flag list".
func validService(s string) error {
	if s == "" {
		return nil
	}
	if strings.HasPrefix(s, "-") {
		return fmt.Errorf("%q is not a service name -- it is a flag", s)
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return fmt.Errorf("%q is not a service name", s)
		}
	}
	return nil
}

// validDir refuses a directory that is not one.
//
// Only reachable through a hand-edited record -- validateAppDir guarantees the
// leading slash on the way in -- which is exactly why it is checked here: that
// made the safety of the compose line a fact about another file. Relative, it
// becomes a path relative to whatever this process is in; leading with a dash,
// it becomes a docker flag, and `-H tcp://...` points docker at another daemon.
func validDir(dir string) error {
	if !strings.HasPrefix(dir, "/") {
		return fmt.Errorf("%q is not an absolute directory", dir)
	}
	return nil
}

// knownVerbs is the closed set. app-only.md §4: an op is a NAME, and the box
// maps it to its own arguments -- never a string a caller composed.
var knownVerbs = map[string]bool{"start": true, "stop": true, "restart": true, "logs": true}

// composeTimeout bounds one invocation.
//
// Generous, because `up -d` pulls images on a box that may be on a slow link,
// and the failure of being too short is an app left half started. Bounded at
// all, because this is reached from a route on the internet and a compose that
// never returns is a request that never ends.
const composeTimeout = 10 * time.Minute

// execCompose is a seam. The tests replace it to assert what would have run,
// which is the only way to check that this stays an exec with a slice -- a
// shell here would make every argument a place where a name becomes a command.
var execCompose = exec.CommandContext

// composeBase is the arguments that name WHICH stack, before the verb.
//
// The file and the project directory are BOTH named. Compose infers a project
// name from the directory, and an app whose directory does not match its name
// would otherwise be acted on under a project nothing else uses -- which looks
// exactly like a command that worked and did nothing. It is the same pair
// alpine-remove.sh already uses, so this resolves to the stack the deploy made.
func composeBase(dir, project string) []string {
	a := []string{"compose", "-f", dir + "/compose.yml", "--project-directory", dir}
	if project != "" {
		a = append(a, "-p", project)
	}
	return a
}

func compose(ctx context.Context, dir, project string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, composeTimeout)
	defer cancel()

	cmd := execCompose(ctx, "docker", append(composeBase(dir, project), args...)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker compose %s: %w", args[0], err)
	}
	return nil
}

// composeCapped runs one and captures at most max bytes of it.
//
// Output() buffers without limit, which is fine for the short answers this asks
// itself and is not fine for a log: the caller is root, on a timer, and how long
// a line is belongs to whatever is running in somebody's container.
func composeCapped(ctx context.Context, dir, project string, max int, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, composeTimeout)
	defer cancel()

	cmd := execCompose(ctx, "docker", append(composeBase(dir, project), args...)...)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	b, readErr := io.ReadAll(io.LimitReader(pipe, int64(max)))
	// Drained to the limit and then closed, so a process still writing gets a
	// broken pipe rather than blocking this one forever.
	_ = pipe.Close()
	waitErr := cmd.Wait()
	if readErr != nil {
		return string(b), readErr
	}
	return string(b), waitErr
}

// composeOut runs one and captures it, for the questions this asks itself.
//
// THE COMPLAINT COMES BACK TOO, not just the exit status. Output() puts stderr
// on the ExitError and never prints it -- `%w` on one renders "exit status 1"
// and nothing else. runVerb turns a failure here into a refusal to restart, and
// a refusal whose only stated reason is a number is a refusal nobody can act
// on: the thing the operator needs is compose saying which line of compose.yml
// it could not read, or that it cannot reach the daemon.
//
// Unlike compose(), this cannot simply hand stderr to os.Stderr -- Output()
// requires it -- so it is folded into the error instead. That also carries it
// to the signed route, where an error becomes a result the app reads;
// compose()'s stderr goes to this process's, which there is rootd's log and so
// reaches nobody who is waiting for an answer.
//
// WHICH IS A BOUNDARY, and it is worth naming rather than leaving to be
// discovered. On the signed route this text becomes res.Detail, which
// WriteResult puts under ServedDir for the agent account to read and post, so
// it leaves the box. Before this it stopped at rootd's log. What is carried is
// docker's own diagnostics about a compose file, which is not a secret --
// but `compose ps -q` parses compose.yml and interpolates .env, both of which
// sit beside a 0600 secrets.env, and what compose chooses to quote back in a
// parse error is docker's decision rather than komizo's. The trade is taken
// deliberately: a refusal whose reason nobody can see is a refusal that gets
// worked around, and the alternative is an operator staring at "exit status 1".
// If that ever stops being the right call, this is the line to change.
//
// BOUNDED BY lastLines, the same rule runProvision already applies for the same
// reason, rather than a second bound written here. Both are "something else's
// output, on its way into a result file somebody downloads", and how long
// docker's stderr is belongs to docker. The tail is what survives, because that
// is where a program says why it stopped.
func composeOut(ctx context.Context, dir, project string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	out, err := execCompose(ctx, "docker", append(composeBase(dir, project), args...)...).Output()
	var ee *exec.ExitError
	if errors.As(err, &ee) && strings.TrimSpace(string(ee.Stderr)) != "" {
		err = fmt.Errorf("%w: %s", err, lastLines(string(ee.Stderr), 12))
	}
	return string(out), err
}
