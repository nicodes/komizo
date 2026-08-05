package main

import (
	"context"
	"flag"
	"fmt"
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

	dir, project := box.ProxyDir, ProxyProject
	if !*proxy {
		var err error
		if dir, err = box.AppDir("", *name); err != nil {
			return err
		}
		// Compose derives a project from the directory, which is what the deploy
		// path does too, so naming one here would resolve to a different stack.
		project = ""
	}
	if err := validDir(dir); err != nil {
		return err
	}

	ctx, stop := signalContext()
	defer stop()

	if verb == "restart" {
		// Restarting nothing succeeds silently, which is the failure paths.go
		// argues against in its own words: a command that "does nothing, and has
		// no reason to say so".
		if out, err := composeOut(ctx, dir, project, "ps", "-q"); err == nil && strings.TrimSpace(out) == "" {
			return fmt.Errorf("nothing is running here -- start it instead")
		}
	}
	return compose(ctx, dir, project, composeArgs(verb, *tail, *svc)...)
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

// composeOut runs one and captures it, for the questions this asks itself.
func composeOut(ctx context.Context, dir, project string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	out, err := execCompose(ctx, "docker", append(composeBase(dir, project), args...)...).Output()
	return string(out), err
}
