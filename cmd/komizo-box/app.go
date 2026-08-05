package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
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
// It also puts the compose invocation somewhere it can be REASONED about. The
// interface built these command strings on the operator's laptop and sent them
// down a pipe, so what ran on the box was decided by the version of komizo
// somebody happened to have.

// logTailMax bounds a log request.
//
// Logs are the only thing here that returns unbounded output, and the caller is
// on the other side of an SSH connection or an HTTPS route. A tail is what this
// is for -- see app-only.md §5, "tail, do not index".
const logTailMax = 2000

func runApp(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: komizo-box app <start|stop|restart|logs> --app NAME")
	}
	verb := args[0]

	fs := flag.NewFlagSet("app "+verb, flag.ContinueOnError)
	name := fs.String("app", "", "which app")
	tail := fs.Int("tail", 40, "how many log lines")
	svc := fs.String("service", "", "one service in the app, rather than all of them")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	// The REQUEST is checked before anything is looked up, so an unknown verb
	// or an unbounded tail is refused on its own terms rather than incidentally,
	// by an app lookup that happened to fail first. That ordering is also what
	// keeps the tests about it honest.
	if !knownVerbs[verb] {
		return fmt.Errorf("%q is not something an app can be told to do", verb)
	}
	if *name == "" {
		return fmt.Errorf("--app is required")
	}
	if verb == "logs" && (*tail < 1 || *tail > logTailMax) {
		return fmt.Errorf("--tail must be between 1 and %d", logTailMax)
	}

	dir, err := box.AppDir("", *name)
	if err != nil {
		return err
	}

	ctx, stop := signalContext()
	defer stop()

	switch verb {
	case "start":
		// `up -d`, never `start`. A stopped app whose image has since been
		// deployed would be brought back on the OLD one by `docker compose
		// start`, silently -- design/architecture.md §6 makes this exact point
		// about why stopped is durable state and how it is undone.
		return compose(ctx, dir, "up", "-d")
	case "stop":
		return compose(ctx, dir, "stop")
	case "restart":
		return compose(ctx, dir, "restart")
	case "logs":
		a := []string{"logs", "--tail", strconv.Itoa(*tail), "--no-color"}
		if *svc != "" {
			a = append(a, *svc)
		}
		return compose(ctx, dir, a...)
	}
	// Unreachable: knownVerbs above is the same set. Kept so that adding a verb
	// to one and not the other is a compile-time shape rather than a silent
	// no-op that reports success.
	return fmt.Errorf("%q is not something an app can be told to do", verb)
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

// compose runs one verb against an app's project, with komizo's own arguments.
//
// The file and the project directory are BOTH named. Compose infers a project
// name from the directory, and an app whose directory does not match its name
// would otherwise be acted on under a project nothing else uses -- which looks
// exactly like a command that worked and did nothing.
//
// exec.Command with a slice, never a shell string. This is the process the
// signed-command path ends in, and a shell here would make every argument a
// place where an app name becomes a command.
func compose(ctx context.Context, dir string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, composeTimeout)
	defer cancel()

	full := append([]string{"compose", "-f", dir + "/compose.yml", "--project-directory", dir}, args...)
	cmd := exec.CommandContext(ctx, "docker", full...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker compose %s: %w", args[0], err)
	}
	return nil
}
