package app

import (
	"flag"
	"fmt"
	"strconv"
)

// Starting, stopping and reading an app, from the command line.
//
// These existed ONLY in the interface -- tui_views.go's startStop and
// tui_server.go's stackLogCmd -- which made them the three capabilities
// komizo-be design/app-only.md §9 has to add before anything deletes it. A
// capability with one home is one that disappears when that home does, and
// assuming it was already CLI-shaped because it felt like it is exactly the
// mistake komizo#26 was.
//
// They do not build a docker command here. They ask `komizo-box app` on the
// box, which is the single implementation app-only.md §8 requires: the same
// binary rootd will run for a signed command. The interface used to compose the
// shell string on the operator's laptop, which meant what ran on somebody's
// server was decided by whichever komizo they happened to have installed.

// RunStart brings an app up.
func RunStart(args []string) error { return lifecycle("start", args) }

// RunStop takes an app down, deliberately.
//
// Deliberate is the whole distinction: architecture.md §6 keeps STOPPED as
// durable state on the box precisely so a stopped app pages nobody, and so that
// a deploy while stopped pulls the image without starting it.
func RunStop(args []string) error { return lifecycle("stop", args) }

// RunRestart is stop and start as the box sees it, which is not the same as
// running the two commands in sequence -- compose restarts the containers it
// has rather than reconciling against the compose file.
func RunRestart(args []string) error { return lifecycle("restart", args) }

func lifecycle(verb string, args []string) error {
	fs := flag.NewFlagSet(verb, flag.ContinueOnError)
	fs.Usage = func() { usageLifecycle(verb, fs) }
	var host, app string
	var port int
	var acceptHostKey bool
	fs.StringVar(&host, "host", "", "server, [user@]HOST")
	fs.StringVar(&app, "app", "", "which app")
	fs.IntVar(&port, "port", 22, "SSH port")
	fs.BoolVar(&acceptHostKey, "accept-host-key", false, "trust an unseen server's host key (trust-on-first-use)")
	if err := fs.Parse(args); err != nil {
		return ErrSilent
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q -- every input is a flag", fs.Arg(0))
	}
	if err := validateApp(app); err != nil {
		return err
	}
	tgt, err := resolveTarget(fs, host, port)
	if err != nil {
		return err
	}
	if err := ensureReachable(tgt, acceptHostKey); err != nil {
		return err
	}

	step("Running %s on %s", verb, app)
	if err := tgt.runScript(boxCmd(verb, "--app", app), nil); err != nil {
		return fmt.Errorf("could not %s %s -- see the output above.\n\n"+
			"    If the box says it does not know that mode, its agent predates\n"+
			"    this command: run `komizo update --host %s`.", verb, app, tgt.host)
	}
	return nil
}

// RunLogs prints what an app has been saying.
//
// A TAIL, bounded, and not a follow. app-only.md §5 says why the product side
// of this is deliberately small; the CLI side is small for a plainer reason,
// which is that anything else is `ssh` and `docker compose logs -f`, and komizo
// should not be a worse version of a thing that already works.
func RunLogs(args []string) error {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	fs.Usage = func() { usageLifecycle("logs", fs) }
	var host, app, service string
	var port, tail int
	var acceptHostKey bool
	fs.StringVar(&host, "host", "", "server, [user@]HOST")
	fs.StringVar(&app, "app", "", "which app")
	fs.StringVar(&service, "service", "", "one service in the app, rather than all of them")
	fs.IntVar(&tail, "tail", 40, "how many lines")
	fs.IntVar(&port, "port", 22, "SSH port")
	fs.BoolVar(&acceptHostKey, "accept-host-key", false, "trust an unseen server's host key (trust-on-first-use)")
	if err := fs.Parse(args); err != nil {
		return ErrSilent
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q -- every input is a flag", fs.Arg(0))
	}
	if err := validateApp(app); err != nil {
		return err
	}
	if service != "" && !onlyChars(service, appChars) {
		return fmt.Errorf("--service must be letters, digits, underscore or hyphen; got %q", service)
	}
	if tail < 1 {
		return fmt.Errorf("--tail must be at least 1, got %d", tail)
	}
	tgt, err := resolveTarget(fs, host, port)
	if err != nil {
		return err
	}
	if err := ensureReachable(tgt, acceptHostKey); err != nil {
		return err
	}

	a := []string{"--app", app, "--tail", strconv.Itoa(tail)}
	if service != "" {
		a = append(a, "--service", service)
	}
	if err := tgt.runScript(boxCmd("logs", a...), nil); err != nil {
		return fmt.Errorf("could not read the logs for %s -- see the output above", app)
	}
	return nil
}

// boxCmd builds the line that runs on the box, quoting every value.
//
// Sent as a SCRIPT over stdin rather than as a remote command line, which is
// what runScript does and why every other command here uses it: a command line
// is visible in the box's process table to every account on it for as long as
// it runs.
//
// Quoted even though each value has already been validated, because the two
// checks are for different things: validation is about whether komizo will act
// on a name, and quoting is about what a shell does with it. Relying on the
// first to make the second unnecessary is how a rule that later relaxes becomes
// an injection.
func boxCmd(verb string, args ...string) string {
	out := "/usr/local/bin/komizo-box app " + shQuote(verb)
	for _, a := range args {
		out += " " + shQuote(a)
	}
	return out
}

func usageLifecycle(verb string, fs *flag.FlagSet) {
	fmt.Printf(`komizo %s - %s

  komizo %s --host [user@]HOST --app NAME

Runs on the box, as root, through the agent komizo installed there. The same
code path a signed command from the app takes, so the two cannot drift.

Flags:
`, verb, lifecycleBlurb[verb], verb)
	fs.PrintDefaults()
	fmt.Println()
}

var lifecycleBlurb = map[string]string{
	"start":   "bring an app up",
	"stop":    "take an app down, and leave it down",
	"restart": "restart an app's containers",
	"logs":    "print what an app has been saying",
}
