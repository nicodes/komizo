package app

import (
	"errors"
	"flag"
	"fmt"
	"os/exec"
	"strconv"
)

// Starting, stopping and reading what runs on a box, from the command line.
//
// These existed ONLY in the interface, which made them the capabilities
// komizo-be design/app-only.md §9 has to add before anything deletes it. A
// capability with one home is one that disappears when that home does, and
// assuming it was already CLI-shaped because it felt like it is exactly the
// mistake komizo#26 was.
//
// FIVE, not three. The first draft of this covered apps and missed the shared
// proxy's lifecycle, the proxy's log and acting on a single container -- and
// the proxy's log is the one that matters most, because tui_server.go says it
// is "where Caddy records its certificate work, the only place a certificate or
// TLS failure is explained". Deleting the interface without it would have left
// no way to read that anywhere.
//
// They do not build a docker command here. They ask `komizo-box app` on the
// box, which is the single implementation app-only.md §8 requires: the same
// binary rootd will run for a signed command. The interface used to compose the
// shell string on the operator's laptop, which meant what ran on somebody's
// server was decided by whichever komizo they happened to have installed.

// RunStart brings an app, a service, or the shared proxy up.
func RunStart(args []string) error { return lifecycle("start", args) }

// RunStop takes it down, deliberately.
//
// Deliberate is the whole distinction: architecture.md §6 keeps STOPPED as
// durable state on the box precisely so a stopped app pages nobody, and so that
// a deploy while stopped pulls the image without starting it.
func RunStop(args []string) error { return lifecycle("stop", args) }

// RunRestart restarts the containers that are there, which is not the same as
// stop then start -- compose restarts what it has rather than reconciling
// against the compose file.
func RunRestart(args []string) error { return lifecycle("restart", args) }

// RunLogs prints what something has been saying.
//
// A TAIL, bounded, and not a follow. app-only.md §5 says why the product side
// of this is deliberately small; the CLI side is small for a plainer reason,
// which is that anything else is `ssh` and `docker compose logs -f`, and komizo
// should not be a worse version of a thing that already works.
func RunLogs(args []string) error { return lifecycle("logs", args) }

func lifecycle(verb string, args []string) error {
	fs := flag.NewFlagSet(verb, flag.ContinueOnError)
	fs.Usage = func() { usageLifecycle(verb, fs) }
	var host, app, service string
	var port, tail int
	var proxy, acceptHostKey bool
	fs.StringVar(&host, "host", "", "server, [user@]HOST")
	fs.StringVar(&app, "app", "", "which app")
	fs.BoolVar(&proxy, "proxy", false, "the shared proxy, rather than an app")
	fs.StringVar(&service, "service", "", "one service, rather than all of them")
	fs.IntVar(&port, "port", 22, "SSH port")
	fs.BoolVar(&acceptHostKey, "accept-host-key", false, "trust an unseen server's host key (trust-on-first-use)")
	if verb == "logs" {
		fs.IntVar(&tail, "tail", 40, "how many lines")
	}
	if err := fs.Parse(args); err != nil {
		return ErrSilent
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q -- every input is a flag", fs.Arg(0))
	}

	// Exactly one subject. Both would be ambiguous and neither is a command with
	// nothing to act on.
	if proxy == (app != "") {
		return fmt.Errorf("give exactly one of --app and --proxy")
	}
	if !proxy {
		if err := validateApp(app); err != nil {
			return err
		}
	}
	// Checked here as well as on the box, so a typo fails before anything
	// connects. The box's check is the one that matters -- rootd builds its
	// arguments from a signed envelope that never passes through this file.
	if err := validateService(service); err != nil {
		return err
	}
	if verb == "logs" && (tail < 1 || tail > LogTailMax) {
		return fmt.Errorf("--tail must be between 1 and %d", LogTailMax)
	}

	tgt, err := resolveTarget(fs, host, port)
	if err != nil {
		return err
	}
	if err := ensureReachable(tgt, acceptHostKey); err != nil {
		return err
	}

	subject := app
	remote := []string{"--app", app}
	if proxy {
		subject, remote = "the proxy", []string{"--proxy"}
	}
	if service != "" {
		subject += " (" + service + ")"
		remote = append(remote, "--service", service)
	}
	if verb == "logs" {
		remote = append(remote, "--tail", strconv.Itoa(tail))
	}

	if verb != "logs" {
		step("Running %s on %s", verb, subject)
	}
	run := tgt.runScript
	if scrubs(verb) {
		run = tgt.runScriptSafe
	}
	if err := run(boxCmd(verb, remote...), nil); err != nil {
		return lifecycleErr(err, verb, subject, tgt)
	}
	return nil
}

// scrubs reports whether a verb's output was written by somebody else.
//
// Everything a lifecycle verb prints is compose's own prose. A LOG LINE IS NOT:
// anyone who can make a request to a hosted app can put text in one, and
// validate.go's scrub exists for exactly that. A separate function rather than
// an inline branch so the decision can be asserted -- the wiring is the half
// that silently regresses, since the scrubbing itself is obviously tested.
func scrubs(verb string) bool { return verb == "logs" }

// lifecycleErr says what to do about a box that could not run this.
//
// Two failures look identical in an exit status and are not: a box komizo has
// never set up has no agent at all, and a box set up before this command
// existed has one that does not know the mode. Telling somebody to update an
// agent they do not have sends them in the wrong direction, and report.go
// already keyed errNoAgent on exactly this exit code.
func lifecycleErr(err error, verb, subject string, tgt target) error {
	var ex *exec.ExitError
	if errors.As(err, &ex) && ex.ExitCode() == 127 {
		return errNoAgent{host: tgt.host}
	}
	return fmt.Errorf("could not %s %s -- see the output above.\n\n"+
		"    If the box says it does not know that mode, its agent predates this\n"+
		"    command: run `komizo update --host %s`.", verb, subject, tgt.host)
}

// LogTailMax mirrors the bound the box enforces, so an impossible request fails
// here rather than after a round trip. The box's is the one that is load-
// bearing; this one is a courtesy.
const LogTailMax = 2000

func validateService(s string) error {
	if s == "" {
		return nil
	}
	// A leading dash is the case that matters: Go's flag package takes the next
	// argument as a value without caring what it looks like, so `--service -f`
	// would arrive at compose as --follow.
	if s[0] == '-' {
		return fmt.Errorf("--service %q is a flag, not a service name", s)
	}
	if !onlyChars(s, serviceChars) {
		return fmt.Errorf("--service must be letters, digits, underscore, hyphen or dot; got %q", s)
	}
	return nil
}

const serviceChars = appChars + "."

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
	out := BoxBin + " app " + shQuote(verb)
	for _, a := range args {
		out += " " + shQuote(a)
	}
	return out
}

func usageLifecycle(verb string, fs *flag.FlagSet) {
	fmt.Printf(`komizo %s - %s

  komizo %s --host [user@]HOST --app NAME
  komizo %s --host [user@]HOST --proxy

Runs on the box, as root, through the agent komizo installed there. The same
code path a signed command from the app takes, so the two cannot drift.

Flags:
`, verb, lifecycleBlurb[verb], verb, verb)
	fs.PrintDefaults()
	fmt.Println()
}

var lifecycleBlurb = map[string]string{
	"start":   "bring an app, a service, or the shared proxy up",
	"stop":    "take one down, and leave it down",
	"restart": "restart the containers that are there",
	"logs":    "print what it has been saying",
}
