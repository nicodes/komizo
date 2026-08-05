package app

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
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
	run := tgt.runScriptHeard
	if scrubs(verb) {
		run = tgt.runScriptSafeHeard
	}
	onOut, onErr, err := run(boxCmd(verb, remote...), nil)
	if err != nil {
		return lifecycleErr(err, verb, subject, tgt)
	}
	// SUCCESS WITH NOTHING TO SHOW IS STILL AN ANSWER. See reportSilence: this
	// is the whole of komizo#47, and the return below is deliberately still nil.
	if !heardOn(verb, onOut, onErr) {
		reportSilence(quietStream(verb), verb, subject, listHint(tgt))
	}
	return nil
}

// heardOn is which stream counts as the box having said something.
//
// STDOUT ONLY FOR LOGS. The log is on stdout -- cmd/komizo-box hands compose's
// two streams straight through -- and compose talks on stderr for reasons that
// have nothing to do with whether an app has logged anything: a box whose
// compose file predates the schema change gets `WARN[0000] the attribute
// 'version' is obsolete` on every invocation, forever. Counting that as the app
// having spoken is komizo#47 restored on exactly the boxes carrying the oldest
// files, and restored silently, because it looks like the fix simply did not
// fire.
//
// EITHER STREAM FOR THE REST, because compose reports start, stop and restart
// on stderr: `Container web-web-1  Stopped` is not an error, it is the whole
// answer, and a stop that said that must not then be told it did nothing.
//
// The asymmetry is deliberate and is the same call quietStream makes from the
// other side: for logs, stderr is not part of the log, so komizo neither writes
// its own remark into stdout nor reads the box's stderr as proof the log exists.
//
// A function rather than an inline || so the decision can be asserted -- the
// same reason scrubs() is one.
func heardOn(verb string, onOut, onErr bool) bool {
	if verb == "logs" {
		return onOut
	}
	return onOut || onErr
}

// listHint is the `komizo list` an empty log can tell somebody to run,
// addressed the way they addressed this command.
//
// The login and the port are carried, because a suggestion that does not work
// when pasted is worse than no suggestion: somebody who reached this box as
// `deploy@BOX --port 2222` and is handed `komizo list --host BOX` gets a
// connection failure as the answer to "is my app running", and now has two
// mysteries.
func listHint(t target) string {
	s := "komizo list --host " + t.addr()
	if t.port != 22 {
		s += fmt.Sprintf(" --port %d", t.port)
	}
	return s
}

// reportSilence says what happened when the box's own output did not.
//
// komizo#47: `komizo logs --host ... --app web` printed nothing and exited 0.
// The command had worked. Nothing about the terminal said so -- an empty stdout
// and a zero exit are also what a command that never ran leaves behind, and
// they are what a mistyped alias, a shell function that swallowed the arguments
// and a binary that returned early all leave behind too. The person is left to
// tell those apart by rerunning it and watching harder.
//
// The box does not have this problem, which is the part that made it a bug
// rather than a rough edge. box/logs.go answers the app's read with "nothing
// collected for that app yet" -- a sentence -- while the CLI, reading the same
// state over SSH, said less than nothing. komizo-be design/app-only.md §9 keeps
// the CLI entire, and "entire" cannot mean the surface that explains itself
// worse.
//
// EXIT ZERO, STILL. An app with no output is not a failure, and making it one
// would break every `komizo logs` in a CI script the moment an app went quiet.
// The fix is a sentence, not a status.
func reportSilence(w io.Writer, verb, subject, listCmd string) {
	if verb != "logs" {
		// start, stop and restart already printed their own "==> Running stop on
		// web" header, so this is the second half of a sentence that was left
		// hanging -- issue #47's postscript, where `stop` on an app with no
		// containers printed the header and then nothing whatsoever.
		//
		// The inference is safe to state because compose names every container it
		// touches: `stop` prints a line per container it stops, `up -d` one per
		// container it creates or finds running, `restart` one per container it
		// restarts. None of them is capable of acting on something quietly, so an
		// empty run means an empty stack. (A box running a current agent refuses
		// `restart` with nothing running before it gets here -- cmd/komizo-box's
		// runVerb -- but an older agent does not, and this is the surface that
		// still has to say something on that box.)
		noteTo(w, "Nothing happened -- compose names every container it acts on, and it")
		noteTo(w, "named none, so %s found nothing under %s to act on.", verb, subject)
		return
	}

	stepTo(w, "%s has logged nothing", subject)
	// "This command ran" first, because that is the sentence the whole issue is
	// about. Everything after it is detail; without it the person is still
	// wondering whether komizo did anything at all, which is where they were
	// before this function existed.
	noteTo(w, "This command ran, and `docker compose logs` came back empty.")
	// TWO CAUSES, NAMED, RATHER THAN ONE GUESSED. The box genuinely cannot tell
	// them apart here: this path is `docker compose logs`, which is empty for a
	// stack with no containers and empty for a stack whose containers have said
	// nothing, and it reports the same emptiness for both. box/logs.go CAN
	// distinguish its own case -- a collected file that does not exist yet is a
	// 404 with "nothing collected for that app yet" -- but that is the app's HTTP
	// route reading a file rootd writes on a timer, and no part of it is on this
	// path. Picking one of the two to print would be komizo inventing a fact
	// about somebody's server, and a wrong reassurance costs more than an honest
	// pair: "nothing collected yet" told to somebody whose app has actually died
	// is a bug report that never gets filed.
	noteTo(w, "Either nothing has ever run under %s, or its containers have", subject)
	noteTo(w, "written no output yet.")
	// So the pair is closed by the command that settles it, rather than left as
	// two possibilities and no next move.
	noteTo(w, "`%s` will say which of the two it is.", listCmd)
}

// quietStream is where komizo's own remark about a silent run goes.
//
// STDERR FOR LOGS, and stdout for everything else. `komizo logs > snapshot.txt`
// and `komizo logs --app web | grep ERROR` are the reason the command exists as
// a command rather than only as a screen in the interface -- parity_test.go
// says it directly, a TUI-only capability "cannot be scripted, cannot run in
// CI". A sentence komizo wrote is not a log line, and writing it to stdout
// would put komizo's prose inside a file that is supposed to be the app's
// output, where the next reader has no way to tell whose words those are.
//
// start, stop and restart print komizo's own header to stdout already, so their
// remark belongs beside it. Nobody pipes a stop.
//
// A function rather than an inline branch so the decision can be asserted --
// the same reason scrubs() is one, and for the same failure: this is wiring,
// and wiring is the half that regresses without anything looking wrong.
func quietStream(verb string) *os.File {
	if verb == "logs" {
		return os.Stderr
	}
	return os.Stdout
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
