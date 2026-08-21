// Package app is komizo: the commands, and everything they do to a server.
//
// It runs on YOUR machine. Every command opens an SSH connection itself; you do
// not run anything on the server by hand. The server-side work is a shell
// script embedded in this binary, printable with `komizo script`, so what runs
// as root on your box stays readable.
package app

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
)

// ErrSilent means the failure has already been reported -- flag parsing prints
// its own message, and repeating it would be noise.
var ErrSilent = errors.New("")

// Main is the whole command line: which subcommand, or an address, or nothing.
//
// Here rather than in the root main.go so that main() is the one thing it should be --
// a call and an exit code. Everything this dispatches to is in this package,
// and a dispatcher that lives apart from what it dispatches to is a file you
// have to open twice.
// Version is what this binary reports for `komizo version`. Set from main at
// startup, which is where the linker can reach it.
var Version = "dev"

// versionText is the version, and the point at which "dev" gets a second
// chance to be something better.
//
// The release workflow bakes a version in with -X, which covers the archives
// people download. It does NOT cover `go install module@v0.0.1`, which
// compiles from source with no linker flags of ours -- so every install that
// way reported "dev", which is exactly the answer nobody needs when they are
// trying to say which build is misbehaving.
//
// The module version is in the binary either way: the toolchain records it in
// the build info for anything installed by version, and for a build from a
// working tree it stamps a pseudo-version from the VCS instead --
// 0.0.0-<date>-<sha>, with +dirty when the tree does not match the commit.
// That is more use than the word "dev", so it is passed through as it is.
//
// "dev" survives only where there is nothing better: no build info at all, or
// VCS stamping turned off, which reports "(devel)" and says no more than "dev"
// does with fewer characters.
// moduleRef is the module path and version this binary was built from, as the
// Go proxy would resolve them -- ("github.com/nicodes/komizo", "v0.0.17").
//
// Both empty when there is no build info, when the version is "(devel)", or on
// a build from a checkout: those are builds no `go install <module>@<version>`
// could reproduce, so there is nothing to pin an agent build to. Said as empty
// rather than guessed, because guessing installs an agent that need not match
// the CLI managing the box. nicodes/komizo-be#177.
func moduleRef() (path, version string) {
	bi, ok := debug.ReadBuildInfo()
	if !ok || bi.Main.Path == "" {
		return "", ""
	}
	v := bi.Main.Version
	if v == "" || v == "(devel)" || !strings.HasPrefix(v, "v") {
		return "", ""
	}
	return bi.Main.Path, v
}

func versionText() string {
	if Version != "dev" {
		return Version
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok || bi.Main.Version == "" || bi.Main.Version == "(devel)" {
		return Version
	}
	return strings.TrimPrefix(bi.Main.Version, "v")
}

// runCommand is every command that acts on a box or on the service.
//
// It used to be called runAccountCommand and every entry needed somebody signed
// in. komizo-be design/app-only.md §7 narrows that: an account is required to
// REGISTER a box, not to OPERATE one. See needsSession.
func runCommand(name string, args []string) error {
	switch name {
	case "init":
		return RunInit(args)
	case "update":
		return RunUpdate(args)
	case "add":
		return RunAdd(args)
	case "list":
		return RunList(args)
	case "report":
		return RunReport(args)
	case "enrol":
		return RunEnrol(args)
	case "remove":
		return RunRemove(args)
	case "start":
		return RunStart(args)
	case "stop":
		return RunStop(args)
	case "restart":
		return RunRestart(args)
	case "logs":
		return RunLogs(args)
	case "proxy":
		return RunProxy(args)
	case "reconcile":
		return RunReconcile(args)
	}
	return fmt.Errorf("unknown command %q", name)
}

// NO COMMAND IS GATED ON AN ACCOUNT. The two calls that reach the service ask
// for one themselves -- registerAndEnrol, and `komizo enrol` when it has to mint
// the token -- and everything else is SSH to a machine whose root key you hold.
//
// There was a one-entry table here, keeping `init` on a front gate, and the
// reason recorded for it was wrong about the code beside it: it said failing at
// the end would leave "a provisioned machine and an error", but init.go was
// deliberately written so that a failed registration is a NOTE and the box is
// still set up. So the gate was not preventing that outcome; it was refusing to
// let somebody without a komizo account provision their own server at all,
// which is the capability gate appify.md §7 says must not exist and which
// app-only.md §7 left standing.

func Main(args []string) error {
	// `komizo` on its own prints what it can do, and SUCCEEDS.
	//
	// It used to open the interface, and before that it printed the usage and
	// exited 2 -- which made the shortest thing anyone would type the one thing
	// that did not work. Exit 0 because asking a tool what it does is not a
	// misuse of it: a script running `komizo || echo broken` should not be told
	// the tool is broken for having been asked.
	if len(args) == 0 {
		Usage()
		return nil
	}

	var err error
	switch args[0] {
	// Asked before anything else can fail. The first thing anyone wants when a
	// tool misbehaves is which build of it they are running, and that answer
	// must not depend on a server being reachable or a flag parsing.
	case "--version", "-v", "version":
		fmt.Println("komizo " + versionText())
		return nil
	// Grouped for what they are rather than for what they need: nothing in this
	// switch needs an account, and the two operations that do ask where they
	// happen. Sign-in is here because it is how you get one.
	case "login":
		err = RunLogin(args[1:])
	case "logout":
		err = RunLogout(args[1:])
	case "init", "update", "add", "list", "report", "enrol", "remove", "proxy",
		"start", "stop", "restart", "logs", "reconcile":
		// No gate. An account is needed to REGISTER a box, and the two places
		// that do it ask for one where they do it.
		//
		// registry.md §10 required one for all of these, on the argument that
		// `komizo init` collapses three steps into one with nothing copied
		// between two surfaces. That argument holds for init and for nothing
		// else -- app-only.md §7 -- and narrowing it makes §10's own constraint
		// structural instead of something a cached session provides:
		//
		//	The CLI must work when the service does not.
		//
		// Adding an app to a box, starting one, reading a report or repairing a
		// proxy is you and your server. komizo is not in it, has never been in
		// it, and asking it for permission first would have made an outage the
		// reason you cannot fix your own machine.
		err = runCommand(args[0], args[1:])
	case "script":
		err = RunScript(args[1:])
	case "-h", "--help", "help":
		Usage()
	default:
		// A BARE ADDRESS USED TO OPEN THE INTERFACE, and there is no longer one
		// to open (nicodes/komizo-be#55). It was the documented front door, so
		// it gets an answer that names where the work moved rather than the
		// generic usage -- somebody typing the thing the README taught them is
		// the last person who should have to work out what changed.
		if strings.HasPrefix(args[0], "-") {
			fmt.Fprintf(os.Stderr, "unknown flag %q\n\n", args[0])
			Usage()
			os.Exit(2)
		}
		// A space in `root @host`. The shell handed this two arguments and the
		// second carries the hostname, so the address was typed correctly and
		// split by one keystroke.
		//
		// Named rather than answered with the usage, which is thirty lines that
		// do not mention the problem -- and which is what somebody who typed
		// almost the right thing least needs to read. Checked BEFORE the
		// address is echoed back, so the suggestion below is not built from
		// half of one.
		if len(args) > 1 && strings.HasPrefix(args[1], "@") && !strings.Contains(args[0], "@") {
			fmt.Fprintf(os.Stderr, "there is a space in the address, so %q was read as the whole host.\n\n    komizo report --host %s%s\n\n",
				args[0], args[0], args[1])
			os.Exit(2)
		}
		// RETURNED, not exited on. Every other outcome of this switch comes back
		// as an error and `Main` is what tests drive -- an os.Exit here takes
		// the test binary with it, which is how this first went in.
		err = fmt.Errorf(`%q is not a command.

The full-screen interface is gone; the app is where a server is watched and
operated now. Everything it did is a command here, and each one takes the
address as a flag:

    komizo report --host %s
    komizo list   --host %s
    komizo init   --host %s

Run "komizo" on its own for the whole list.`, args[0], args[0], args[0], args[0])
	}

	return err
}

func Usage() {
	fmt.Print(`komizo - deploy to your own servers from GitHub Actions

Every operation is a command, and each takes the server as a flag. komizo runs
on your machine and connects to the box itself; you never run anything on it by
hand.

  komizo login
  komizo logout
  komizo init    --host root@HOST
  komizo update  --host root@HOST
  komizo add     --host root@HOST --app NAME --config REF
  komizo list    --host root@HOST
  komizo report  --host root@HOST
  komizo enrol   --host root@HOST --token kmz_enr_...
  komizo remove  --host root@HOST --app NAME --yes
  komizo start   --host root@HOST --app NAME
  komizo stop    --host root@HOST --app NAME
  komizo restart --host root@HOST --app NAME
  komizo logs    --host root@HOST --app NAME [--tail N] [--service S]
  komizo proxy   --host root@HOST
  komizo reconcile --host root@HOST --inventory expected-apps.json
  komizo script [init|add|remove|proxy]

"komizo login" signs this machine in. It shows a code to approve from a device
you are already signed in on -- a phone will do -- so a machine with no browser
can still be signed in.

AN ACCOUNT IS TO REGISTER A BOX, NOT TO OPERATE ONE. Nothing here refuses to run
without one. Filing a server under your account needs one -- that is what "komizo
init" does at the end, and what "komizo enrol" does when you do not pass a token
-- and a box set up without it works exactly as it always did; it simply does not
appear in the app until you enrol it.

Everything else -- adding an app, starting or stopping one, reading a report,
repairing the proxy -- is you and your server over SSH, and needs nothing from
komizo at all. The session is read from disk rather than checked over the
network, so an outage costs registration and nothing else.

"komizo init" prepares a fresh server: Docker, the shared network, and the one
Caddy that terminates TLS for every app on the box. It is a separate step from
adding an app, so a server is either set up or it is not.

"komizo update" re-runs all of that on a server that already has it, which is
how a box is brought up to a newer komizo and how one with a missing or broken
agent is repaired. "komizo report" says when a box is due one.

"komizo start", "stop", "restart" and "logs" act on one app. They run through
the agent on the box rather than composing a docker command here, so they take
exactly the path a signed command from the app will take and the two cannot
drift apart. "stop" is durable: a stopped app stays stopped across a deploy,
and pages nobody.

"komizo reconcile" is the rebuild check: does this box hold exactly the apps a
local inventory says it must, with the pinned config image and the expected
public hostnames? It reads the box once and changes nothing -- any missing,
unexpected or mismatched entry is printed and the exit status is nonzero.

"komizo script" prints the shell this ships to the server, so you can read what
will run as root before it does.

Run a command with --help for its flags.
`)
}

func UsageAdd(fs *flag.FlagSet) {
	fmt.Print(`komizo add - set an app up on a server, or update one

  komizo add --host root@myapp.example.com --app myapp \
    --config ghcr.io/you/myapp-config

Re-running is safe: it is how you change the config image, repair permissions,
or pick up a newer version of this tool.

Every app is named, including the first. To host several on one box, run this
once per app: each gets its own directory, deploy scripts, doas rules and
deploy account, so a key that leaks from one repo reaches only that app.

Flags:
`)
	fs.PrintDefaults()
	fmt.Println()
}

func usageList(fs *flag.FlagSet) {
	fmt.Print(`komizo list - what apps are on a server

  komizo list --host root@myapp.example.com

Reads the generated deploy scripts, which are what actually define an app.
A directory under /srv with no script behind it is reported as an orphan.

Flags:
`)
	fs.PrintDefaults()
	fmt.Println()
}
