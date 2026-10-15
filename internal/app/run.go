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
	case "set-secret":
		return RunSetSecret(args)
	case "unset-secret":
		return RunUnsetSecret(args)
	case "start":
		return RunStart(args)
	case "stop":
		return RunStop(args)
	case "restart":
		return RunRestart(args)
	case "logs":
		return RunLogs(args)
	case "preview":
		return RunPreview(args)
	case "ui":
		return RunUI(args)
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

func Main(args []string) (err error) {
	defer func() {
		if errors.Is(err, flag.ErrHelp) {
			err = nil
		}
	}()
	if printGroupHelp(args) {
		return nil
	}
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

	switch args[0] {
	// Asked before anything else can fail. The first thing anyone wants when a
	// tool misbehaves is which build of it they are running, and that answer
	// must not depend on a server being reachable or a flag parsing.
	case "--version", "-v", "version":
		if machineMode() {
			return printMachineVersion()
		}
		fmt.Println("komizo " + versionText())
		return nil
	case "capabilities":
		if hasHelp(args) {
			return RunCapabilities(nil)
		}
		return RunCapabilities(args[1:])
	case "doctor":
		return RunDoctor(args[1:])
	case "setup":
		return RunSetup(args[1:])
	case "deploy":
		return RunDeploy(args[1:])
	case "operation":
		return RunOperation(args[1:])
	// Grouped for what they are rather than for what they need: nothing in this
	// switch needs an account, and the two operations that do ask where they
	// happen. Sign-in is here because it is how you get one.
	case "login":
		err = RunLogin(args[1:])
	case "logout":
		err = RunLogout(args[1:])
	case "init", "update", "add", "list", "report", "enrol", "remove", "proxy",
		"start", "stop", "restart", "logs", "preview", "ui", "reconcile",
		"set-secret", "unset-secret":
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
	case "platform":
		err = RunPlatform(args[1:])
	case "publication":
		err = RunPublication(args[1:])
	case "operator":
		err = RunOperator(args[1:])
	case "workspace":
		err = RunWorkspace(args[1:])
	case "workload":
		err = RunWorkloadAcceptance(args[1:])
	case "artifact":
		err = RunArtifact(args[1:])
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
		err = fmt.Errorf("%q is not a command; use komizo help or komizo capabilities", args[0])
		if strings.ContainsAny(args[0], "@.:") {
			err = fmt.Errorf("server addresses belong in --host; try komizo report --host %s", args[0])
		}
	}

	return err
}

func Usage() {
	fmt.Print(`komizo - operate your own application hosts over SSH

Start here:
  komizo capabilities
  komizo doctor --host root@HOST
  komizo setup --host root@HOST [--definition app.json]
  komizo deploy --host root@HOST --app APP --version COMMIT
  komizo operation inspect --host root@HOST --app APP
  komizo report --host root@HOST

Agent interface:
  komizo --json COMMAND [FLAGS]
  komizo --json --timeout 5m COMMAND [FLAGS]

One versioned JSON result goes to stdout; progress goes to stderr. Discover
command effects and result formats with capabilities. Failed mutations may
have completed remotely: inspect their operation before retrying.

Applications:
  komizo list    --host root@HOST
  komizo add     --host root@HOST --app APP --config REF --key PRIVATE_FILE
  komizo start|stop|restart|logs --host root@HOST --app APP
  komizo remove --host root@HOST --app APP --yes
  komizo set-secret|unset-secret --host root@HOST --app APP
  komizo preview --help

Host and advanced operations:
  komizo init|update|proxy --host root@HOST
  komizo reconcile --host root@HOST --inventory expected-apps.json
  komizo platform --help
  komizo operator plan|apply|status|recover|export
  komizo artifact --arch amd64|arm64 --output NEW_FILE
  komizo publication prepare --help
  komizo workspace check|plan|clean --help
  komizo workload acceptance --help
  komizo script [init|add|remove|unset-secret|proxy]
  komizo ui --help

Supported application hosts use Alpine Linux and amd64 or arm64. No hosted
Komizo account is required. Each app supplies its own Compose artifacts and
explicit configuration. Run COMMAND --help for options. Legacy login/enrolment
commands only retain decommissioning and removal behavior.

Reconcile performs a reachability preflight and reads the report once. SSH may
create or tighten ~/.ssh for its control socket; explicit --accept-host-key
can append to local known_hosts. Reconcile writes nothing on the server.
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
