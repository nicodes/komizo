// Package app is komizo: the commands, the interface, and everything they do
// to a server.
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

// runAccountCommand is every command that needs somebody signed in.
//
// One table, so a command added later cannot be added to the dispatch and
// forgotten by the gate -- which would be a route into somebody's servers that
// nobody remembered to close.
func runAccountCommand(name string, args []string) error {
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
	}
	return fmt.Errorf("unknown command %q", name)
}

func Main(args []string) error {
	// `komizo` on its own is the interface with nothing to connect to yet: it
	// opens and asks for an address. It used to print the usage and exit 2,
	// which made the shortest thing anyone would type the one thing that did
	// not work.
	if len(args) == 0 {
		return RunLoginTUI()
	}

	var err error
	switch args[0] {
	// Asked before anything else can fail. The first thing anyone wants when a
	// tool misbehaves is which build of it they are running, and that answer
	// must not depend on a server being reachable or a flag parsing.
	case "--version", "-v", "version":
		fmt.Println("komizo " + versionText())
		return nil
	// Signing in, signing out, saying which version this is and printing the
	// shell komizo ships are the four things that do not need an account. The
	// first two because they are how you get one; the last two because they
	// touch neither a service nor a server.
	case "login":
		err = RunLogin(args[1:])
	case "logout":
		err = RunLogout(args[1:])
	case "init", "update", "add", "list", "report", "enrol", "remove", "proxy",
		"start", "stop", "restart", "logs":
		// Read from disk, never checked over the network -- see session.go.
		// The CLI is what repairs a broken box, and requiring a reachable
		// service to fix a server is requiring it at the moment it is least
		// likely to be there.
		if _, serr := requireSession(); serr != nil {
			return serr
		}
		err = runAccountCommand(args[0], args[1:])
	case "script":
		err = RunScript(args[1:])
	case "-h", "--help", "help":
		Usage()
	default:
		// Anything that is not a known command is treated as a host: the normal
		// way to use this is `komizo root@your-server`, which opens the interface
		// and does everything from there. Requiring a subcommand for the common
		// case would be one more thing to know for no benefit.
		if strings.HasPrefix(args[0], "-") {
			fmt.Fprintf(os.Stderr, "unknown flag %q\n\n", args[0])
			Usage()
			os.Exit(2)
		}
		// --port is the one flag the interactive path takes. Without it we read
		// the port from the user's ssh config instead of assuming 22.
		fs := flag.NewFlagSet("komizo", flag.ContinueOnError)
		fs.Usage = Usage
		port := fs.Int("port", 22, "SSH port")
		// Interactive, so this only skips the confirmation -- without it komizo
		// still offers to accept an unseen host key, it just asks first.
		yes := fs.Bool("accept-host-key", false, "accept an unseen host key without asking")
		if perr := fs.Parse(args[1:]); perr != nil {
			os.Exit(2)
		}
		if fs.NArg() > 0 {
			// A space in `root @host`. The shell handed this two arguments and
			// the second carries the hostname, so the address was typed
			// correctly and split by one keystroke.
			//
			// Named rather than answered with the usage, which is thirty lines
			// that do not mention the problem -- and which is what somebody who
			// typed almost the right thing least needs to read.
			if rest := fs.Arg(0); strings.HasPrefix(rest, "@") && !strings.Contains(args[0], "@") {
				fmt.Fprintf(os.Stderr, "there is a space in the address, so %q was read as the whole host.\n\n    komizo %s%s\n\n",
					args[0], args[0], rest)
				os.Exit(2)
			}
			fmt.Fprintf(os.Stderr, "unexpected argument %q after a host\n\n", fs.Arg(0))
			Usage()
			os.Exit(2)
		}
		// The interface needs an account like every other route into a server.
		// Refused here rather than opened and then refused inside, so somebody
		// who is not signed in gets a sentence they can act on instead of a
		// full-screen program that will not do anything.
		if _, serr := requireSession(); serr != nil {
			return serr
		}
		err = RunTUI(args[0], *port, portWasSet(fs), *yes)
	}

	return err
}

func Usage() {
	fmt.Print(`komizo - deploy to your own servers from GitHub Actions

  komizo
  komizo root@your-server
  komizo root@your-server --port 2222

On its own it asks which server; with an address it goes straight there. Either
way opens the interface, and everything -- adding an app, rotating its deploy
key, removing one -- is done from there. It runs on your machine and connects to the
server itself; you never run anything on the box by hand.

The same operations are available non-interactively, for scripting:

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
  komizo script [init|add|remove|proxy]

"komizo login" signs this machine in. It shows a code to approve from a device
you are already signed in on -- a phone will do -- so a machine with no browser
can still be signed in. Every other command needs it, and the session is read
from disk rather than checked over the network: a komizo outage must never stop
somebody repairing their own server.

"komizo init" prepares a fresh server: Docker, the shared network, and the one
Caddy that terminates TLS for every app on the box. It is a separate step from
adding an app, so a server is either set up or it is not.

"komizo update" re-runs all of that on a server that already has it, which is
how a box is brought up to a newer komizo and how one with a missing or broken
agent is repaired. It is the same operation as "u" in the interface.

"komizo start", "stop", "restart" and "logs" act on one app. They run through
the agent on the box rather than composing a docker command here, so they take
exactly the path a signed command from the app will take and the two cannot
drift apart. "stop" is durable: a stopped app stays stopped across a deploy,
and pages nobody.

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
