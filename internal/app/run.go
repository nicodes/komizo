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
	"strings"
)

// ErrSilent means the failure has already been reported -- flag parsing prints
// its own message, and repeating it would be noise.
var ErrSilent = errors.New("")

// Main is the whole command line: which subcommand, or an address, or nothing.
//
// Here rather than in cmd/komizo so that main() is the one thing it should be --
// a call and an exit code. Everything this dispatches to is in this package,
// and a dispatcher that lives apart from what it dispatches to is a file you
// have to open twice.
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
	case "init":
		err = RunInit(args[1:])
	case "add":
		err = RunAdd(args[1:])
	case "list":
		err = RunList(args[1:])
	case "remove":
		err = RunRemove(args[1:])
	case "proxy":
		err = RunProxy(args[1:])
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
			fmt.Fprintf(os.Stderr, "unexpected argument %q after a host\n\n", fs.Arg(0))
			Usage()
			os.Exit(2)
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

  komizo init    --host root@HOST
  komizo add     --host root@HOST --app NAME --config REF
  komizo list    --host root@HOST
  komizo remove  --host root@HOST --app NAME --yes
  komizo proxy   --host root@HOST
  komizo script [init|add|remove|proxy]

"komizo init" prepares a fresh server: Docker, the shared network, and the one
Caddy that terminates TLS for every app on the box. It is a separate step from
adding an app, so a server is either set up or it is not.

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
