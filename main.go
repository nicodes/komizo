// Command komizo sets up and inspects servers that deploy from GitHub Actions.
//
// It runs on YOUR machine. Every command opens an SSH connection itself; you do
// not run anything on the server by hand. The server-side work is a shell
// script embedded in this binary, printable with `komizo script`, so what runs as
// root on your box stays readable.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

// errSilent means the failure has already been reported -- flag parsing prints
// its own message, and repeating it would be noise.
var errSilent = errors.New("")

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "init":
		err = runInit(os.Args[2:])
	case "add":
		err = runAdd(os.Args[2:])
	case "list":
		err = runList(os.Args[2:])
	case "remove":
		err = runRemove(os.Args[2:])
	case "proxy":
		err = runProxy(os.Args[2:])
	case "script":
		err = runScript(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		// Anything that is not a known command is treated as a host: the normal
		// way to use this is `komizo root@your-server`, which opens the interface
		// and does everything from there. Requiring a subcommand for the common
		// case would be one more thing to know for no benefit.
		if strings.HasPrefix(os.Args[1], "-") {
			fmt.Fprintf(os.Stderr, "unknown flag %q\n\n", os.Args[1])
			usage()
			os.Exit(2)
		}
		// --port is the one flag the interactive path takes. Without it we read
		// the port from the user's ssh config instead of assuming 22.
		fs := flag.NewFlagSet("komizo", flag.ContinueOnError)
		fs.Usage = usage
		port := fs.Int("port", 22, "SSH port")
		if perr := fs.Parse(os.Args[2:]); perr != nil {
			os.Exit(2)
		}
		if fs.NArg() > 0 {
			fmt.Fprintf(os.Stderr, "unexpected argument %q after a host\n\n", fs.Arg(0))
			usage()
			os.Exit(2)
		}
		err = runTUI(os.Args[1], *port, portWasSet(fs))
	}

	if err != nil {
		if !errors.Is(err, errSilent) {
			fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
		}
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`komizo - deploy to your own servers from GitHub Actions

  komizo root@your-server
  komizo root@your-server --port 2222

That opens the interface. Everything -- adding an app, rotating its deploy key,
removing one -- is done from there. It runs on your machine and connects to the
server itself; you never run anything on the box by hand.

The same operations are available non-interactively, for scripting:

  komizo init    --host root@HOST
  komizo add     --host root@HOST --app NAME --config REF
  komizo list    --host root@HOST
  komizo remove  --host root@HOST --app NAME
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

func usageAdd(fs *flag.FlagSet) {
	fmt.Print(`komizo add - set an app up on a server, or update one

  komizo add --host root@myapp.example.com --config ghcr.io/you/myapp-config

Re-running is safe: it is how you change the config image, repair permissions,
or pick up a newer version of this tool.

To host several apps on one box, pass --app once per app. Each gets its own
directory, deploy scripts, doas rules and deploy account, so a key that leaks
from one repo reaches only that app.

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
