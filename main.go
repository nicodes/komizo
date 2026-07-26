// Command cicd sets up and inspects servers that deploy from GitHub Actions.
//
// It runs on YOUR machine. Every command opens an SSH connection itself; you do
// not run anything on the server by hand. The server-side work is a shell
// script embedded in this binary, printable with `cicd script`, so what runs as
// root on your box stays readable.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/nicodes/cicd"
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
	case "add":
		err = runAdd(os.Args[2:])
	case "list":
		err = runList(os.Args[2:])
	case "script":
		fmt.Print(cicd.AlpineScript)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		if !errors.Is(err, errSilent) {
			fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
		}
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`cicd - deploy to your own servers from GitHub Actions

Runs on your machine and connects to the server itself.

  cicd add     --host root@HOST --config REF [--app NAME]
                 Set an app up on a server, or update one. Generates a deploy
                 key locally, prepares the box, and prints the two values to
                 paste into GitHub. Safe to re-run.

  cicd list    --host root@HOST
                 What apps are on a box: account, directory, live version,
                 running containers, config image.

  cicd script
                 Print the server-side script this ships, so you can read what
                 will run as root before it does.

Run a command with --help for its flags.
`)
}

func usageAdd(fs *flag.FlagSet) {
	fmt.Print(`cicd add - set an app up on a server, or update one

  cicd add --host root@myapp.example.com --config ghcr.io/you/myapp-config

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
	fmt.Print(`cicd list - what apps are on a server

  cicd list --host root@myapp.example.com

Reads the generated deploy scripts, which are what actually define an app.
A directory under /srv with no script behind it is reported as an orphan.

Flags:
`)
	fs.PrintDefaults()
	fmt.Println()
}
