// Command komizo operates application hosts over SSH through their protected executor.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/nicodes/komizo/internal/app"
)

// version is the release this binary was built from, set at link time by the
// release workflow with -X. "dev" everywhere else, which is the honest answer
// for a binary built from a working tree that may not match any tag.
var version = "dev"

func main() {
	app.Version = version
	if len(os.Args) > 1 && os.Args[1] == "--json" {
		os.Exit(app.Machine(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	if err := app.Main(os.Args[1:]); err != nil {
		// A silent error has already said its piece -- flag parsing prints its
		// own message, and repeating it would be noise.
		if !errors.Is(err, app.ErrSilent) && app.ExitCode(err) != app.MachineHelpExit {
			fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
		}
		os.Exit(app.ExitCode(err))
	}
}
