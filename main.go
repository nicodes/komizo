// Command komizo sets up and inspects servers that deploy from GitHub Actions.
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
	if err := app.Main(os.Args[1:]); err != nil {
		// A silent error has already said its piece -- flag parsing prints its
		// own message, and repeating it would be noise.
		if !errors.Is(err, app.ErrSilent) {
			fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
		}
		os.Exit(1)
	}
}
