// Command komizo sets up and inspects servers that deploy from GitHub Actions.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/nicodes/komizo-be/cli/internal/app"
)

func main() {
	if err := app.Main(os.Args[1:]); err != nil {
		// A silent error has already said its piece -- flag parsing prints its
		// own message, and repeating it would be noise.
		if !errors.Is(err, app.ErrSilent) {
			fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
		}
		os.Exit(1)
	}
}
