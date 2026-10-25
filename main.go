// Command komizo operates application hosts over SSH through their protected executor.
package main

import (
	"github.com/nicodes/komizo/internal/app"
	"os"
)

// version is the release this binary was built from, set at link time by the
// release workflow with -X. "dev" everywhere else, which is the honest answer
// for a binary built from a working tree that may not match any tag.
var version = "dev"

func main() {
	app.Version = version
	os.Exit(app.CLI(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
