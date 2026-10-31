package app

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/nicodes/komizo/internal/nativeapi"
)

// RunUI preserves the CLI's flag/help contract and supervises the native API.
// HTTP validation, authentication, file reads and lifecycle dispatch are Rust.
func RunUI(args []string) error {
	flags := flag.NewFlagSet("ui", flag.ContinueOnError)
	flags.SetOutput(commandFlags())
	flags.Usage = func() {
		fmt.Fprintln(commandFlags(), "komizo ui - local host dashboard\n\nThe listener defaults to 127.0.0.1. Use --bind to select an explicit interface.")
		flags.PrintDefaults()
	}
	flags.String("bind", "127.0.0.1", "listener IP address")
	flags.Int("port", 8480, "listener port")
	for _, name := range []string{"hosts", "report", "history", "metrics", "results", "logs", "inbox", "apps"} {
		flags.String(name, "", "explicit API input path or allowed hosts")
	}
	if err := flags.Parse(args); err != nil {
		return silentFlagError(err)
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q -- every input is a flag", flags.Arg(0))
	}
	argv := append([]string{"ui"}, args...)
	return nativeapi.Run(context.Background(), argv, os.Stdin, commandOutput(), commandFlags())
}
