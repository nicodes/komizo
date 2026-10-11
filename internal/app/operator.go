package app

import (
	"errors"
	"flag"
	"os"

	"github.com/nicodes/komizo/internal/operator"
)

func RunOperator(args []string) error {
	if len(args) == 0 {
		return errors.New("operator requires plan, apply, status, recover or export")
	}
	fs := flag.NewFlagSet("operator", flag.ContinueOnError)
	directory := fs.String("directory", "", "new private directory for the authenticated operator bundle")
	expected := fs.String("expected-plan", "", "reviewed operator installation plan SHA256")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("operator accepts no positional paths")
	}
	switch args[0] {
	case "plan", "apply", "status", "recover":
		if *directory != "" {
			return errors.New("operator lifecycle accepts no directory")
		}
		if args[0] != "apply" && *expected != "" {
			return errors.New("only apply accepts an expected plan")
		}
		return operator.Lifecycle(args[0], *expected, os.Stdout)
	case "export":
		if *expected != "" {
			return errors.New("export accepts no expected plan")
		}
		return operator.Export(*directory)
	default:
		return errors.New("operator requires plan, apply, status, recover or export")
	}
}
