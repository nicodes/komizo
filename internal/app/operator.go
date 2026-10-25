package app

import (
	"bytes"
	"errors"
	"flag"

	"github.com/nicodes/komizo/internal/operator"
)

func RunOperator(args []string) error {
	if len(args) == 0 {
		return errors.New("operator requires plan, apply, status, recover or export")
	}
	fs := flag.NewFlagSet("operator", flag.ContinueOnError)
	fs.SetOutput(commandFlags())
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
		var output bytes.Buffer
		if err := operator.Lifecycle(commandContext(), args[0], *expected, &output, commandProgress()); err != nil {
			return err
		}
		return emitProtocol(output.Bytes())
	case "export":
		if *expected != "" {
			return errors.New("export accepts no expected plan")
		}
		if err := operator.Export(*directory); err != nil {
			return err
		}
		if machineMode() {
			files, err := operator.Plan()
			if err != nil {
				return err
			}
			return emitResult(map[string]any{"version": 1, "directory": *directory, "files": files, "exported": true})
		}
		return nil
	default:
		return errors.New("operator requires plan, apply, status, recover or export")
	}
}
