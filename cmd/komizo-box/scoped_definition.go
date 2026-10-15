package main

import (
	"errors"
	"flag"

	"github.com/nicodes/komizo/box"
)

func runScopedDefinitionCheck(args []string) error {
	fs := flag.NewFlagSet("scoped-definition-check", flag.ContinueOnError)
	profile := fs.String("profile", "", "operator-defined profile")
	schema := fs.String("schema", "", "positive protocol schema")
	files := fs.String("files", "", "declared private environment filenames")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("scoped definition accepts only declared fields")
	}
	_, err := box.ParseScopedDefinition(*profile, *schema, *files)
	return err
}
