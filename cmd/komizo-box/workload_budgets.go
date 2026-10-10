package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/nicodes/komizo/internal/workload"
)

func runWorkloadBudgets(args []string) error {
	fs := flag.NewFlagSet("budgets", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "protected policy document")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *policyPath == "" || os.Geteuid() != 0 {
		return errors.New("budgets requires root and a policy path; reads the reviewed envelope from stdin")
	}
	p, err := readWorkloadPolicy(*policyPath)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, workload.MaxBytes+1))
	decoder.DisallowUnknownFields()
	var resources workload.ResourcePolicy
	if err := decoder.Decode(&resources); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("resource envelope must contain one document")
	}
	if err := resources.Check(); err != nil {
		return err
	}
	p.Resources = &resources
	return workload.WritePrivateJSON(*policyPath, p)
}
