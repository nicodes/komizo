package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"runtime"
	"strings"

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
	body, err := readWorkloadInput(context.Background(), os.Stdin, workload.MaxBytes)
	if err != nil || len(body) > workload.MaxBytes {
		return errors.New("resource envelope exceeds its deadline or size bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
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
	if err := p.Check(); err != nil {
		return err
	}
	if err := installedServingBudget(p); err != nil {
		return err
	}
	return workload.WritePrivateJSON(*policyPath, p)
}

func installedServingBudget(p workload.Policy) error {
	if p.Resources == nil || !strings.HasPrefix(p.Resources.CgroupParent, "/komizo-production/") {
		return nil
	}
	var host workload.HostResources
	if err := protectedActivationJSON("/etc/komizo/resources.json", &host); err != nil {
		return errors.New("installed host serving allocation is unavailable")
	}
	memory, err := hostMemoryBytes()
	if err != nil {
		return err
	}
	if err := host.Check(memory, int64(runtime.NumCPU())*1000); err != nil {
		return err
	}
	return host.CheckServingBudget(p.App, p.Resources)
}
