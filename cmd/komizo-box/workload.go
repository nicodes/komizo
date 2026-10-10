package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nicodes/komizo/internal/workload"
)

func runWorkload(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "host-resources":
			return runHostResources(args[1:])
		case "image-refs":
			if len(args) != 1 {
				return errors.New("image-refs reads only standard input")
			}
			refs, err := workload.JSONImageReferences(os.Stdin)
			if err != nil {
				return err
			}
			for _, ref := range refs {
				fmt.Println(ref)
			}
			return nil
		case "capacity":
			return runWorkloadCapacity(args[1:])
		case "budgets":
			return runWorkloadBudgets(args[1:])
		case "ingress-name", "isolate-ingress":
			return runWorkloadIngress(args[1:], args[0] == "isolate-ingress")
		case "readiness":
			return runWorkloadReadinessPolicy(args[1:])
		case "trust", "release-admit", "release-bind", "release-bootstrap", "operation", "ready":
			return runWorkloadRelease(args)
		}
	}
	if len(args) == 0 || (args[0] != "init" && args[0] != "validate") {
		return errors.New("workload requires init or validate")
	}
	fs := flag.NewFlagSet("workload", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "root-owned policy document")
	app := fs.String("app", "", "app namespace")
	appDir := fs.String("app-dir", "", "root-owned app directory")
	configImage := fs.String("config-image", "", "approved configuration repository")
	network := fs.String("network", "edge", "approved shared ingress network")
	compose := fs.String("compose", "", "untrusted repository configuration")
	output := fs.String("output", "", "validated configuration destination")
	version := fs.String("version", "", "release revision")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *policyPath == "" {
		return errors.New("workload needs a policy path and no positional arguments")
	}
	if args[0] == "init" {
		p, err := workload.NewPolicy(*app, *appDir, *configImage, *network)
		if err != nil {
			return err
		}
		// Initialization never changes existing authority. Operators edit the policy
		// separately; re-running app provisioning cannot widen it from a new image.
		if _, err := os.Lstat(*policyPath); err == nil {
			old, err := readWorkloadPolicy(*policyPath)
			if err != nil {
				return err
			}
			authority := old
			authority.SourceRepository = ""
			authority.RepositoryID = ""
			authority.Resources = nil // provisioning retains the operator's envelope
			authority.Readiness = nil
			authority.IngressNetwork = ""
			if authority != p {
				return errors.New("existing workload policy differs; review an operator policy update")
			}
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
		data, err := json.MarshalIndent(p, "", "  ")
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(*policyPath), 0700); err != nil {
			return err
		}
		f, err := os.OpenFile(*policyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, writeErr := f.Write(append(data, '\n'))
		closeErr := f.Close()
		if writeErr != nil {
			return writeErr
		}
		return closeErr
	}
	if *compose == "" || *output == "" {
		return errors.New("workload validation needs compose and output paths")
	}
	p, err := readWorkloadPolicy(*policyPath)
	if err != nil {
		return err
	}
	if p.App != *app || p.AppDir != *appDir {
		return errors.New("workload policy does not match this deployment")
	}
	// Opening configuration does not follow a symlink out of the staging area.
	info, err := os.Lstat(*compose)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("workload configuration must be a regular file")
	}
	f, err := os.Open(*compose)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := workload.Validate(f, p, *version)
	if err != nil {
		return err
	}
	// Output is new and private. No untrusted Compose parser has run yet.
	out, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := out.Write(append(bytes.TrimSpace(data), '\n'))
	closeErr := out.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	fmt.Fprintln(os.Stdout, "workload: host policy accepted")
	return nil
}

func readWorkloadPolicy(path string) (workload.Policy, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return workload.Policy{}, errors.New("workload policy must be a protected regular file")
	}
	if !workloadRootOwner(info) {
		return workload.Policy{}, errors.New("workload policy must be root-owned")
	}
	f, err := os.Open(path)
	if err != nil {
		return workload.Policy{}, err
	}
	defer f.Close()
	return workload.ReadPolicy(f)
}
