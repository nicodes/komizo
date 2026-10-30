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
		case "capabilities":
			if len(args) != 1 {
				return errors.New("workload capabilities accepts no arguments")
			}
			return json.NewEncoder(os.Stdout).Encode(map[string]any{"version": 1, "policy_bootstrap": true, "typed_deployment": true, "operation_contract_version": 1})
		case "policy-bootstrap":
			return runWorkloadPolicyBootstrap(args[1:])
		case "scoped-definition-check":
			return runScopedDefinitionCheck(args[1:])
		case "policy-check":
			return runWorkloadPolicyCheck(args[1:])
		case "routine-backup", "backup-inspect":
			return runRoutineBackup(args)
		case "owner-task":
			return runWorkloadTask(args[1:], true)
		case "task":
			return runWorkloadTask(args[1:], false)
		case "release-secrets", "owner-secret", "legacy-secrets-allowed":
			return runWorkloadSecrets(args)
		case "delivery-enable", "delivery-authorize":
			return runWorkloadDelivery(args)
		case "inspect", "reconcile":
			return runWorkloadReconciliation(args)
		case "operation-contract":
			if len(args) != 1 {
				return errors.New("operation-contract accepts no arguments")
			}
			_, err := os.Stdout.Write(workload.OperationContract())
			return err
		case "deployment-enable", "deployment-enabled", "deployment-submit":
			return runWorkloadDeployment(args)
		case "activation-idle", "activation-submit", "activation-wait":
			return runWorkloadActivation(args)
		case "host-resources":
			return runHostResources(args[1:])
		case "startup-check":
			return runWorkloadStartupCheck(args[1:])
		case "proxy-budget":
			return runProxyBudget(args[1:])
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
		case "trust", "release-admit", "owner-recovery-admit", "release-bind", "release-bootstrap", "operation", "ready":
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
			authority.OwnerApproval = false
			authority.Resources = nil // provisioning retains the operator's envelope
			authority.Readiness = nil
			authority.IngressNetwork = ""
			authority.RequireDeliveryAuthorization = false
			authority.RequireStatefulContract = false // provisioning retains root's requirement
			authority.Static = nil                    // provisioning retains root's opt-in profile
			authority.Deployment = nil
			authority.RoutineBackup = nil
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

// Authority migration validates a policy without Compose or output paths.
// The ordinary validate verb still requires and bounds a complete workload.
func runWorkloadPolicyCheck(args []string) error {
	fs := flag.NewFlagSet("workload policy-check", flag.ContinueOnError)
	path := fs.String("policy", "", "protected policy candidate")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 || *path == "" || fs.NArg() != 0 {
		return errors.New("policy-check needs the root executor, one policy and no positional arguments")
	}
	_, err := readWorkloadPolicy(*path)
	return err
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
