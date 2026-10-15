package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"time"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/internal/workload"
)

// Only the root operator can initialize authority, and only from the exact
// empty registration policy. Established authority requires the existing
// reviewed platform migration; setup cannot replace it or erase a fence.
func runWorkloadPolicyBootstrap(args []string) error {
	fs := flag.NewFlagSet("policy-bootstrap", flag.ContinueOnError)
	app := fs.String("app", "", "registered application")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 || fs.NArg() != 0 || *app == "" {
		return errors.New("policy bootstrap requires root and a registered application")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	body, err := readWorkloadInput(ctx, os.Stdin, workload.MaxBytes)
	if err != nil {
		return err
	}
	next, err := workload.ReadPolicy(bytes.NewReader(body))
	if err != nil {
		return err
	}
	unlock, err := box.LockDeployment(ctx, "", *app)
	if err != nil {
		return err
	}
	defer unlock()
	if err := activationIdle(activationDirectory); err != nil {
		return err
	}
	settings, err := box.AppSettings("", *app)
	if err != nil {
		return err
	}
	base, err := workload.NewPolicy(*app, settings["APP_DIR"], settings["CONFIG_IMAGE"], next.SharedNetwork)
	if err != nil {
		return err
	}
	path := filepath.Join(workloadPolicyDirectory, *app+".json")
	existing, err := readWorkloadPolicy(path)
	if err != nil {
		return err
	}
	next, err = enabledDeploymentPolicy(next)
	if err != nil {
		return err
	}
	compose, err := protectedActivationBytes(filepath.Join(base.AppDir, "compose.yml"))
	if err != nil {
		return err
	}
	environment, err := protectedActivationBytes(filepath.Join(base.AppDir, ".env"))
	if err != nil {
		return err
	}
	hasServingState, err := bootstrapServingState(compose, environment, fileExists(filepath.Join(releaseDirectory, *app, "operation.json")) || fileExists(filepath.Join(base.AppDir, ".komizo-image-retention")))
	if err != nil {
		return err
	}
	if err := checkBootstrapPolicy(base, existing, next, hasServingState); err != nil {
		return err
	}
	if err := installedServingBudget(next); err != nil {
		return err
	}
	if err := workload.WritePrivateJSON(path, next); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"version": 1, "app": *app, "installed": true, "deployment_enabled": true})
}

func bootstrapServingState(compose, environment []byte, retained bool) (bool, error) {
	version, err := deploymentVersion(environment)
	if err != nil {
		return true, err
	}
	return retained || version != "" || !bytes.Equal(bytes.TrimSpace(compose), []byte("services: {}")), nil
}

func checkBootstrapPolicy(base, existing, next workload.Policy, hasOperation bool) error {
	equal := func(a, b workload.Policy) bool {
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		return bytes.Equal(x, y)
	}
	if next.App != base.App || next.AppDir != base.AppDir || next.ImagePrefix != base.ImagePrefix || next.SharedNetwork != base.SharedNetwork {
		return errors.New("bootstrap policy does not match registered authority")
	}
	if equal(existing, next) {
		return nil
	}
	if hasOperation || !equal(existing, base) {
		return errors.New("established policy cannot change through setup; review a platform authority migration")
	}
	return nil
}
