package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/nicodes/komizo/internal/workload"
)

func runWorkloadReadinessPolicy(args []string) error {
	fs := flag.NewFlagSet("readiness", flag.ContinueOnError)
	path := fs.String("policy", "", "protected workload policy")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *path == "" || os.Geteuid() != 0 {
		return errors.New("readiness requires root and a policy path; reads reviewed probes from stdin")
	}
	p, err := readWorkloadPolicy(*path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, workload.MaxBytes+1))
	decoder.DisallowUnknownFields()
	var probes workload.ReadinessPolicy
	if err := decoder.Decode(&probes); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("readiness policy must contain one document")
	}
	if err := probes.Check(); err != nil {
		return err
	}
	p.Readiness = &probes
	return workload.WritePrivateJSON(*path, p)
}

func readyWorkload(p workload.Policy, candidate, previous, dir, composePath string) error {
	if p.Readiness == nil {
		return nil
	} // activation remains explicitly unverified
	if composePath != filepath.Join(p.AppDir, "compose.yml") {
		return errors.New("readiness uses only the active app configuration")
	}
	info, err := os.Lstat(composePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || !workloadRootOwner(info) {
		return errors.New("active workload must be protected")
	}
	body, err := os.ReadFile(composePath)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var failed error
	for {
		failed = workload.VerifyReadiness(ctx, dockerReleaseRun, client, p, candidate, composePath, body)
		if failed == nil {
			return workload.RecordOperation(filepath.Join(dir, "operation.json"), p.App, candidate, previous, "ready", time.Now().UTC())
		}
		select {
		case <-ctx.Done():
			_ = workload.RecordOperation(filepath.Join(dir, "operation.json"), p.App, candidate, previous, "readiness_failed", time.Now().UTC())
			return failed
		case <-time.After(2 * time.Second):
		}
	}
}
