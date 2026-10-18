package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nicodes/komizo/internal/workload"
)

// emptyRegistration proves absence of serving effects; it never creates a
// retention record or treats an admitted release as a serving release.
func (h *hostActivation) emptyRegistration(ctx context.Context, p workload.Policy, dir string) error {
	for _, path := range []string{filepath.Join(p.AppDir, ".komizo-image-retention"), filepath.Join(p.AppDir, "hostnames"), p.Deployment.RoutePath} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return errors.New("initial registration has serving metadata")
		}
	}
	env, err := h.readBytes(filepath.Join(p.AppDir, ".env"))
	if err != nil || len(bytes.TrimSpace(env)) != 0 {
		return errors.New("initial registration has installed environment")
	}
	compose, err := h.readBytes(filepath.Join(p.AppDir, "compose.yml"))
	if err != nil || !bytes.Equal(bytes.TrimSpace(compose), []byte("services: {}")) {
		return errors.New("initial registration has installed services")
	}
	containers, err := h.run(ctx, "ps", "-aq", "--filter", "label=com.docker.compose.project="+p.App)
	if err != nil || strings.TrimSpace(containers) != "" {
		return errors.New("initial registration has container objects or cannot be inspected")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "staging-") {
			return errors.New("initial registration has a configuration snapshot")
		}
	}
	return nil
}

func (h *hostActivation) reconcileInitial(ctx context.Context, r reconciliationRequest, op workload.Operation, dir string) (map[string]any, error) {
	if r.Serving != "" || op.Previous != "" || (op.Phase != "staging" && op.Phase != "staging_failed") {
		return nil, errors.New("initial reconciliation requires an early first-deployment refusal")
	}
	if err := h.emptyRegistration(ctx, h.policy, dir); err != nil {
		return nil, err
	}
	result := map[string]any{"version": 1, "operation_id": op.ID, "app": op.App, "candidate": op.Candidate, "outcome": r.Outcome, "serving": "", "application_restart": false, "database_restore": false, "provider_retry": false, "at": time.Now().UTC()}
	if err := workload.WritePrivateJSON(filepath.Join(dir, "reconciliation-"+op.ID+".json"), result); err != nil {
		return nil, err
	}
	if err := workload.RecordOperation(filepath.Join(dir, "operation.json"), op.App, op.Candidate, "", "reconciled", time.Now().UTC()); err != nil {
		return nil, err
	}
	return result, nil
}

// A fresh authenticated proof has already bound the cached receipt. This
// exception applies only before there is any retained serving release.
func (h *hostActivation) initialRetryAllowed(ctx context.Context, p workload.Policy, dir string) error {
	if p.Deployment == nil {
		return errors.New("initial retry requires protected deployment authority")
	}
	var op workload.Operation
	if _, err := os.Lstat(filepath.Join(dir, "operation.json")); err == nil {
		if err := h.readJSON(filepath.Join(dir, "operation.json"), &op); err != nil {
			return err
		}
		if op.App != p.App || op.Version != 1 || op.Previous != "" || op.Phase != "reconciled" || !reconciliationIdentity(op.ID, 32) {
			return errors.New("initial deployment requires explicit reconciliation")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return h.emptyRegistration(ctx, p, dir)
}
