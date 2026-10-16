package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/internal/workload"
)

type reconciliationRequest struct {
	ID           string
	Candidate    string
	PolicySHA256 string
	Phase        string
	Serving      string
	Outcome      string
}

func runWorkloadReconciliation(args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("reconciliation requires the local root operator")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	policy := fs.String("policy", "", "installed protected policy")
	r := reconciliationRequest{}
	fs.StringVar(&r.ID, "id", "", "exact interrupted operation")
	fs.StringVar(&r.Candidate, "version", "", "exact candidate")
	fs.StringVar(&r.PolicySHA256, "policy-sha256", "", "reviewed policy bytes")
	fs.StringVar(&r.Phase, "expected-phase", "", "reviewed interrupted phase")
	fs.StringVar(&r.Serving, "serving-version", "", "revision whose serving identity must be established")
	fs.StringVar(&r.Outcome, "outcome", "", "restore-serving or accept-candidate")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("reconciliation accepts no positional arguments")
	}
	p, err := readWorkloadPolicy(*policy)
	if err != nil {
		return err
	}
	if *policy != filepath.Join(workloadPolicyDirectory, p.App+".json") {
		return errors.New("reconciliation uses the installed policy")
	}
	h := newHostActivation()
	h.policy = p
	if args[0] == "inspect" {
		var op workload.Operation
		if err := h.readJSON(filepath.Join(h.releases, p.App, "operation.json"), &op); err != nil {
			return err
		}
		body, err := h.readBytes(*policy)
		if err != nil {
			return err
		}
		if op.App != p.App || op.Version != 1 || !reconciliationIdentity(op.ID, 32) || !workload.KnownOperationPhase(op.Phase) {
			return errors.New("unknown operation identity or vocabulary; mutation refused")
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"operation": op, "policy_sha256": deploymentHash(body), "snapshot_retained": fileExists(filepath.Join(h.releases, p.App, "staging-"+op.ID+".json")), "private_bodies_omitted": true})
	}
	result, err := h.reconcile(context.Background(), r, activationDirectory)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func fileExists(path string) bool { _, err := os.Lstat(path); return err == nil }
func reconciliationIdentity(value string, size int) bool {
	return len(value) == size && strings.Trim(value, "0123456789abcdef") == ""
}

// reconcile never starts/restarts a binary, pulls an image, restores data or
// retries provider work. Interrupted writes are repeatable from the same retained
// snapshot; the fence closes only after local artifacts and serving postconditions.
func (h *hostActivation) reconcile(parent context.Context, r reconciliationRequest, queue string) (map[string]any, error) {
	if !reconciliationIdentity(r.ID, 32) || !reconciliationIdentity(r.Candidate, 40) || !reconciliationIdentity(r.Serving, 40) || !reconciliationIdentity(r.PolicySHA256, 64) {
		return nil, errors.New("reconciliation requires exact reviewed identities")
	}
	if r.Outcome != "restore-serving" && r.Outcome != "accept-candidate" {
		return nil, errors.New("unknown reconciliation outcome")
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	unlock, err := box.LockDeployment(ctx, h.root, h.policy.App)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := activationIdle(queue); err != nil {
		return nil, err
	}
	p := h.policy
	policyBytes, err := h.readBytes(filepath.Join(h.policies, p.App+".json"))
	if err != nil || deploymentHash(policyBytes) != r.PolicySHA256 {
		return nil, errors.New("reviewed reconciliation policy changed")
	}
	current, err := workload.ReadPolicy(bytes.NewReader(policyBytes))
	if err != nil || current.App != p.App || current.Deployment == nil {
		return nil, errors.New("protected deployment authority required")
	}
	h.policy = current
	p = current
	if r.Outcome == "accept-candidate" && p.Static != nil {
		return nil, errors.New("static candidates require their existing ready retention; use restore-serving for initial conversion")
	}
	path := filepath.Join(h.releases, p.App, "operation.json")
	var op workload.Operation
	if err := h.readJSON(path, &op); err != nil {
		return nil, err
	}
	if op.Version != 1 || op.App != p.App || op.ID != r.ID || op.Candidate != r.Candidate || op.Phase != r.Phase {
		return nil, errors.New("reviewed operation changed")
	}
	switch op.Phase {
	case "staging", "staging_failed", "configured", "activating", "activation_failed", "readiness_failed", "failed":
	default:
		return nil, errors.New("operation is not an interrupted reconciliation fence")
	}
	composePath := filepath.Join(p.AppDir, "compose.yml")
	compose, err := h.readBytes(composePath)
	if err != nil {
		return nil, err
	}
	var snapshot deploymentSnapshot
	restoreConfiguration := false
	if r.Outcome == "restore-serving" {
		if p.RequireStatefulContract && op.Phase != "staging" && op.Phase != "staging_failed" && op.Phase != "configured" {
			return nil, errors.New("stateful activation may have written data; configuration restoration cannot establish compatibility")
		}
		if r.Serving != op.Previous {
			return nil, errors.New("restore-serving requires the existing previous revision")
		}
		snapshotErr := h.readSnapshot(filepath.Join(h.releases, p.App, "staging-"+op.ID+".json"), &snapshot)
		if snapshotErr != nil {
			// Staging persists this snapshot before its first configuration write.
			// An early refusal can therefore retain the original serving files
			// without having a snapshot to restore. Prove the current revision,
			// retained images and serving identity instead; later phases and
			// unreadable/corrupt snapshots still require the ordinary snapshot.
			if !os.IsNotExist(snapshotErr) || p.Static != nil || (op.Phase != "staging" && op.Phase != "staging_failed") {
				return nil, snapshotErr
			}
			env, err := h.readBytes(filepath.Join(p.AppDir, ".env"))
			if err != nil {
				return nil, err
			}
			if version, err := deploymentVersion(env); err != nil || version != r.Serving {
				return nil, errors.New("early staging refusal requires the unchanged serving revision")
			}
			snapshot = deploymentSnapshot{}
		} else {
			restoreConfiguration = true
		}
		allowed := []string{composePath, p.Deployment.RoutePath, filepath.Join(p.AppDir, "hostnames"), filepath.Join(p.AppDir, ".env")}
		if restoreConfiguration && (snapshot.Version != 1 || snapshot.ID != op.ID || len(snapshot.Files) != len(allowed)) {
			return nil, errors.New("snapshot identity differs")
		}
		for i, file := range snapshot.Files {
			if file.Path != allowed[i] || !file.Exists || file.Mode&0022 != 0 || file.Mode & ^uint32(0777) != 0 || len(file.Body) > workload.MaxBytes {
				return nil, errors.New("snapshot is outside the four protected configuration files")
			}
		}
		if restoreConfiguration {
			if version, err := deploymentVersion(snapshot.Files[3].Body); err != nil || version != r.Serving {
				return nil, errors.New("snapshot revision differs")
			}
			compose = snapshot.Files[0].Body
		}
	} else if r.Serving != op.Candidate {
		return nil, errors.New("accept-candidate requires the exact candidate")
	}
	retained, err := h.readBytes(filepath.Join(p.AppDir, ".komizo-image-retention"))
	if r.Outcome == "restore-serving" {
		current, _, parseErr := parseRetainedRevisions(retained)
		if err != nil || parseErr != nil || current != r.Serving {
			return nil, errors.New("restoration requires the still-retained serving release")
		}
	}
	var accepted workload.ReleaseAcceptance
	if err := h.readJSON(filepath.Join(h.releases, p.App, r.Serving+".json"), &accepted); err != nil {
		return nil, err
	}
	if _, err := workload.BindLocalRelease(ctx, h.run, p, accepted, r.Serving, p.ImagePrefix+"config:"+r.Serving, compose); err != nil {
		return nil, err
	}
	state, err := box.StateRevision(h.root, p.App)
	if err != nil {
		return nil, err
	}
	stopped, err := box.IsStopped(h.root, p.App)
	if err != nil {
		return nil, err
	}
	verify := func() error {
		if h.reconciliationReady != nil {
			return h.reconciliationReady(ctx, r.Serving, compose)
		}
		if p.Static != nil {
			return workload.VerifyStaticReadiness(ctx, h.run, h.staticClient(), p, r.Serving)
		}
		return workload.VerifyReadiness(ctx, h.run, h.staticClient(), p, r.Serving, composePath, compose)
	}
	if stopped {
		return nil, errors.New("owner stop retained; explicitly reconcile while stopped after serving identity review")
	}
	if err := verify(); err != nil {
		return nil, fmt.Errorf("existing serving identity unavailable: %w", err)
	}
	if restoreConfiguration {
		if err := restoreDeploymentSnapshot(snapshot, h.writeDeployment); err != nil {
			return nil, err
		}
		h.deploymentCheckpoint("reconcile_configuration")
	}
	activation := workload.ActivationRequest{App: p.App, ID: op.ID, Candidate: r.Serving, Previous: op.Previous, Proxy: p.Deployment.Proxy, RoutePath: p.Deployment.RoutePath}
	if err := h.ReloadProxy(ctx, activation); err != nil {
		return nil, err
	}
	if now, err := box.StateRevision(h.root, p.App); err != nil || now != state {
		_ = h.composeWorkload(ctx, activation, "stop")
		return nil, workload.ErrActivationStopped
	}
	if err := verify(); err != nil {
		return nil, err
	}
	if now, err := box.StateRevision(h.root, p.App); err != nil || now != state {
		_ = h.composeWorkload(ctx, activation, "stop")
		return nil, workload.ErrActivationStopped
	}
	if r.Outcome == "accept-candidate" {
		if err := h.retainWorkload(activation); err != nil {
			return nil, err
		}
	}
	result := map[string]any{"version": 1, "operation_id": op.ID, "app": p.App, "candidate": op.Candidate, "serving": r.Serving, "outcome": r.Outcome, "configuration_restored": restoreConfiguration, "application_restart": false, "database_restore": false, "provider_retry": false, "at": time.Now().UTC()}
	if err := workload.WritePrivateJSON(filepath.Join(h.releases, p.App, "reconciliation-"+op.ID+".json"), result); err != nil {
		return nil, err
	}
	if err := workload.RecordOperation(path, p.App, op.Candidate, op.Previous, "reconciled", time.Now().UTC()); err != nil {
		return nil, err
	}
	return result, nil
}

func (h *hostActivation) readSnapshot(path string, out any) error {
	if h.reconciliationSnapshot != nil {
		return h.reconciliationSnapshot(path, out)
	}
	file, err := os.OpenFile(path, os.O_RDONLY|oNoFollow|oNonBlock, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !workloadRootOwner(info) || info.Mode().Perm()&0077 != 0 || info.Size() > 4<<20 {
		return errors.New("snapshot must be a bounded private root file")
	}
	body, err := io.ReadAll(io.LimitReader(file, (4<<20)+1))
	if err != nil || len(body) > 4<<20 {
		return errors.New("snapshot exceeds its byte bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("snapshot must contain one document")
	}
	return nil
}
