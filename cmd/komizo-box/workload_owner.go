package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/internal/workload"
)

func typedOwnerVerb(ctx context.Context, verb string, sub subject, svc, by string) (bool, error) {
	if sub.app == "" || (verb != "start" && verb != "stop" && verb != "restart") {
		return false, nil
	}
	path := filepath.Join(sub.root, workloadPolicyDirectory, sub.app+".json")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return true, err
	}
	p, err := readWorkloadPolicy(path)
	if err != nil {
		return true, err
	}
	if p.Deployment == nil || p.Static != nil {
		return false, nil
	}
	if p.App != sub.app || p.AppDir != sub.dir {
		return true, errors.New("lifecycle subject differs from protected deployment authority")
	}
	h := newHostActivation()
	h.root = sub.root
	h.policies = filepath.Join(sub.root, workloadPolicyDirectory)
	h.releases = filepath.Join(sub.root, releaseDirectory)
	h.policy = p
	return true, h.performTypedOwner(ctx, verb, sub, svc, by, filepath.Join(sub.root, activationDirectory))
}

func (h *hostActivation) performTypedOwner(parent context.Context, verb string, sub subject, svc, by, queue string) error {
	// Intent is durable even if a deployment still owns the app lock. The
	// activation worker observes it before acknowledging readiness.
	if verb == "stop" && svc == "" {
		if err := box.MarkStopped(sub.root, sub.app, by, time.Now()); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	lockCtx, lockCancel := context.WithTimeout(ctx, 60*time.Second)
	defer lockCancel()
	unlock, err := box.LockDeployment(lockCtx, sub.root, sub.app)
	if err != nil {
		return err
	}
	defer unlock()
	p := h.policy
	var currentPolicy workload.Policy
	if err := h.readJSON(filepath.Join(h.policies, sub.app+".json"), &currentPolicy); err != nil {
		return err
	}
	before, _ := json.Marshal(p)
	after, _ := json.Marshal(currentPolicy)
	if string(before) != string(after) {
		return errors.New("protected lifecycle policy changed while acquiring deployment locks")
	}
	if verb != "stop" {
		if err := activationIdle(queue); err != nil {
			return err
		}
		var op workload.Operation
		if err := h.readJSON(filepath.Join(h.releases, p.App, "operation.json"), &op); err != nil {
			return err
		}
		switch op.Phase {
		case "ready", "prepared_stopped", "activated", "reconciled":
		default:
			return errors.New("interrupted deployment must be reconciled before lifecycle startup")
		}
	}
	composePath := filepath.Join(p.AppDir, "compose.yml")
	body, err := h.readBytes(composePath)
	if err != nil {
		return err
	}
	var doc struct {
		Services map[string]json.RawMessage `json:"services"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return errors.New("invalid approved compose")
	}
	if svc != "" {
		if _, exists := doc.Services[svc]; !exists {
			return errors.New("service is outside the approved workload")
		}
	}
	args := []string{"compose", "--project-name", p.App, "--project-directory", p.AppDir, "-f", composePath}
	if verb == "stop" {
		args = append(args, "stop")
		if svc != "" {
			args = append(args, svc)
		}
		_, err := h.run(ctx, args...)
		return err
	}
	state, err := box.StateRevision(sub.root, sub.app)
	if err != nil {
		return err
	}
	stopped, err := box.IsStopped(sub.root, sub.app)
	if err != nil {
		return err
	}
	if stopped && (verb == "restart" || svc != "") {
		return errors.New("start the whole stopped workload explicitly")
	}
	if err := box.RefuseScopedStart(sub.root, sub.app); err != nil {
		return err
	}
	env, err := h.readBytes(filepath.Join(p.AppDir, ".env"))
	if err != nil {
		return err
	}
	version, err := deploymentVersion(env)
	if err != nil || version == "" {
		return errors.New("lifecycle needs the current accepted source revision")
	}
	// Current retention, protected acceptance and immutable local identities
	// bound owner startup too; it cannot start a half-staged candidate.
	retained, err := h.readBytes(filepath.Join(p.AppDir, ".komizo-image-retention"))
	if err != nil {
		return err
	}
	current, _, err := parseRetainedRevisions(retained)
	if err != nil || current != version {
		return errors.New("lifecycle revision differs from current retention")
	}
	var accepted workload.ReleaseAcceptance
	if err := h.readJSON(filepath.Join(h.releases, p.App, version+".json"), &accepted); err != nil {
		return err
	}
	if _, err := workload.BindLocalRelease(ctx, h.run, p, accepted, version, p.ImagePrefix+"config:"+version, body); err != nil {
		return err
	}
	if verb == "restart" {
		running, err := h.run(ctx, append(append([]string{}, args...), "ps", "-q")...)
		if err != nil || strings.TrimSpace(running) == "" {
			return errors.New("there are no running containers to restart")
		}
		args = append(args, "restart")
	} else {
		args = append(args, "up", "-d", "--remove-orphans", "--pull", "never")
	}
	if svc != "" {
		args = append(args, svc)
	}
	if _, err := h.run(ctx, args...); err != nil {
		return err
	}
	stopAfterChange := func() error {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return h.Compose(cleanup, workload.ActivationRequest{App: p.App}, "stop")
	}
	for {
		now, err := box.StateRevision(sub.root, sub.app)
		if err != nil {
			return err
		}
		if now != state {
			stopAfterChange()
			return workload.ErrActivationStopped
		}
		if p.Readiness == nil {
			break
		}
		err = workload.VerifyReadiness(ctx, h.run, h.staticClient(), p, version, composePath, body)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return errors.New("owner lifecycle readiness did not pass")
		case <-time.After(2 * time.Second):
		}
	}
	if verb == "start" && svc == "" {
		cleared, err := box.ClearStoppedIfUnchanged(sub.root, sub.app, state)
		if err != nil {
			return errors.Join(err, stopAfterChange())
		}
		if !cleared {
			stopAfterChange()
			return workload.ErrActivationStopped
		}
	}
	return nil
}
