package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/internal/workload"
)

const activationDirectory = "/var/lib/komizo/activations"
const releaseDirectory = "/var/lib/komizo/releases"
const workloadPolicyDirectory = "/etc/komizo/workloads"

func activationIdle(dir string) error {
	if _, err := os.Lstat(filepath.Join(dir, "pending.json")); os.IsNotExist(err) {
		return nil
	}
	return errors.New("host activation is pending; wait for its durable result before staging another deployment")
}

func protectedActivationJSON(path string, out any) error {
	var body json.RawMessage
	if err := readPrivateRelease(path, &body); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("activation needs one document")
	}
	return nil
}

func runWorkloadActivation(args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("host activation requires the local root operator")
	}
	if args[0] == "activation-idle" {
		if len(args) != 1 {
			return errors.New("activation-idle accepts no arguments")
		}
		return activationIdle(activationDirectory)
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	policy := fs.String("policy", "", "protected workload policy")
	candidate := fs.String("version", "", "configured candidate")
	previous := fs.String("previous", "", "previous revision")
	route := fs.String("route", "", "protected configured route")
	proxy := fs.String("proxy", "", "local proxy container")
	id := fs.String("id", "", "submitted operation identity")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("activation accepts no positional arguments")
	}
	if args[0] == "activation-wait" {
		if len(*id) != 32 || strings.Trim(*id, "0123456789abcdef") != "" {
			return errors.New("invalid operation identity")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
		defer cancel()
		result, err := waitActivation(ctx, activationDirectory, *id, protectedActivationJSON)
		if err != nil {
			return err
		}
		if !result.OK || result.Started == nil {
			return fmt.Errorf("activation %s: %s; inspect the durable operation before retrying", result.ID, result.Phase)
		}
		if *result.Started {
			fmt.Println("deploy: started=yes")
		} else {
			fmt.Println("deploy: started=no")
		}
		fmt.Printf("deploy: operation=%s phase=%s\n", result.ID, result.Phase)
		return nil
	}
	if args[0] != "activation-submit" {
		return errors.New("unknown activation command")
	}
	p, err := readWorkloadPolicy(*policy)
	if err != nil {
		return err
	}
	if *policy != filepath.Join(workloadPolicyDirectory, p.App+".json") {
		return errors.New("activation uses the installed workload policy")
	}
	var op workload.Operation
	if err := protectedActivationJSON(filepath.Join(releaseDirectory, p.App, "operation.json"), &op); err != nil {
		return err
	}
	if op.Phase != "configured" || op.Candidate != *candidate || op.Previous != *previous {
		return errors.New("activation needs the matching configured operation")
	}
	r := workload.ActivationRequest{Version: 1, ID: op.ID, App: p.App, Candidate: op.Candidate, Previous: op.Previous, Deadline: op.Deadline, RoutePath: *route, Proxy: *proxy}
	for _, item := range []struct {
		path string
		hash *string
	}{{*policy, &r.PolicySHA256}, {filepath.Join(p.AppDir, "compose.yml"), &r.ComposeSHA256}, {*route, &r.RouteSHA256}} {
		body, err := protectedActivationBytes(item.path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		*item.hash = hex.EncodeToString(sum[:])
	}
	if err := r.Check(time.Now()); err != nil {
		return err
	}
	if err := protectedReleaseDirectory(activationDirectory); err != nil {
		return err
	}
	if err := activationIdle(activationDirectory); err != nil {
		return err
	}
	// Submission runs under the deploy script's app and host locks. Rootd is
	// the only consumer; the pending marker also guards staging after handoff.
	if err := workload.WritePrivateJSON(filepath.Join(activationDirectory, "pending.json"), r); err != nil {
		return err
	}
	fmt.Println(r.ID)
	return nil
}

func protectedActivationBytes(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || !workloadRootOwner(info) || info.Size() > workload.MaxBytes {
		return nil, errors.New("activation input is not a bounded protected root file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, workload.MaxBytes+1))
	if err != nil || len(b) > workload.MaxBytes {
		return nil, errors.New("activation input exceeds its bound")
	}
	return b, nil
}

func waitActivation(ctx context.Context, dir, id string, read func(string, any) error) (workload.ActivationResult, error) {
	for {
		var result workload.ActivationResult
		err := read(filepath.Join(dir, id+".json"), &result)
		if err == nil {
			if result.Version != 1 || result.ID != id {
				return result, errors.New("activation result identity differs")
			}
			return result, nil
		}
		if _, statErr := os.Lstat(filepath.Join(dir, id+".json")); !os.IsNotExist(statErr) {
			return result, err
		}
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

type hostActivation struct {
	policies, releases, root string
	run                      workload.ImageRun
	readJSON                 func(string, any) error
	readBytes                func(string) ([]byte, error)
	policy                   workload.Policy
}

func newHostActivation() *hostActivation {
	return &hostActivation{policies: workloadPolicyDirectory, releases: releaseDirectory, run: dockerReleaseRun, readJSON: protectedActivationJSON, readBytes: protectedActivationBytes}
}
func (h *hostActivation) operation(r workload.ActivationRequest) (workload.Operation, error) {
	var op workload.Operation
	err := h.readJSON(filepath.Join(h.releases, r.App, "operation.json"), &op)
	if err == nil && (op.Version != 1 || op.ID != r.ID || op.Candidate != r.Candidate || op.Previous != r.Previous || !op.Deadline.Equal(r.Deadline)) {
		err = errors.New("activation no longer owns the durable operation")
	}
	return op, err
}
func (h *hostActivation) Verify(ctx context.Context, r workload.ActivationRequest) error {
	op, err := h.operation(r)
	if err != nil {
		return err
	}
	if op.Phase != "configured" {
		return workload.ErrActivationReconciliation
	}
	for _, item := range []struct{ path, hash string }{{filepath.Join(h.policies, r.App+".json"), r.PolicySHA256}, {r.RoutePath, r.RouteSHA256}} {
		body, err := h.readBytes(item.path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != item.hash {
			return errors.New("configured activation input changed")
		}
		if filepath.Dir(item.path) == h.policies {
			h.policy, err = workload.ReadPolicy(bytes.NewReader(body))
			if err != nil {
				return err
			}
		}
	}
	if h.policy.App != r.App {
		return errors.New("activation policy identity differs")
	}
	compose, err := h.readBytes(filepath.Join(h.policy.AppDir, "compose.yml"))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(compose)
	if hex.EncodeToString(sum[:]) != r.ComposeSHA256 {
		return errors.New("configured compose changed")
	}
	env, err := h.readBytes(filepath.Join(h.policy.AppDir, ".env"))
	if err != nil {
		return err
	}
	version := ""
	for _, line := range strings.Split(string(env), "\n") {
		if strings.HasPrefix(line, "APP_VERSION=") {
			version = strings.TrimPrefix(line, "APP_VERSION=")
			break
		}
	}
	if version != r.Candidate {
		return errors.New("configured app revision differs")
	}
	if h.policy.SourceRepository != "" {
		var accepted workload.ReleaseAcceptance
		if err := h.readJSON(filepath.Join(h.releases, r.App, r.Candidate+".json"), &accepted); err != nil {
			return err
		}
		if _, err := workload.BindLocalRelease(ctx, h.run, h.policy, accepted, r.Candidate, h.policy.ImagePrefix+"config:"+r.Candidate, compose); err != nil {
			return err
		}
	}
	return nil
}
func (h *hostActivation) Stopped(ctx context.Context, r workload.ActivationRequest) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return box.IsStopped(h.root, r.App)
}
func (h *hostActivation) Compose(ctx context.Context, r workload.ActivationRequest, verb string) error {
	args := []string{"compose", "--project-name", r.App, "--project-directory", h.policy.AppDir, "-f", filepath.Join(h.policy.AppDir, "compose.yml")}
	switch verb {
	case "up":
		args = append(args, "up", "-d", "--remove-orphans", "--pull", "never")
	case "stop":
		args = append(args, "stop")
	default:
		return errors.New("invalid activation compose verb")
	}
	_, err := h.run(ctx, args...)
	return err
}
func (h *hostActivation) ReloadProxy(ctx context.Context, r workload.ActivationRequest) error {
	for _, verb := range []string{"validate", "reload"} {
		if _, err := h.run(ctx, "exec", r.Proxy, "caddy", verb, "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"); err != nil {
			return errors.New("complete candidate proxy configuration failed; loaded configuration retained")
		}
	}
	return nil
}
func (h *hostActivation) Retain(ctx context.Context, r workload.ActivationRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.Candidate != r.Previous {
		path := filepath.Join(h.policy.AppDir, ".komizo-image-retention")
		if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
			return errors.New("unsafe retention destination")
		}
		if err := writePrivateText(path, []byte("CURRENT="+r.Candidate+"\nPREVIOUS="+r.Previous+"\n")); err != nil {
			return err
		}
	}
	for _, path := range []string{filepath.Join(h.policy.AppDir, "compose.yml.prev"), filepath.Join(h.policy.AppDir, "hostnames.prev"), r.RoutePath + ".prev"} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
func writePrivateText(path string, body []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".komizo-retain-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(body); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}
func (h *hostActivation) Ready(parent context.Context, r workload.ActivationRequest) error {
	if h.policy.Readiness == nil {
		return workload.ErrReadinessUnspecified
	}
	body, err := h.readBytes(filepath.Join(h.policy.AppDir, "compose.yml"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for {
		if stopped, err := h.Stopped(ctx, r); err != nil {
			return err
		} else if stopped {
			return workload.ErrActivationStopped
		}
		err = workload.VerifyReadiness(ctx, h.run, client, h.policy, r.Candidate, filepath.Join(h.policy.AppDir, "compose.yml"), body)
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("candidate readiness did not pass before its deadline")
		case <-time.After(2 * time.Second):
		}
	}
}
func (h *hostActivation) Phase(r workload.ActivationRequest, phase string) error {
	if _, err := h.operation(r); err != nil {
		return err
	}
	return workload.RecordOperation(filepath.Join(h.releases, r.App, "operation.json"), r.App, r.Candidate, r.Previous, phase, time.Now().UTC())
}

func activationPass(ctx context.Context, dir string, h *hostActivation) error {
	var request workload.ActivationRequest
	if _, err := os.Lstat(filepath.Join(dir, "pending.json")); os.IsNotExist(err) {
		return nil
	}
	if err := h.readJSON(filepath.Join(dir, "pending.json"), &request); err != nil {
		return err
	}
	// Reject malformed identities before constructing lock or result paths.
	if err := request.CheckIdentity(); err != nil {
		return err
	}
	lockCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	unlock, err := box.LockDeployment(lockCtx, h.root, request.App)
	if err != nil {
		return err
	}
	defer unlock()
	var result workload.ActivationResult
	op, opErr := h.operation(request)
	if opErr == nil && (op.Phase == "ready" || op.Phase == "prepared_stopped") {
		started := op.Phase == "ready"
		result = workload.ActivationResult{Version: 1, ID: request.ID, App: request.App, Candidate: request.Candidate, At: op.At, Phase: op.Phase, OK: true, Started: &started}
	} else {
		result, _ = workload.Activate(ctx, request, h)
	}
	if err := pruneActivationResults(dir); err != nil {
		return err
	}
	if err := workload.WritePrivateJSON(filepath.Join(dir, request.ID+".json"), result); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, "pending.json")); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}
func pruneActivationResults(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	type resultFile struct {
		name string
		at   time.Time
	}
	var results []resultFile
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") || len(name) != 37 || strings.Trim(strings.TrimSuffix(name, ".json"), "0123456789abcdef") != "" {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("unsafe activation result")
		}
		results = append(results, resultFile{name, info.ModTime()})
	}
	sort.Slice(results, func(i, j int) bool { return results[i].at.Before(results[j].at) })
	for i, item := range results {
		if i < len(results)-255 || time.Since(item.at) > 7*24*time.Hour {
			if err := os.Remove(filepath.Join(dir, item.name)); err != nil {
				return err
			}
		}
	}
	return nil
}
func activationLoop(ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	var lastError time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := activationPass(ctx, activationDirectory, newHostActivation()); err != nil && time.Since(lastError) > time.Minute {
				fmt.Fprintln(os.Stderr, "komizo-box: activation queue needs local operator inspection")
				lastError = time.Now()
			}
		}
	}
}
