package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/internal/workload"
)

func reconciliationFixture(t *testing.T) (*deploymentFixture, reconciliationRequest, map[string][]byte) {
	t.Helper()
	f := newDeploymentFixture(t)
	var policy workload.Policy
	if err := f.h.readJSON(filepath.Join(f.h.policies, "example.json"), &policy); err != nil {
		t.Fatal(err)
	}
	compose := []byte(`{"services":{"example-gate":{"image":"` + policy.ImagePrefix + `gate:` + f.r.Previous + `"}}}`)
	if err := os.WriteFile(filepath.Join(policy.AppDir, "compose.yml"), compose, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policy.AppDir, "hostnames"), []byte("example.test -> gate\n"), 0600); err != nil {
		t.Fatal(err)
	}
	before := map[string][]byte{}
	for _, path := range []string{filepath.Join(policy.AppDir, "compose.yml"), f.r.RoutePath, filepath.Join(policy.AppDir, "hostnames"), filepath.Join(policy.AppDir, ".env")} {
		before[path], _ = os.ReadFile(path)
	}
	if _, err := f.h.stageDeployment(context.Background(), f.r, f.queue); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.queue, "pending.json")); err != nil {
		t.Fatal(err)
	}
	var acceptance workload.ReleaseAcceptance
	if err := f.h.readJSON(filepath.Join(f.h.releases, "example", f.r.Candidate+".json"), &acceptance); err != nil {
		t.Fatal(err)
	}
	acceptance.Manifest.Revision = f.r.Previous
	images := map[string]string{}
	for ref, id := range acceptance.Manifest.Images {
		images[strings.ReplaceAll(ref, f.r.Candidate, f.r.Previous)] = id
	}
	acceptance.Manifest.Images = images
	if err := workload.WritePrivateJSON(filepath.Join(f.h.releases, "example", f.r.Previous+".json"), acceptance); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policy.AppDir, ".komizo-image-retention"), []byte("CURRENT="+f.r.Previous+"\nPREVIOUS=\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f.h.reconciliationSnapshot = f.h.readJSON
	f.h.reconciliationReady = func(_ context.Context, source string, body []byte) error {
		if source != f.r.Previous || string(body) != string(compose) {
			return errors.New("synthetic serving identity differs")
		}
		return nil
	}
	r := reconciliationRequest{ID: f.r.ID, Candidate: f.r.Candidate, PolicySHA256: f.r.PolicySHA256, Phase: "configured", Serving: f.r.Previous, Outcome: "restore-serving"}
	return f, r, before
}

func TestReconciliationRestoresOnlyFourConfigurationFilesAndProvesServing(t *testing.T) {
	f, r, before := reconciliationFixture(t)
	f.calls = nil
	result, err := f.h.reconcile(context.Background(), r, f.queue)
	if err != nil {
		t.Fatal(err)
	}
	for path, body := range before {
		after, _ := os.ReadFile(path)
		if string(after) != string(body) {
			t.Fatalf("configuration not restored: %s", filepath.Base(path))
		}
	}
	if result["serving"] != r.Serving || result["database_restore"] != false || result["application_restart"] != false {
		t.Fatal(result)
	}
	for _, call := range f.calls {
		if strings.Contains(call, "pull") || strings.Contains(call, " up ") || strings.Contains(call, "restart") {
			t.Fatal("reconciliation restarted or downloaded code")
		}
	}
	var op workload.Operation
	if err := f.h.readJSON(filepath.Join(f.h.releases, "example/operation.json"), &op); err != nil || op.Phase != "reconciled" {
		t.Fatal(op, err)
	}
	body, _ := json.Marshal(result)
	if strings.Contains(string(body), "synthetic-fixture-only") {
		t.Fatal("private snapshot body escaped")
	}
}

func TestReconciliationRefusesChangedIdentityPolicyQueueAndForeignSnapshot(t *testing.T) {
	for _, condition := range []string{"identity", "policy", "queue", "snapshot", "serving"} {
		t.Run(condition, func(t *testing.T) {
			f, r, before := reconciliationFixture(t)
			switch condition {
			case "identity":
				r.ID = strings.Repeat("f", 32)
			case "policy":
				r.PolicySHA256 = strings.Repeat("f", 64)
			case "queue":
				os.WriteFile(filepath.Join(f.queue, "pending.json"), []byte(`{}`), 0600)
			case "snapshot":
				original := f.h.reconciliationSnapshot
				f.h.reconciliationSnapshot = func(path string, out any) error {
					if err := original(path, out); err != nil {
						return err
					}
					out.(*deploymentSnapshot).Files[0].Path = filepath.Join(f.h.root, "foreign")
					return nil
				}
			case "serving":
				f.h.reconciliationReady = func(context.Context, string, []byte) error { return errors.New("unverified serving identity") }
			}
			current, _ := os.ReadFile(filepath.Join(f.h.policy.AppDir, "compose.yml"))
			if _, err := f.h.reconcile(context.Background(), r, f.queue); err == nil {
				t.Fatal("invalid reconciliation accepted")
			}
			after, _ := os.ReadFile(filepath.Join(f.h.policy.AppDir, "compose.yml"))
			if string(current) != string(after) {
				t.Fatal("refused reconciliation changed configuration")
			}
			_ = before
		})
	}
}

func TestReconciliationFailureKeepsFenceAndNewOwnerStop(t *testing.T) {
	for _, stop := range []bool{false, true} {
		f, r, _ := reconciliationFixture(t)
		original := f.h.run
		f.h.run = func(ctx context.Context, args ...string) (string, error) {
			if len(args) > 0 && args[0] == "exec" {
				if stop {
					if err := box.MarkStopped(f.h.root, "example", "fixture-owner", time.Now()); err != nil {
						t.Fatal(err)
					}
				} else {
					return "", errors.New("synthetic proxy refusal")
				}
			}
			return original(ctx, args...)
		}
		if _, err := f.h.reconcile(context.Background(), r, f.queue); err == nil {
			t.Fatal("failed postcondition acknowledged")
		}
		var op workload.Operation
		f.h.readJSON(filepath.Join(f.h.releases, "example/operation.json"), &op)
		if op.Phase != "configured" {
			t.Fatal("failure closed the fence")
		}
		if stop {
			stopped, err := box.IsStopped(f.h.root, "example")
			if err != nil || !stopped {
				t.Fatal("new stop intent lost")
			}
		}
	}
}

func TestReconciliationOfEarlyRefusalWithoutSnapshotProvesExistingServing(t *testing.T) {
	for _, phase := range []string{"staging", "staging_failed"} {
		t.Run(phase, func(t *testing.T) {
			f, r, before := reconciliationFixture(t)
			for path, body := range before {
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Remove(filepath.Join(f.h.releases, "example", "staging-"+r.ID+".json")); err != nil {
				t.Fatal(err)
			}
			r.Phase = phase
			var op workload.Operation
			if err := f.h.readJSON(filepath.Join(f.h.releases, "example", "operation.json"), &op); err != nil {
				t.Fatal(err)
			}
			op.Phase = phase
			if err := workload.WritePrivateJSON(filepath.Join(f.h.releases, "example", "operation.json"), op); err != nil {
				t.Fatal(err)
			}
			writes := 0
			f.h.deploymentWrite = func(string, []byte, os.FileMode) error {
				writes++
				return errors.New("early refusal must preserve serving files")
			}
			f.calls = nil
			result, err := f.h.reconcile(t.Context(), r, f.queue)
			if err != nil {
				t.Fatal(err)
			}
			if writes != 0 || result["configuration_restored"] != false || result["application_restart"] != false || result["database_restore"] != false {
				t.Fatal(result, writes)
			}
			for path, body := range before {
				after, err := os.ReadFile(path)
				if err != nil || string(after) != string(body) {
					t.Fatal("serving file changed", path, err)
				}
			}
			for _, call := range f.calls {
				if strings.Contains(call, "pull") || strings.Contains(call, "create") || strings.Contains(call, " up ") || strings.Contains(call, "restart") {
					t.Fatal("refusal recovery performed deployment work", call)
				}
			}
			if err := f.h.readJSON(filepath.Join(f.h.releases, "example", "operation.json"), &op); err != nil || op.Phase != "reconciled" {
				t.Fatal(op, err)
			}
		})
	}
}

func TestReconciliationWithoutSnapshotRejectsLaterOrChangedServing(t *testing.T) {
	for _, condition := range []string{"configured", "activating", "activation_failed", "readiness_failed", "revision", "retention", "compose", "readiness", "unreadable", "static"} {
		t.Run(condition, func(t *testing.T) {
			f, r, before := reconciliationFixture(t)
			for path, body := range before {
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Remove(filepath.Join(f.h.releases, "example", "staging-"+r.ID+".json")); err != nil {
				t.Fatal(err)
			}
			r.Phase = "staging_failed"
			switch condition {
			case "configured", "activating", "activation_failed", "readiness_failed":
				r.Phase = condition
			case "revision":
				if err := os.WriteFile(filepath.Join(f.h.policy.AppDir, ".env"), []byte("APP_VERSION="+r.Candidate+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "retention":
				if err := os.WriteFile(filepath.Join(f.h.policy.AppDir, ".komizo-image-retention"), []byte("CURRENT="+r.Candidate+"\nPREVIOUS=\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "compose":
				path := filepath.Join(f.h.policy.AppDir, "compose.yml")
				if err := os.WriteFile(path, []byte(strings.ReplaceAll(string(before[path]), r.Serving, r.Candidate)), 0600); err != nil {
					t.Fatal(err)
				}
			case "readiness":
				f.h.reconciliationReady = func(context.Context, string, []byte) error { return errors.New("serving proof unavailable") }
			case "static":
				policyPath := filepath.Join(f.h.policies, "example.json")
				var policy workload.Policy
				if err := f.h.readJSON(policyPath, &policy); err != nil {
					t.Fatal(err)
				}
				policy.Static = &workload.StaticPolicy{Profile: "spa-v1", GateConfigSHA: strings.Repeat("a", 64), Proxy: "komizo-proxy", Hostnames: []string{"example.test"}}
				policy.Readiness = &workload.ReadinessPolicy{Probes: []workload.ReadinessProbe{{URL: "https://example.test/"}}}
				if err := policy.Check(); err != nil {
					t.Fatal(err)
				}
				if err := workload.WritePrivateJSON(policyPath, policy); err != nil {
					t.Fatal(err)
				}
				body, err := os.ReadFile(policyPath)
				if err != nil {
					t.Fatal(err)
				}
				r.PolicySHA256 = deploymentHash(body)
			case "unreadable":
				f.h.reconciliationSnapshot = func(string, any) error { return os.ErrPermission }
			}
			var op workload.Operation
			path := filepath.Join(f.h.releases, "example", "operation.json")
			if err := f.h.readJSON(path, &op); err != nil {
				t.Fatal(err)
			}
			op.Phase = r.Phase
			if err := workload.WritePrivateJSON(path, op); err != nil {
				t.Fatal(err)
			}
			writes := 0
			f.h.deploymentWrite = func(string, []byte, os.FileMode) error { writes++; return nil }
			if _, err := f.h.reconcile(t.Context(), r, f.queue); err == nil {
				t.Fatal("unproven snapshot-free recovery accepted")
			}
			if writes != 0 {
				t.Fatal("refused recovery wrote serving files")
			}
			if err := f.h.readJSON(path, &op); err != nil || op.Phase != r.Phase {
				t.Fatal("refusal lost its fence", op, err)
			}
		})
	}
}
