package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nicodes/komizo/internal/workload"
)

func initialFixture(t *testing.T) (*deploymentFixture, reconciliationRequest) {
	t.Helper()
	f := newDeploymentFixture(t)
	if err := f.h.readJSON(filepath.Join(f.h.policies, f.r.App+".json"), &f.h.policy); err != nil {
		t.Fatal(err)
	}
	p := f.h.policy
	for path, body := range map[string]string{filepath.Join(p.AppDir, ".env"): "", filepath.Join(p.AppDir, "compose.yml"): "services: {}\n"} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(p.Deployment.RoutePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.queue, "pending.json")); err != nil {
		t.Fatal(err)
	}
	var op workload.Operation
	path := filepath.Join(f.h.releases, p.App, "operation.json")
	if err := f.h.readJSON(path, &op); err != nil {
		t.Fatal(err)
	}
	op.Previous, op.Phase = "", "staging_failed"
	if err := workload.WritePrivateJSON(path, op); err != nil {
		t.Fatal(err)
	}
	return f, reconciliationRequest{ID: op.ID, Candidate: op.Candidate, PolicySHA256: f.r.PolicySHA256, Phase: op.Phase, Outcome: "abandon-initial"}
}

func TestInitialReconciliationPreservesEvidenceWithoutServingEffects(t *testing.T) {
	f, r := initialFixture(t)
	f.calls = nil
	dir := filepath.Join(f.h.releases, f.r.App)
	receipt, err := os.ReadFile(filepath.Join(dir, f.r.Candidate+".json"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.h.reconcile(context.Background(), r, f.queue)
	if err != nil {
		t.Fatal(err)
	}
	if result["serving"] != "" || result["application_restart"] != false || result["database_restore"] != false {
		t.Fatal(result)
	}
	var op workload.Operation
	if err := f.h.readJSON(filepath.Join(dir, "operation.json"), &op); err != nil || op.ID != r.ID || op.Phase != "reconciled" || op.Previous != "" {
		t.Fatal(op, err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, f.r.Candidate+".json"))
	if string(after) != string(receipt) {
		t.Fatal("accepted evidence changed")
	}
	if len(f.calls) != 1 || f.calls[0] != "ps -aq --filter label=com.docker.compose.project=example" {
		t.Fatal("unexpected effects", f.calls)
	}
	if _, err := os.Lstat(filepath.Join(f.h.policy.AppDir, ".komizo-image-retention")); !os.IsNotExist(err) {
		t.Fatal("created serving retention", err)
	}
}

func TestInitialReconciliationRefusesAnyServingOrUncertainState(t *testing.T) {
	for _, condition := range []string{"revision", "environment", "compose", "hostnames", "route", "retention", "dangling retention", "snapshot", "container", "docker error", "previous", "configured", "activating", "wrong id", "wrong policy", "pending"} {
		t.Run(condition, func(t *testing.T) {
			f, r := initialFixture(t)
			p := f.h.policy
			dir := filepath.Join(f.h.releases, p.App)
			write := func(path, body string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch condition {
			case "revision":
				r.Serving = f.r.Candidate
			case "environment":
				write(filepath.Join(p.AppDir, ".env"), "OTHER=value\n")
			case "compose":
				write(filepath.Join(p.AppDir, "compose.yml"), "services: {gate: {image: example}}")
			case "hostnames":
				write(filepath.Join(p.AppDir, "hostnames"), "")
			case "route":
				write(p.Deployment.RoutePath, "")
			case "retention":
				write(filepath.Join(p.AppDir, ".komizo-image-retention"), "")
			case "dangling retention":
				if err := os.Symlink("missing", filepath.Join(p.AppDir, ".komizo-image-retention")); err != nil {
					t.Fatal(err)
				}
			case "snapshot":
				write(filepath.Join(dir, "staging-"+r.ID+".json"), "{}")
			case "container":
				f.h.run = func(context.Context, ...string) (string, error) { return strings.Repeat("a", 64), nil }
			case "docker error":
				f.h.run = func(context.Context, ...string) (string, error) { return "", errors.New("inspection unavailable") }
			case "previous", "configured", "activating":
				var op workload.Operation
				if err := f.h.readJSON(filepath.Join(dir, "operation.json"), &op); err != nil {
					t.Fatal(err)
				}
				if condition == "previous" {
					op.Previous = f.r.Previous
				} else {
					op.Phase = condition
					r.Phase = condition
				}
				if err := workload.WritePrivateJSON(filepath.Join(dir, "operation.json"), op); err != nil {
					t.Fatal(err)
				}
			case "wrong id":
				r.ID = strings.Repeat("f", 32)
			case "wrong policy":
				r.PolicySHA256 = strings.Repeat("f", 64)
			case "pending":
				write(filepath.Join(f.queue, "pending.json"), "{}")
			}
			before, _ := os.ReadFile(filepath.Join(dir, "operation.json"))
			if _, err := f.h.reconcile(context.Background(), r, f.queue); err == nil {
				t.Fatal("uncertain initial state accepted")
			}
			after, _ := os.ReadFile(filepath.Join(dir, "operation.json"))
			if string(before) != string(after) {
				t.Fatal("refusal changed operation fence")
			}
		})
	}
}

func TestInitialReceiptCanBeReusedOnlyBeforeDeploymentOrAfterReconciliation(t *testing.T) {
	f, r := initialFixture(t)
	dir := filepath.Join(f.h.releases, f.r.App)
	if err := f.h.initialRetryAllowed(context.Background(), f.h.policy, dir); err == nil {
		t.Fatal("unresolved operation allowed")
	}
	if _, err := f.h.reconcile(context.Background(), r, f.queue); err != nil {
		t.Fatal(err)
	}
	if err := f.h.initialRetryAllowed(context.Background(), f.h.policy, dir); err != nil {
		t.Fatal("explicitly reconciled empty registration refused", err)
	}
	if err := os.Remove(filepath.Join(dir, "operation.json")); err != nil {
		t.Fatal(err)
	}
	if err := f.h.initialRetryAllowed(context.Background(), f.h.policy, dir); err != nil {
		t.Fatal("first pre-deployment receipt refused", err)
	}
	if err := os.WriteFile(filepath.Join(f.h.policy.AppDir, ".env"), []byte("APP_VERSION="+r.Candidate), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.h.initialRetryAllowed(context.Background(), f.h.policy, dir); err == nil {
		t.Fatal("installed state allowed")
	}
}
