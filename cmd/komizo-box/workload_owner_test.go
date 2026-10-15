package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/internal/workload"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTypedLifecyclePreservesNewerStop(t *testing.T) {
	f := newDeploymentFixture(t)
	if err := activationPass(context.Background(), f.queue, f.h); err != nil {
		t.Fatal(err)
	}
	sub := subject{app: f.r.App, root: f.h.root, dir: f.h.policy.AppDir}
	if err := box.MarkStopped(sub.root, sub.app, "fixture", time.Now()); err != nil {
		t.Fatal(err)
	}
	original := f.h.run
	f.h.run = func(ctx context.Context, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), " up -d ") {
			if err := box.MarkStopped(sub.root, sub.app, "newer-stop", time.Now()); err != nil {
				return "", err
			}
		}
		return original(ctx, args...)
	}
	if err := f.h.performTypedOwner(context.Background(), "start", sub, "", "fixture", f.queue); !errors.Is(err, workload.ErrActivationStopped) {
		t.Fatalf("start did not refuse newer stop: %v", err)
	}
	stopped, err := box.IsStopped(sub.root, sub.app)
	if err != nil || !stopped {
		t.Fatal("new stop disappeared")
	}
	if !strings.Contains(strings.Join(f.calls, "\n"), " stop") {
		t.Fatal("containers not stopped after race")
	}
}
func TestTypedLifecycleRefusesPendingStartupAndPreservesFailedStop(t *testing.T) {
	f := newDeploymentFixture(t)
	sub := subject{app: f.r.App, root: f.h.root, dir: filepath.Join(f.h.root, "srv/example")}
	if err := f.h.performTypedOwner(context.Background(), "start", sub, "", "fixture", f.queue); err == nil {
		t.Fatal("startup consumed pending deployment")
	}
	if len(f.calls) != 0 {
		t.Fatal("pending startup touched docker")
	}
	if err := activationPass(context.Background(), f.queue, f.h); err != nil {
		t.Fatal(err)
	}
	f.h.run = func(context.Context, ...string) (string, error) { return "", errors.New("synthetic docker failure") }
	if err := f.h.performTypedOwner(context.Background(), "stop", sub, "", "fixture", f.queue); err == nil {
		t.Fatal("failed docker stop reported success")
	}
	stopped, err := box.IsStopped(sub.root, sub.app)
	if err != nil || !stopped {
		t.Fatal("failed stop lost durable intent")
	}
}
func TestTypedLifecycleRejectsDuplicateRetention(t *testing.T) {
	f := newDeploymentFixture(t)
	if err := activationPass(context.Background(), f.queue, f.h); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.h.policy.AppDir, ".komizo-image-retention"), []byte("CURRENT="+f.r.Previous+"\nCURRENT="+f.r.Candidate+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	sub := subject{app: f.r.App, root: f.h.root, dir: f.h.policy.AppDir}
	if err := f.h.performTypedOwner(context.Background(), "start", sub, "", "fixture", f.queue); err == nil {
		t.Fatal("duplicate current retention accepted")
	}
}

func TestTypedScopedLifecycleKeepsOneLockAndChecksProvenance(t *testing.T) {
	for _, verb := range []string{"start", "restart"} {
		t.Run(verb, func(t *testing.T) {
			f := newDeploymentFixture(t)
			if err := activationPass(context.Background(), f.queue, f.h); err != nil {
				t.Fatal(err)
			}
			sub := subject{app: f.r.App, root: f.h.root, dir: f.h.policy.AppDir}
			// The virtual host runner uses root/run while production RunDir is
			// /run/komizo. Bind both fixture paths to the same actual lock inode.
			if err := os.MkdirAll(filepath.Join(sub.root, "run/komizo"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(filepath.Join(sub.root, "run", "deploy-"+sub.app+".lock"), filepath.Join(sub.root, "run/komizo", "deploy-"+sub.app+".lock")); err != nil {
				t.Fatal(err)
			}
			id := "0123456789abcdef0123456789abcdef"
			generation := filepath.Join(sub.dir, "secrets", "generations", id)
			if err := os.MkdirAll(generation, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("generations/"+id, filepath.Join(sub.dir, "secrets", "current")); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"postgres.env", "migrate.env", "api.env", "godot-api.env"} {
				if err := os.WriteFile(filepath.Join(generation, name), []byte("synthetic-only\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			record := "APP_DIR=" + sub.dir + "\nSCOPED_ENV=fields-postgres-v2\nSCOPED_SCHEMA=11\nSCOPED_FILES=postgres.env,migrate.env,api.env,godot-api.env\nSCOPED_GENERATION=" + id + "\n"
			if err := os.WriteFile(filepath.Join(sub.root, box.AppsDir, sub.app+".env"), []byte(record), 0600); err != nil {
				t.Fatal(err)
			}
			f.calls = nil
			if err := f.h.performTypedOwner(context.Background(), verb, sub, "", "fixture", f.queue); err == nil || !strings.Contains(err.Error(), "scoped env is not ready") {
				t.Fatalf("missing provenance must refuse before effects, got %v", err)
			}
			if len(f.calls) != 0 {
				t.Fatal("missing provenance touched Docker")
			}
			marker := filepath.Join(generation, "provenance")
			body := []byte("profile=fields-postgres-v2\nschema=11\ngeneration=" + id + "\n")
			if err := os.WriteFile(marker, body, 0400); err != nil {
				t.Fatal(err)
			}
			if os.Geteuid() != 0 {
				if err := f.h.performTypedOwner(context.Background(), verb, sub, "", "fixture", f.queue); err == nil || !strings.Contains(err.Error(), "scoped env is not ready") || len(f.calls) != 0 {
					t.Fatalf("untrusted marker started a scoped workload: %v", err)
				}
				return
			}
			original := f.h.run
			f.h.run = func(ctx context.Context, args ...string) (string, error) {
				joined := strings.Join(args, " ")
				if strings.Contains(joined, " up -d ") || strings.Contains(joined, " restart --no-deps ") {
					lockCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
					defer cancel()
					if unlock, err := box.LockDeployment(lockCtx, sub.root, sub.app); err == nil {
						unlock()
						t.Fatal("startup effect lost the shared app lock")
					}
				}
				if strings.HasSuffix(joined, " ps --status running --services") {
					return "example-gate\n", nil
				}
				return original(ctx, args...)
			}
			if err := f.h.performTypedOwner(context.Background(), verb, sub, "", "fixture", f.queue); err != nil {
				t.Fatal(err)
			}
			if len(f.calls) == 0 {
				t.Fatal("valid scoped startup did not reach Docker")
			}
			if err := os.WriteFile(marker, []byte("foreign marker\n"), 0400); err != nil {
				t.Fatal(err)
			}
			f.calls = nil
			if err := f.h.performTypedOwner(context.Background(), verb, sub, "", "fixture", f.queue); err == nil || len(f.calls) != 0 {
				t.Fatalf("changed provenance started a scoped workload: %v", err)
			}
		})
	}
}

func TestTypedRestartUsesOnlyApprovedRunningServices(t *testing.T) {
	for _, tc := range []struct {
		name, running, requested string
		wantRestart              bool
	}{
		{name: "serving only", running: "example-gate\n", wantRestart: true},
		{name: "explicit running service", running: "example-gate\n", requested: "example-gate", wantRestart: true},
		{name: "foreign service", running: "foreign\n"},
		{name: "duplicate service", running: "example-gate\nexample-gate\n"},
		{name: "no running service"},
		{name: "requested stopped service", running: "example-gate\n", requested: "migrate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDeploymentFixture(t)
			if err := activationPass(context.Background(), f.queue, f.h); err != nil {
				t.Fatal(err)
			}
			sub := subject{app: f.r.App, root: f.h.root, dir: f.h.policy.AppDir}
			composePath := filepath.Join(sub.dir, "compose.yml")
			body, err := os.ReadFile(composePath)
			if err != nil {
				t.Fatal(err)
			}
			var definition map[string]any
			if err := json.Unmarshal(body, &definition); err != nil {
				t.Fatal(err)
			}
			services := definition["services"].(map[string]any)
			gate := services["example-gate"].(map[string]any)
			job := make(map[string]any)
			for key, value := range gate {
				job[key] = value
			}
			job["profiles"] = []string{"migrate"}
			services["migrate"] = job
			body, err = json.Marshal(definition)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(composePath, body, 0600); err != nil {
				t.Fatal(err)
			}
			original := f.h.run
			var restarts []string
			f.h.run = func(ctx context.Context, args ...string) (string, error) {
				joined := strings.Join(args, " ")
				if strings.HasSuffix(joined, " ps --status running --services") {
					return tc.running, nil
				}
				if strings.HasSuffix(joined, " ps -q") {
					return "synthetic-running-container\n", nil
				}
				if strings.Contains(joined, " restart") {
					restarts = append(restarts, joined)
				}
				return original(ctx, args...)
			}
			err = f.h.performTypedOwner(context.Background(), "restart", sub, tc.requested, "fixture", f.queue)
			if !tc.wantRestart {
				if err == nil || len(restarts) != 0 {
					t.Fatalf("invalid inventory/request caused startup: err=%v effects=%v", err, restarts)
				}
				return
			}
			if err != nil || len(restarts) != 1 || !strings.HasSuffix(restarts[0], " restart --no-deps example-gate") {
				t.Fatalf("restart broadened the running service set: err=%v effects=%v", err, restarts)
			}
		})
	}
}
