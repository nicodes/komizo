package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/internal/workload"
)

type deploymentFixture struct {
	queue string
	h     *hostActivation
	r     workload.ActivationRequest
	calls []string
}

func newDeploymentFixture(t *testing.T) *deploymentFixture {
	t.Helper()
	queue, h, _ := activationFixture(t)
	f := &deploymentFixture{queue: queue, h: h}
	p, err := workload.NewPolicy("example", filepath.Join(h.root, "srv/example"), "ghcr.io/example/example-config", "edge")
	if err != nil {
		t.Fatal(err)
	}
	p.SourceRepository = "example/repo"
	p.Resources = &workload.ResourcePolicy{Default: workload.ServiceBudget{MemoryBytes: 64 << 20, MemorySwapBytes: 64 << 20, MilliCPUs: 500}, MaxMemoryBytes: 128 << 20, MaxMemorySwapBytes: 128 << 20, MaxMilliCPUs: 1000}
	p.RepositoryID = "123"
	p.Deployment = &workload.DeploymentPolicy{RoutePath: filepath.Join(h.root, box.ProxyDir, "routes/example.caddy"), Proxy: "komizo-proxy", ProxyDir: filepath.Join(h.root, box.ProxyDir)}
	for _, dir := range []string{filepath.Dir(p.Deployment.RoutePath), filepath.Join(h.root, box.AppsDir)} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	previous, candidate := strings.Repeat("a", 40), strings.Repeat("b", 40)
	write(filepath.Join(p.AppDir, ".env"), "SECRET=synthetic-fixture-only\nAPP_VERSION="+previous+"\n")
	write(p.Deployment.RoutePath, "example.test { respond old }\n")
	write(filepath.Join(p.Deployment.ProxyDir, "Caddyfile"), "import routes/*\n")
	write(filepath.Join(h.root, box.AppsDir, "example.env"), "APP_DIR="+p.AppDir+"\nSTOPPED=0\n")
	if err := workload.WritePrivateJSON(filepath.Join(h.policies, "example.json"), p); err != nil {
		t.Fatal(err)
	}
	manifest := workload.ReleaseManifest{Version: 1, Repository: p.SourceRepository, RepositoryID: p.RepositoryID, Revision: candidate, Images: map[string]string{p.ImagePrefix + "config:" + candidate: "sha256:" + strings.Repeat("2", 64), p.ImagePrefix + "gate:" + candidate: "sha256:" + strings.Repeat("1", 64)}}
	if err := workload.WritePrivateJSON(filepath.Join(h.releases, "example", candidate+".json"), workload.ReleaseAcceptance{Manifest: manifest, Authority: "operator-bootstrap", VerifiedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	opPath := filepath.Join(h.releases, "example/operation.json")
	os.Remove(opPath)
	if err := workload.RecordOperation(opPath, p.App, candidate, previous, "admitted", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	var op workload.Operation
	if err := h.readJSON(opPath, &op); err != nil {
		t.Fatal(err)
	}
	slot := deploymentCredentialPath(queue, op.ID)
	os.MkdirAll(filepath.Dir(slot), 0700)
	if err := workload.WritePrivateJSON(slot, deploymentCredentials{}); err != nil {
		t.Fatal(err)
	}
	policyBytes, _ := os.ReadFile(filepath.Join(h.policies, "example.json"))
	credentials, _ := os.ReadFile(slot)
	f.r = workload.ActivationRequest{Version: 2, ID: op.ID, App: p.App, Candidate: candidate, Previous: previous, Deadline: op.Deadline, PolicySHA256: deploymentHash(policyBytes), RoutePath: p.Deployment.RoutePath, Proxy: p.Deployment.Proxy, Stage: &workload.DeploymentStage{CredentialSHA256: deploymentHash(credentials)}}
	if err := workload.WritePrivateJSON(filepath.Join(queue, "pending.json"), f.r); err != nil {
		t.Fatal(err)
	}
	h.deploymentWrite = func(path string, body []byte, mode os.FileMode) error {
		if err := writePrivateText(path, body); err != nil {
			return err
		}
		return os.Chmod(path, mode)
	}
	h.deploymentLogin = func(context.Context, deploymentCredentials, string) error {
		f.calls = append(f.calls, "login")
		return nil
	}
	h.deploymentCopy = func(context.Context, string) ([]byte, []byte, error) {
		return []byte("services:\n  example-gate:\n    image: " + p.ImagePrefix + "gate:${APP_VERSION}\n    networks: [shared]\nnetworks:\n  shared:\n    external: true\n    name: edge\n"), []byte("example.test -> gate\n"), nil
	}
	h.run = func(_ context.Context, args ...string) (string, error) {
		f.calls = append(f.calls, strings.Join(args, " "))
		if len(args) > 3 && args[0] == "image" && args[2] == "--format" {
			if args[3] == "{{json .Config.Volumes}}" {
				return "null", nil
			}
			return "sha256:" + strings.Repeat("2", 64), nil
		}
		if args[0] == "create" {
			return strings.Repeat("c", 64), nil
		}
		if args[0] == "image" && args[1] == "inspect" {
			image := args[2]
			component := "gate"
			id := strings.Repeat("1", 64)
			if strings.Contains(image, "config") {
				component = "config"
				id = strings.Repeat("2", 64)
			}
			b, _ := json.Marshal([]map[string]any{{"Id": "sha256:" + id, "RepoDigests": []string{p.ImagePrefix + component + "@sha256:" + strings.Repeat("3", 64)}}})
			return string(b), nil
		}
		return "", nil
	}
	return f
}
func TestTypedDeploymentOwnsDisconnectedStagingAndStop(t *testing.T) {
	for _, stop := range []bool{false, true} {
		t.Run(map[bool]string{false: "running", true: "stopped"}[stop], func(t *testing.T) {
			f := newDeploymentFixture(t)
			if stop {
				os.WriteFile(filepath.Join(f.h.root, box.AppsDir, "example.env"), []byte("APP_DIR="+filepath.Join(f.h.root, "srv/example")+"\nSTOPPED=1\n"), 0600)
			}
			client, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := waitActivation(client, f.queue, f.r.ID, f.h.readJSON); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if err := activationPass(context.Background(), f.queue, f.h); err != nil {
				t.Fatal(err)
			}
			result, err := waitActivation(context.Background(), f.queue, f.r.ID, f.h.readJSON)
			if err != nil || !result.OK || result.Started == nil || *result.Started == stop {
				t.Fatalf("result %+v: %v; calls %v", result, err, f.calls)
			}
			if _, err := os.Lstat(filepath.Dir(deploymentCredentialPath(f.queue, f.r.ID))); !os.IsNotExist(err) {
				t.Fatal("registry credentials survived acknowledgement")
			}
			env, _ := os.ReadFile(filepath.Join(f.h.policy.AppDir, ".env"))
			if !strings.Contains(string(env), "SECRET=synthetic-fixture-only") || !strings.Contains(string(env), f.r.Candidate) {
				t.Fatal("revision update changed unrelated environment")
			}
		})
	}
}
func TestTypedDeploymentFailureRestoresFilesAndFencesReplay(t *testing.T) {
	f := newDeploymentFixture(t)
	originalRun := f.h.run
	f.h.run = func(ctx context.Context, args ...string) (string, error) {
		if args[0] == "exec" {
			return "", errors.New("synthetic validation failure")
		}
		return originalRun(ctx, args...)
	}
	before, _ := os.ReadFile(f.r.RoutePath)
	if err := activationPass(context.Background(), f.queue, f.h); err != nil {
		t.Fatal(err)
	}
	result, err := waitActivation(context.Background(), f.queue, f.r.ID, f.h.readJSON)
	if err != nil || result.OK || result.Phase != "staging_failed" {
		t.Fatal(result, err)
	}
	after, _ := os.ReadFile(f.r.RoutePath)
	if string(after) != string(before) {
		t.Fatal("failed staging left new route")
	}
	for _, call := range f.calls {
		if strings.Contains(call, " up ") {
			t.Fatal("failed configuration started containers")
		}
	}
	if err := workload.RecordOperation(filepath.Join(f.h.releases, "example/operation.json"), "example", f.r.Candidate, f.r.Previous, "admitted", time.Now()); err == nil {
		t.Fatal("failed staging was blindly replayed")
	}
}
func TestTypedDeploymentCredentialAndPolicySubstitutionBeforeEffects(t *testing.T) {
	for _, field := range []string{"credentials", "policy", "revision"} {
		t.Run(field, func(t *testing.T) {
			f := newDeploymentFixture(t)
			switch field {
			case "credentials":
				os.WriteFile(deploymentCredentialPath(f.queue, f.r.ID), []byte("{}"), 0600)
			case "policy":
				os.WriteFile(filepath.Join(f.h.policies, "example.json"), []byte("{}"), 0600)
			case "revision":
				os.WriteFile(filepath.Join(f.h.root, "srv/example/.env"), []byte("APP_VERSION="+strings.Repeat("d", 40)+"\n"), 0600)
			}
			if err := activationPass(context.Background(), f.queue, f.h); err != nil {
				t.Fatal(err)
			}
			if len(f.calls) > 0 {
				t.Fatal("substituted authority reached Docker", f.calls)
			}
		})
	}
}

func TestTypedDeploymentScopedGenerationAndNeighborClaims(t *testing.T) {
	for _, fault := range []string{"none", "generation", "secret-mode", "parent-link", "provenance", "hostname"} {
		t.Run(fault, func(t *testing.T) {
			f := newDeploymentFixture(t)
			appDir := filepath.Join(f.h.root, "srv/example")
			generation := strings.Repeat("d", 32)
			root := filepath.Join(appDir, "secrets")
			dir := filepath.Join(root, "generations", generation)
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"postgres.env", "migrate.env", "api.env", "godot-api.env"} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte("SYNTHETIC_ONLY=true\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			marker := filepath.Join(dir, "provenance")
			os.WriteFile(marker, []byte("profile=fields-postgres-v2\nschema=11\ngeneration="+generation+"\n"), 0400)
			os.Symlink("generations/"+generation, filepath.Join(root, "current"))
			os.WriteFile(filepath.Join(f.h.root, box.AppsDir, "example.env"), []byte("APP_DIR="+appDir+"\nSCOPED_ENV=fields-postgres-v2\nSCOPED_GENERATION="+generation+"\n"), 0600)
			f.h.deploymentOwner = func(os.FileInfo) bool { return true }
			checks := 0
			f.h.deploymentSecretCheck = func(context.Context, string, string) error { checks++; return nil }
			f.r.Stage.Generation = generation
			switch fault {
			case "generation":
				f.r.Stage.Generation = strings.Repeat("e", 32)
			case "secret-mode":
				os.Chmod(filepath.Join(dir, "api.env"), 0644)
			case "parent-link":
				parent := filepath.Dir(dir)
				os.Rename(parent, parent+"-foreign")
				os.Symlink(parent+"-foreign", parent)
			case "provenance":
				os.Chmod(marker, 0600)
				os.WriteFile(marker, []byte("profile=unapproved\n"), 0600)
				os.Chmod(marker, 0400)
			case "hostname":
				other := filepath.Join(f.h.root, "srv/other")
				os.MkdirAll(other, 0700)
				os.WriteFile(filepath.Join(other, "hostnames"), []byte("EXAMPLE.test -> gate\n"), 0600)
				os.WriteFile(filepath.Join(f.h.root, box.AppsDir, "other.env"), []byte("APP_DIR="+other+"\n"), 0600)
			}
			workload.WritePrivateJSON(filepath.Join(f.queue, "pending.json"), f.r)
			before, _ := os.ReadFile(f.r.RoutePath)
			if err := activationPass(context.Background(), f.queue, f.h); err != nil {
				t.Fatal(err)
			}
			result, err := waitActivation(context.Background(), f.queue, f.r.ID, f.h.readJSON)
			if err != nil {
				t.Fatal(err)
			}
			if fault == "none" {
				if !result.OK || checks != 1 {
					t.Fatal("valid scoped metadata rejected", result, checks)
				}
			} else {
				after, _ := os.ReadFile(f.r.RoutePath)
				if result.OK || string(before) != string(after) {
					t.Fatal("invalid staged authority changed the installed route", fault, result)
				}
			}
		})
	}
}

func TestTypedDeploymentProcessCrashBoundaries(t *testing.T) {
	if boundary := os.Getenv("KOMIZO_DEPLOYMENT_CRASH_BOUNDARY"); boundary != "" {
		f := newDeploymentFixture(t)
		f.h.deploymentBoundary = func(name string) {
			if name == boundary {
				b, _ := json.Marshal(map[string]any{"queue": f.queue, "root": f.h.root, "policies": f.h.policies, "releases": f.h.releases, "request": f.r})
				if err := os.WriteFile(os.Getenv("KOMIZO_DEPLOYMENT_CRASH_MARKER"), b, 0600); err != nil {
					t.Fatal(err)
				}
				select {}
			}
		}
		if err := activationPass(context.Background(), f.queue, f.h); err != nil {
			t.Fatal(err)
		}
		t.Fatal("requested boundary did not occur")
	}
	for _, boundary := range []string{"journal-staging", "registry-login", "configuration-copy", "snapshot", "compose-swap", "route-swap", "hostname-swap", "revision-swap", "configured-submission"} {
		t.Run(boundary, func(t *testing.T) {
			parent := t.TempDir()
			marker := filepath.Join(parent, "boundary.json")
			cmd := exec.Command(os.Args[0], "-test.run=^TestTypedDeploymentProcessCrashBoundaries$", "-test.timeout=30s")
			cmd.Env = append(os.Environ(), "TMPDIR="+parent, "KOMIZO_DEPLOYMENT_CRASH_BOUNDARY="+boundary, "KOMIZO_DEPLOYMENT_CRASH_MARKER="+marker)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cmd.Process.Kill(); cmd.Wait() }()
			var body []byte
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				body, _ = os.ReadFile(marker)
				if len(body) > 0 {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if len(body) == 0 {
				t.Fatal("owned child did not reach mutation boundary")
			}
			cmd.Process.Kill()
			cmd.Wait()
			var saved struct {
				Queue, Root, Policies, Releases string
				Request                         workload.ActivationRequest
			}
			if err := json.Unmarshal(body, &saved); err != nil {
				t.Fatal(err)
			}
			calls := 0
			h := &hostActivation{root: saved.Root, policies: saved.Policies, releases: saved.Releases, readBytes: os.ReadFile, readJSON: func(path string, out any) error {
				b, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				return json.Unmarshal(b, out)
			}, run: func(context.Context, ...string) (string, error) { calls++; return "", nil }}
			if err := activationPass(context.Background(), saved.Queue, h); err != nil {
				t.Fatal(err)
			}
			var result workload.ActivationResult
			h.readJSON(filepath.Join(saved.Queue, saved.Request.ID+".json"), &result)
			// A configured queue delegates to activation. Earlier ambiguous staging
			// never repeats registry, copy, file swaps, or container startup.
			if boundary != "configured-submission" && (result.OK || result.Phase != "reconciliation_required" || calls != 0) {
				t.Fatal("crash replayed staging", result, calls)
			}
			if _, err := os.Lstat(filepath.Dir(deploymentCredentialPath(saved.Queue, saved.Request.ID))); !os.IsNotExist(err) {
				t.Fatal("interrupted credentials retained")
			}
		})
	}
}
