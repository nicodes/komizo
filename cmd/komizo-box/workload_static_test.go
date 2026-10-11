package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/internal/workload"
)

type staticFixtureState struct {
	calls  []string
	fail   string
	during func(string)
}

func staticActivationFixture(t *testing.T) (*hostActivation, workload.ActivationRequest, *staticFixtureState) {
	t.Helper()
	_, h, _ := activationFixture(t)
	h.policies = filepath.Join(h.root, workloadPolicyDirectory)
	h.releases = filepath.Join(h.root, releaseDirectory)
	rev := strings.Repeat("a", 40)
	for _, dir := range []string{h.policies, filepath.Join(h.releases, "example"), filepath.Join(h.root, box.ProxyDir, "routes")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	p, err := workload.NewPolicy("example", filepath.Join(h.root, "srv/example"), "ghcr.io/example/example-config", "edge")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.root, box.AppsDir, "example.env"), []byte("DIR="+p.AppDir+"\nSTOPPED=0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p.SourceRepository = "example/repo"
	p.RepositoryID = "123"
	config := []byte(":80 {\n root * /srv/public/app\n try_files {path} {path}.html {path}/index.html /index.html\n file_server\n}\n")
	sum := sha256.Sum256(config)
	p.Static = &workload.StaticPolicy{Profile: "spa-v1", GateConfigSHA: hex.EncodeToString(sum[:]), Proxy: "komizo-proxy", Hostnames: []string{"example.test"}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Komizo-Revision", rev)
		_, _ = w.Write([]byte("ready"))
	}))
	t.Cleanup(server.Close)
	p.Readiness = &workload.ReadinessPolicy{Probes: []workload.ReadinessProbe{{URL: server.URL}}}
	h.readinessClient = server.Client()
	h.policy = p
	h.makeStaticDir = func(path string, mode os.FileMode) error {
		if err := os.MkdirAll(path, mode); err != nil {
			return err
		}
		return os.Chmod(path, mode)
	}
	write := func(path string, body []byte) {
		t.Helper()
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := workload.WritePrivateJSON(filepath.Join(h.policies, "example.json"), p); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(p.AppDir, ".env"), []byte("APP_VERSION="+rev+"\n"))
	gate := p.ImagePrefix + "gate@sha256:" + strings.Repeat("3", 64)
	compose := []byte(`{"services":{"example-gate":{"image":"` + gate + `"}}}`)
	write(filepath.Join(p.AppDir, "compose.yml"), compose)
	route := []byte("example.test {\n\theader >X-Komizo-Revision " + rev + "\n\treverse_proxy example-gate:80 {\n\t\theader_up X-Forwarded-For {remote_host}\n\t}\n}\n")
	routePath := filepath.Join(h.root, box.ProxyDir, "routes/example.caddy")
	write(routePath, route)
	write(routePath+".prev", route)
	manifest := workload.ReleaseManifest{Version: 1, Repository: p.SourceRepository, RepositoryID: p.RepositoryID, Revision: rev, Images: map[string]string{p.ImagePrefix + "gate:" + rev: "sha256:" + strings.Repeat("1", 64), p.ImagePrefix + "config:" + rev: "sha256:" + strings.Repeat("2", 64)}}
	if err := workload.WritePrivateJSON(filepath.Join(h.releases, "example", rev+".json"), workload.ReleaseAcceptance{Manifest: manifest, Authority: "operator-bootstrap", VerifiedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	opPath := filepath.Join(h.releases, "example/operation.json")
	for _, phase := range []string{"admitted", "configured"} {
		if err := workload.RecordOperation(opPath, "example", rev, "", phase, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	var op workload.Operation
	if err := h.readJSON(opPath, &op); err != nil {
		t.Fatal(err)
	}
	r := workload.ActivationRequest{Version: 1, ID: op.ID, App: p.App, Candidate: rev, Deadline: op.Deadline, RoutePath: routePath, Proxy: p.Static.Proxy}
	hash := func(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }
	policyBody, _ := os.ReadFile(filepath.Join(h.policies, "example.json"))
	r.PolicySHA256 = hash(policyBody)
	r.ComposeSHA256 = hash(compose)
	r.RouteSHA256 = hash(route)
	state := new(staticFixtureState)
	h.run = func(_ context.Context, args ...string) (string, error) {
		call := strings.Join(args, " ")
		state.calls = append(state.calls, call)
		if state.during != nil {
			state.during(call)
		}
		if state.fail != "" && strings.Contains(call, state.fail) {
			return "", errors.New("fixture refusal")
		}
		switch args[0] {
		case "inspect":
			if strings.Contains(call, ".Mounts") {
				b, _ := json.Marshal(map[string]any{"source": filepath.Join(h.root, workload.StaticRoot), "read_write": false})
				return string(b), nil
			}
			return "running", nil
		case "image":
			if len(args) > 2 && args[2] == "--format" {
				return "{}", nil
			}
			ref := args[2]
			id := manifest.Images[p.ImagePrefix+"gate:"+rev]
			repo := p.ImagePrefix + "gate"
			if strings.Contains(ref, "config:") {
				id = manifest.Images[ref]
				repo = p.ImagePrefix + "config"
			}
			b, _ := json.Marshal([]map[string]any{{"Id": id, "RepoDigests": []string{repo + "@sha256:" + strings.Repeat("3", 64)}}})
			return string(b), nil
		case "create":
			return strings.Repeat("b", 64), nil
		case "rm", "exec", "compose":
			return "", nil
		default:
			return "", errors.New("unexpected fixture mutation")
		}
	}
	h.staticStream = func(_ context.Context, args []string, consume func(io.Reader) error) error {
		var b bytes.Buffer
		archive := tar.NewWriter(&b)
		name, body := "index.html", []byte("<html>fixture</html>")
		if strings.Contains(args[1], "Caddyfile") {
			name, body = "Caddyfile", config
		}
		if err := archive.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Size: int64(len(body)), ModTime: time.Unix(1700000000, 0)}); err != nil {
			return err
		}
		_, _ = archive.Write(body)
		if err := archive.Close(); err != nil {
			return err
		}
		return consume(&b)
	}
	return h, r, state
}

func TestStaticActivationOwnerLifecycleAndDurableAcceptance(t *testing.T) {
	h, r, state := staticActivationFixture(t)
	state.during = func(call string) {
		if strings.HasPrefix(call, "compose ") && strings.HasSuffix(call, " stop") {
			var op workload.Operation
			if err := h.readJSON(filepath.Join(h.releases, r.App, "operation.json"), &op); err != nil || op.Phase != "ready" {
				t.Errorf("gate retired before durable acceptance: %s %v", op.Phase, err)
			}
		}
	}
	result, err := workload.Activate(context.Background(), r, h)
	if err != nil || !result.OK || result.Phase != "ready" {
		t.Fatal(result, err)
	}
	state.during = nil
	var record staticRecord
	if err := h.readJSON(h.staticPath(r.App), &record); err != nil || !record.Active || record.TreeSHA256 == "" {
		t.Fatal(record, err)
	}
	sub := subject{app: r.App, root: h.root, dir: h.policy.AppDir}
	for _, verb := range []string{"stop", "start", "restart"} {
		handled, err := staticOwnerWithHost(context.Background(), verb, sub, "", "fixture", h)
		if !handled || err != nil {
			t.Fatal(verb, handled, err)
		}
		stopped, _ := box.IsStopped(h.root, r.App)
		if stopped != (verb == "stop") {
			t.Fatal("owner intent lost", verb)
		}
	}
	for _, call := range state.calls {
		if strings.Contains(call, " up ") || strings.HasPrefix(call, "pull ") {
			t.Fatal("static lifecycle created service or pulled image", call)
		}
	}
}

func TestStaticFailuresPreserveOldGateAndOwnerStop(t *testing.T) {
	for _, tc := range []struct {
		name, fail, during string
		stop               bool
	}{
		{"configuration", "", "bad config", false}, {"validation", "caddy validate", "", false}, {"stop during extraction", "", "create", true}, {"stop during reload", "", "caddy reload", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, r, state := staticActivationFixture(t)
			original, _ := os.ReadFile(r.RoutePath)
			state.fail = tc.fail
			if tc.during == "bad config" {
				h.policy.Static.GateConfigSHA = strings.Repeat("0", 64)
				body, _ := json.Marshal(h.policy)
				_ = os.WriteFile(filepath.Join(h.policies, r.App+".json"), body, 0600)
				sum := sha256.Sum256(body)
				r.PolicySHA256 = hex.EncodeToString(sum[:])
			}
			stopped := false
			state.during = func(call string) {
				if tc.stop && !stopped && strings.Contains(call, tc.during) {
					stopped = true
					if err := box.MarkStopped(h.root, r.App, "fixture", time.Now()); err != nil {
						t.Fatal(err)
					}
				}
			}
			result, err := workload.Activate(context.Background(), r, h)
			if tc.stop {
				if err != nil || result.Started == nil || *result.Started {
					t.Fatal(result, err)
				}
				var rec staticRecord
				_ = h.readJSON(h.staticPath(r.App), &rec)
				if rec.Active {
					t.Fatal("owner stop served public route")
				}
			}
			if !tc.stop {
				if err == nil || result.OK {
					t.Fatal("failed static activation accepted")
				}
				route, _ := os.ReadFile(r.RoutePath)
				if !bytes.Equal(original, route) {
					t.Fatal("previous route lost")
				}
				for _, call := range state.calls {
					if strings.HasPrefix(call, "compose ") && strings.HasSuffix(call, " stop") {
						t.Fatal("old gate retired after failed acceptance")
					}
				}
			}
		})
	}
}

func TestStaticRetentionKeepsAcceptedPairAndRefusesLinkedTree(t *testing.T) {
	h, r, _ := staticActivationFixture(t)
	if err := h.prepareStatic(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(h.root, workload.StaticRoot, r.App)
	previous, old := strings.Repeat("c", 40), strings.Repeat("d", 40)
	r.Previous = previous
	for _, rev := range []string{previous, old} {
		var body bytes.Buffer
		archive := tar.NewWriter(&body)
		_ = archive.WriteHeader(&tar.Header{Name: "index.html", Typeflag: tar.TypeReg, Size: 3})
		_, _ = archive.Write([]byte("old"))
		_ = archive.Close()
		if _, err := workload.StaticTree(&body, filepath.Join(dir, rev)); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.pruneStatic(r); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, old)); !os.IsNotExist(err) {
		t.Fatal("retired tree retained")
	}
	if _, err := os.Stat(filepath.Join(dir, previous)); err != nil {
		t.Fatal("previous tree removed")
	}
	if err := os.Symlink(h.policy.AppDir, filepath.Join(dir, old)); err != nil {
		t.Fatal(err)
	}
	if err := h.pruneStatic(r); err == nil {
		t.Fatal("linked tree removed")
	}
	if _, err := os.Stat(filepath.Join(h.policy.AppDir, ".env")); err != nil {
		t.Fatal("foreign private directory changed")
	}
}

func TestStaticOwnerFailedStartPreservesStopAndDisabledRoute(t *testing.T) {
	h, r, state := staticActivationFixture(t)
	if _, err := workload.Activate(context.Background(), r, h); err != nil {
		t.Fatal(err)
	}
	sub := subject{app: r.App, root: h.root, dir: h.policy.AppDir}
	if _, err := staticOwnerWithHost(context.Background(), "stop", sub, "", "fixture", h); err != nil {
		t.Fatal(err)
	}
	state.fail = "caddy validate"
	if _, err := staticOwnerWithHost(context.Background(), "start", sub, "", "fixture", h); err == nil {
		t.Fatal("failed owner start succeeded")
	}
	stopped, err := box.IsStopped(h.root, r.App)
	if err != nil || !stopped {
		t.Fatal("failed start cleared owner stop")
	}
	route, _ := os.ReadFile(r.RoutePath)
	if strings.Contains(string(route), "file_server") {
		t.Fatal("failed start left static route active")
	}
}

func TestStaticCrashProcessHelper(t *testing.T) {
	statePath := os.Getenv("KOMIZO_STATIC_CRASH_STATE")
	if statePath == "" {
		return
	}
	h, r, _ := staticActivationFixture(t)
	queue := filepath.Join(h.root, "queue")
	if err := workload.WritePrivateJSON(filepath.Join(queue, "pending.json"), r); err != nil {
		t.Fatal(err)
	}
	if err := workload.WritePrivateJSON(statePath, struct {
		Root    string
		Request workload.ActivationRequest
	}{h.root, r}); err != nil {
		t.Fatal(err)
	}
	h.checkpoint = func(name string) {
		if name == os.Getenv("KOMIZO_STATIC_CRASH_BOUNDARY") {
			if err := os.WriteFile(statePath+".boundary", []byte(name), 0600); err != nil {
				t.Fatal(err)
			}
			time.Sleep(30 * time.Second)
		}
	}
	if err := activationPass(context.Background(), queue, h); err != nil {
		t.Fatal(err)
	}
}

func TestStaticProcessCrashAtEveryMutationBoundaryRequiresReconciliation(t *testing.T) {
	for _, boundary := range []string{"public_copy", "public_rename", "route_write", "proxy_reload", "retention", "serving_record", "journal_ready"} {
		t.Run(boundary, func(t *testing.T) {
			parent := t.TempDir()
			statePath := filepath.Join(parent, "state.json")
			cmd := exec.Command(os.Args[0], "-test.run=^TestStaticCrashProcessHelper$", "-test.timeout=40s")
			cmd.Env = []string{"PATH=/usr/bin:/bin", "TMPDIR=" + parent, "KOMIZO_STATIC_CRASH_STATE=" + statePath, "KOMIZO_STATIC_CRASH_BOUNDARY=" + boundary}
			var diagnostic bytes.Buffer
			cmd.Stdout = &diagnostic
			cmd.Stderr = &diagnostic
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
			deadline := time.Now().Add(10 * time.Second)
			for {
				if _, err := os.Stat(statePath + ".boundary"); err == nil {
					break
				}
				if time.Now().After(deadline) {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
					t.Fatal("fixture never crossed boundary", diagnostic.String())
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = cmd.Wait()
			var state struct {
				Root    string
				Request workload.ActivationRequest
			}
			body, err := os.ReadFile(statePath)
			if err != nil || json.Unmarshal(body, &state) != nil {
				t.Fatal(err)
			}
			calls := 0
			h := &hostActivation{root: state.Root, policies: filepath.Join(state.Root, workloadPolicyDirectory), releases: filepath.Join(state.Root, releaseDirectory), readBytes: os.ReadFile, readJSON: func(path string, out any) error {
				body, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				return json.Unmarshal(body, out)
			}, run: func(context.Context, ...string) (string, error) { calls++; return "", errors.New("unexpected replay") }}
			queue := filepath.Join(state.Root, "queue")
			if err := activationPass(context.Background(), queue, h); err != nil {
				t.Fatal(err)
			}
			result, err := waitActivation(context.Background(), queue, state.Request.ID, h.readJSON)
			if err != nil {
				t.Fatal(err)
			}
			if boundary == "journal_ready" {
				if !result.OK || result.Phase != "ready" {
					t.Fatal("lost terminal acknowledgement was not recovered", result)
				}
			} else if result.OK || result.Phase != "reconciliation_required" {
				t.Fatal("ambiguous mutation replayed", result)
			}
			if calls != 0 {
				t.Fatal("replacement worker replayed external effects", calls)
			}
		})
	}
}
