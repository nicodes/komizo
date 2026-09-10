package rollout

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDockerRollout(t *testing.T) {
	if os.Getenv("KOMIZO_TEST_ROLLOUT") != "1" {
		t.Skip("set KOMIZO_TEST_ROLLOUT=1 for isolated real Docker/gateway execution")
	}
	const composeImage = "docker/compose-bin@sha256:023f617349e1791bc03b6d79ac7cc469b2e26c3aa8614c615389aa364a09c6aa"
	const backendImage = "caddy@sha256:c3d7ee5d2b11f9dc54f947f68a734c84e9c9666c92c88a7f30b9cba5da182adb"
	root := t.TempDir()
	app := "kmzr-" + hash([]byte(root))[:12]
	network := app + "-private"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	docker := func(args ...string) (string, error) {
		op, end := context.WithTimeout(context.Background(), time.Minute)
		defer end()
		cmd := exec.CommandContext(op, "docker", append([]string{"--host", "unix:///var/run/docker.sock"}, args...)...)
		out, err := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	must := func(args ...string) string {
		t.Helper()
		out, err := docker(args...)
		if err != nil {
			t.Fatalf("synthetic Docker fixture failed: %v\n%s", err, out)
		}
		return out
	}
	cleanup := func(args ...string) {
		t.Cleanup(func() {
			if out, err := docker(args...); err != nil {
				t.Errorf("fixture cleanup: %v\n%s", err, out)
			}
		})
	}
	tool := must("create", "--entrypoint", "/docker-compose", composeImage)
	compose := filepath.Join(root, "compose")
	if _, err := docker("cp", tool+":/docker-compose", compose); err != nil {
		docker("rm", tool)
		t.Fatal(err)
	}
	must("rm", tool)
	buildDir := filepath.Join(root, "image")
	if err := os.Mkdir(buildDir, 0o700); err != nil {
		t.Fatal(err)
	}
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", filepath.Join(buildDir, "box"), "../../cmd/komizo-box")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("gateway fixture build: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(buildDir, "Dockerfile"), []byte("FROM scratch\nCOPY box /box\nENTRYPOINT [\"/box\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	image := app + ":gateway"
	must("build", "--network", "none", "--tag", image, buildDir)
	cleanup("image", "rm", image)
	// Match the existing application bridge/NAT topology. Candidate isolation
	// must not depend on disabling outbound authentication/provider connections.
	must("network", "create", "--label", "io.komizo.app="+app, network)
	cleanup("network", "rm", network)
	edge := app + "-edge"
	must("network", "create", "--label", "io.komizo.test="+app, edge)
	cleanup("network", "rm", edge)
	t.Cleanup(func() {
		out, err := docker("ps", "--all", "--filter", "label=io.komizo.app="+app, "--format", "{{.Names}}")
		if err != nil {
			t.Error("cannot enumerate owned fixture candidates for cleanup")
			return
		}
		for _, name := range strings.Fields(out) {
			if _, err := docker("rm", "--force", "--volumes", name); err != nil {
				t.Error("cannot clean fixture candidate")
			}
		}
	})
	statePath := filepath.Join(root, "state")
	store, err := OpenStore(ctx, statePath, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PublishGateway([]byte(`{"app":"` + app + `","generation":"bootstrap","routes":[]}`)); err != nil {
		store.Close()
		t.Fatal(err)
	}
	store.Close()
	admin := filepath.Join(root, "admin")
	if err := os.Mkdir(admin, 0o700); err != nil {
		t.Fatal(err)
	}
	proxy := app + "-gateway"
	must("run", "--detach", "--name", proxy, "--network", edge, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--user", strconv.Itoa(os.Getuid())+":"+strconv.Itoa(os.Getgid()),
		"--publish", "127.0.0.1::8080", "--mount", "type=bind,src="+filepath.Join(statePath, "gateway")+",dst=/routes,readonly",
		"--mount", "type=bind,src="+admin+",dst=/admin", image, "gateway", "--app", app,
		"--config", "/routes/config.json", "--admin-socket", "/admin/g.sock", "--listen", ":8080", "--shutdown-timeout", "1s")
	cleanup("rm", "--force", "--volumes", proxy)
	must("network", "connect", network, proxy)
	socket := filepath.Join(admin, "g.sock")
	router, err := NewGatewayClient(socket)
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; {
		if _, _, err := router.Current(ctx); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("gateway not ready: %s", must("logs", proxy))
		}
		time.Sleep(20 * time.Millisecond)
	}
	endpoint := "http://" + must("port", proxy, "8080/tcp")
	keyPath, modelPath := filepath.Join(root, "key"), filepath.Join(root, "model.json")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{1}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	source := func(version string, ready bool) []byte {
		var model map[string]any
		json.Unmarshal(sourceModel("b"), &model)
		model["name"] = app
		model["networks"].(map[string]any)["private"] = map[string]any{"name": network, "internal": true}
		for _, service := range []string{"api", "ui"} {
			body, status := service, "200"
			if service == "ui" {
				body = version
				if !ready {
					status = "503"
				}
			}
			model["services"].(map[string]any)[service] = map[string]any{
				"image": backendImage, "networks": map[string]any{"private": nil},
				"cap_drop": []string{"ALL"}, "cap_add": []string{"NET_BIND_SERVICE"}, "read_only": true,
				"tmpfs":        []string{"/data", "/config"},
				"security_opt": []string{"no-new-privileges:true"},
				"command":      []string{"caddy", "respond", "--listen", ":8080", "--body", body, "--status", status},
			}
		}
		data, _ := json.Marshal(model)
		return data
	}
	run := func(data []byte) (Result, error) {
		if err := os.WriteFile(modelPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		var out, diag bytes.Buffer
		err := Command(ctx, []string{"--app", app, "--network", network, "--model", modelPath, "--key-file", keyPath,
			"--state-dir", statePath, "--gateway-socket", socket, "--compose-bin", compose, "--compose-version", "2.39.2",
			"--timeout", "45s", "--ready-timeout", "2s", "--operation-timeout", "15s", "--stabilize", "50ms", "--retire-timeout", "2s", "--poll", "10ms"}, &out, &diag)
		var result Result
		if err == nil {
			if decodeErr := json.Unmarshal(out.Bytes(), &result); decodeErr != nil {
				t.Fatal(decodeErr)
			}
		}
		return result, err
	}
	load := func() *State {
		s, err := OpenStore(ctx, statePath, time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		state, err := s.Load()
		if err != nil {
			t.Fatal(err)
		}
		return state
	}
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	get := func(host string) (string, error) {
		r, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		r.Host = host
		response, err := client.Do(r)
		if err != nil {
			return "", err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
		if err != nil {
			return "", err
		}
		if response.StatusCode != http.StatusOK {
			return "", fmt.Errorf("status %d", response.StatusCode)
		}
		return string(body), nil
	}
	first, err := run(source("v1", true))
	if err != nil {
		t.Fatalf("initial rollout: %v", err)
	}
	if first.Changed != 2 {
		t.Fatal("initial services not created")
	}
	before := load()
	oldUI, oldAPI := before.Bindings["ui"].Name, before.Bindings["api"].Name
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var requests, failures atomic.Int64
	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				body, err := get("app.test")
				if err != nil || (body != "v1" && body != "v2") {
					failures.Add(1)
				}
				requests.Add(1)
			}
		})
	}
	second, err := run(source("v2", true))
	close(stop)
	wg.Wait()
	if err != nil {
		t.Fatalf("UI rollout: %v", err)
	}
	if second.Changed != 1 || failures.Load() != 0 || requests.Load() == 0 {
		t.Fatalf("selective continuity: %+v requests=%d failures=%d", second, requests.Load(), failures.Load())
	}
	after := load()
	if after.Bindings["api"].Name != oldAPI || after.Bindings["ui"].Name == oldUI {
		t.Fatal("wrong services replaced")
	}
	if existing := must("ps", "--all", "--filter", "name=^/"+oldUI+"$", "--format", "{{.ID}}"); existing != "" {
		t.Fatal("old UI retained")
	}
	if body, err := get("api.test"); err != nil || body != "api" {
		t.Fatal("unchanged API unavailable")
	}
	noOp, err := run(source("v2", true))
	if err != nil || !noOp.NoOp {
		t.Fatalf("no-op: %+v, %v", noOp, err)
	}
	if _, err := run(source("broken", false)); err == nil {
		t.Fatal("failed readiness accepted")
	}
	if body, err := get("app.test"); err != nil || body != "v2" {
		t.Fatal("failed release replaced serving UI")
	}
	final := load()
	if final.Pending != nil || final.Routes.Generation != second.Generation {
		t.Fatal("failed candidate was not cleanly aborted")
	}
	left := strings.Fields(must("ps", "--all", "--filter", "label=io.komizo.app="+app, "--format", "{{.Names}}"))
	if len(left) != 2 {
		t.Fatalf("superseded or failed candidate retained: %v", left)
	}
	var implicit map[string]any
	json.Unmarshal(source("v2", true), &implicit)
	delete(implicit["services"].(map[string]any)["ui"].(map[string]any), "tmpfs")
	// Build a known VOLUME control rather than assume third-party metadata.
	volumeImage := app + ":volume-control"
	if err := os.WriteFile(filepath.Join(buildDir, "Dockerfile"), []byte("FROM scratch\nCOPY box /box\nVOLUME /implicit-state\nENTRYPOINT [\"/box\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	must("build", "--network", "none", "--tag", volumeImage, buildDir)
	cleanup("image", "rm", volumeImage)
	implicit["services"].(map[string]any)["ui"].(map[string]any)["image"] = must("image", "inspect", "--format", "{{.Id}}", volumeImage)
	implicitData, _ := json.Marshal(implicit)
	if _, err := run(implicitData); err == nil {
		t.Fatal("image-declared writable state was accepted implicitly")
	}
	if names := strings.Fields(must("ps", "--all", "--filter", "label=io.komizo.app="+app, "--format", "{{.Names}}")); len(names) != 2 {
		t.Fatal("implicit-volume candidate was created before refusal")
	}
	var abortOut, abortDiag bytes.Buffer
	if err := Command(ctx, []string{"--abort", "--app", app, "--network", network,
		"--key-file", keyPath, "--state-dir", statePath, "--gateway-socket", socket,
		"--timeout", "5s", "--operation-timeout", "2s", "--poll", "10ms"}, &abortOut, &abortDiag); err != nil {
		t.Fatal(err)
	}
	if state := load(); state.Pending != nil {
		t.Fatal("preparation abort left a pending journal")
	}
	if body, err := get("app.test"); err != nil || body != "v2" {
		t.Fatal("aborting preparation disturbed the serving release")
	}
	t.Logf("real CLI rollout: %d HTTP requests during UI replacement, zero observed failures; API unchanged; no-op preserved IDs; failed readiness preserved v2; exactly 2 active service containers", requests.Load())
}
