package release_test

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nicodes/komizo/internal/rollout"
)

// This is a real routing control, not the production rollout engine. It proves
// only HTTP request routing/draining on the pinned fixture. It makes no claim
// about DB operations, app writes, WebSocket resumption or host-failure survival.
func TestPinnedCaddySwitchAndHTTPDrain(t *testing.T) {
	if os.Getenv("KOMIZO_TEST_CADDY") != "1" {
		t.Skip("set KOMIZO_TEST_CADDY=1 for isolated Caddy routing control")
	}
	const caddyImage = "caddy@sha256:c3d7ee5d2b11f9dc54f947f68a734c84e9c9666c92c88a7f30b9cba5da182adb"
	id := "kmz-continuity-" + strings.ToLower(rand.Text()[:12])
	docker := func(args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "docker", append([]string{"--host", "unix:///var/run/docker.sock"}, args...)...)
		out, err := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	mustDocker := func(args ...string) string {
		t.Helper()
		out, err := docker(args...)
		if err != nil {
			t.Fatalf("isolated fixture command failed: %v\n%s", err, out)
		}
		return out
	}
	cleanup := func(args ...string) {
		t.Cleanup(func() {
			if out, err := docker(args...); err != nil {
				t.Errorf("fixture cleanup failed: %v\n%s", err, out)
			}
		})
	}
	buildDir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", filepath.Join(buildDir, "server"), "../../testdata/continuity")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("fixture binary build: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(buildDir, "Dockerfile"), []byte("FROM scratch\nCOPY server /server\nUSER 65534:65534\nENTRYPOINT [\"/server\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	image := id + ":test"
	mustDocker("build", "--network", "none", "--tag", image, buildDir)
	cleanup("image", "rm", image)
	mustDocker("network", "create", "--internal", "--label", "komizo.test="+id, id)
	cleanup("network", "rm", id)
	// Docker 29 does not publish host ports for an internal-only endpoint.
	// Model the real boundary: only the proxy joins a separate test edge;
	// application instances remain on the internal network exclusively.
	edge := id + "-edge"
	mustDocker("network", "create", "--label", "komizo.test="+id, edge)
	cleanup("network", "rm", edge)
	for _, version := range []string{"old", "new"} {
		name := id + "-" + version
		mustDocker("run", "--detach", "--name", name, "--label", "komizo.test="+id,
			"--network", id, "--network-alias", version, "--read-only", "--cap-drop", "ALL",
			"--security-opt", "no-new-privileges", image, "--release", version)
		cleanup("rm", "--force", "--volumes", name)
	}
	config := func(upstream string) []byte {
		value := map[string]any{
			"admin": map[string]any{"listen": ":2019", "config": map[string]any{"persist": false}},
			"apps": map[string]any{"http": map[string]any{"servers": map[string]any{"fixture": map[string]any{
				"listen": []string{":8080"},
				"routes": []any{map[string]any{"handle": []any{map[string]any{
					"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": upstream + ":8080"}},
				}}}},
			}}}},
		}
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	configPath := filepath.Join(buildDir, "caddy.json")
	if err := os.WriteFile(configPath, config("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	proxy := id + "-proxy"
	mustDocker("run", "--detach", "--name", proxy, "--label", "komizo.test="+id,
		"--network", edge, "--read-only", "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE", "--security-opt", "no-new-privileges",
		"--publish", "127.0.0.1::8080", "--publish", "127.0.0.1::2019",
		"--mount", "type=bind,src="+configPath+",dst=/fixture.json,readonly",
		caddyImage, "caddy", "run", "--config", "/fixture.json")
	cleanup("rm", "--force", "--volumes", proxy)
	mustDocker("network", "connect", id, proxy)
	if status := mustDocker("inspect", "--format", "{{.State.Status}}", proxy); status != "running" {
		t.Fatalf("fixture proxy is %s: %s", status, mustDocker("logs", proxy))
	}
	endpoint := "http://" + mustDocker("port", proxy, "8080/tcp")
	admin := "http://" + mustDocker("port", proxy, "2019/tcp")
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	t.Cleanup(client.CloseIdleConnections)
	get := func(path string) (string, error) {
		res, err := client.Get(endpoint + path)
		if err != nil {
			return "", err
		}
		defer res.Body.Close()
		body, err := io.ReadAll(io.LimitReader(res.Body, 4096))
		if err != nil || res.StatusCode != http.StatusOK {
			return "", fmt.Errorf("fixture request status=%d: %w", res.StatusCode, err)
		}
		return string(body), nil
	}
	readyDeadline := time.Now().Add(10 * time.Second)
	for {
		if body, err := get("/"); err == nil && body == "old" {
			break
		}
		if time.Now().After(readyDeadline) {
			t.Fatal("fixture did not become ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	var baseline []time.Duration
	baselineSamples := make(chan time.Duration, 400)
	var baselineWG sync.WaitGroup
	for range 4 {
		baselineWG.Go(func() {
			for range 100 {
				start := time.Now()
				if body, err := get("/"); err != nil || body != "old" {
					t.Errorf("baseline failed: %q, %v", body, err)
				}
				baselineSamples <- time.Since(start)
			}
		})
	}
	baselineWG.Wait()
	close(baselineSamples)
	for sample := range baselineSamples {
		baseline = append(baseline, sample)
	}
	// Invalid routing configuration must leave the old route usable. This is
	// Caddy's config transaction control, not an app/schema rollback policy.
	router, err := rollout.NewCaddy(admin, nil, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	invalidCtx, invalidCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer invalidCancel()
	// Preserve the management settings even in the deliberately invalid
	// application config; the updater must reject changes to admin itself.
	invalidConfig := []byte(`{"admin":{"listen":":2019","config":{"persist":false}},"apps":{"unknown-fixture-module":{}}}`)
	if err := router.Apply(invalidCtx, invalidConfig); err == nil {
		t.Fatal("invalid route configuration was accepted")
	}
	if body, err := get("/"); err != nil || body != "old" {
		t.Fatalf("failed config update interrupted old route: %q, %v", body, err)
	}
	// Establish an old-release response before switching. Reading the first
	// SSE line proves the handler is in flight rather than merely queued.
	slow, err := client.Get(endpoint + "/slow")
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Body.Close()
	reader := bufio.NewReader(slow.Body)
	if first, err := reader.ReadString('\n'); err != nil || first != "data: old-start\n" {
		t.Fatalf("old request not established: %q, %v", first, err)
	}
	var wg sync.WaitGroup
	type observation struct {
		latency time.Duration
		err     error
	}
	observations := make(chan observation, 400)
	for range 4 {
		wg.Go(func() {
			for range 100 {
				start := time.Now()
				body, err := get("/")
				if err == nil && body != "old" && body != "new" {
					err = fmt.Errorf("unexpected fixture response")
				}
				observations <- observation{time.Since(start), err}
			}
		})
	}
	switchCtx, switchCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer switchCancel()
	if err := router.Apply(switchCtx, config("new")); err != nil {
		diagnostic, _ := docker("exec", proxy, "wget", "-qO-", "http://localhost:2019/config/")
		t.Fatalf("%v; synthetic fixture internal config: %s; logs: %s", err, diagnostic, mustDocker("logs", proxy))
	}
	if body, err := get("/"); err != nil || body != "new" {
		t.Fatalf("new requests did not switch: %q, %v", body, err)
	}
	remainder, err := io.ReadAll(reader)
	if err != nil || !strings.Contains(string(remainder), "data: old-complete") {
		t.Fatalf("in-flight old request was interrupted: %q, %v", remainder, err)
	}
	// Retire only after this fixture's known old request drains. This is not a
	// production drain detector or an approved user-session retirement budget.
	mustDocker("stop", "--time", "1", id+"-old")
	wg.Wait()
	close(observations)
	var latencies []time.Duration
	for observation := range observations {
		if observation.err != nil {
			t.Errorf("request interrupted during switch: %v", observation.err)
		}
		latencies = append(latencies, observation.latency)
	}
	if body, err := get("/"); err != nil || body != "new" {
		t.Fatalf("service unavailable after old retirement: %q, %v", body, err)
	}
	slices.Sort(baseline)
	slices.Sort(latencies)
	t.Logf("synthetic control: baseline n=%d concurrency=4 p99=%s max=%s; switch n=%d concurrency=4 p99=%s max=%s; old HTTP stream completed before retirement",
		len(baseline), baseline[len(baseline)*99/100], baseline[len(baseline)-1],
		len(latencies), latencies[len(latencies)*99/100], latencies[len(latencies)-1])
}
