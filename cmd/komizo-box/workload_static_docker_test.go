package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/internal/workload"
)

// Explicit disposable fixture, never a registry push or a production route.
// It exercises real Docker copy/extraction and Caddy serving. Source identity
// admission and owner lifecycle are covered by their independent host fixtures.
func TestStaticDockerCopyAndCaddyParity(t *testing.T) {
	image := os.Getenv("KOMIZO_STATIC_FIXTURE_IMAGE")
	if image == "" {
		t.Skip("explicit local immutable public fixture image required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("fixture must exercise actual root ownership")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	command := func(args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, "docker", args...)
		var out bytes.Buffer
		cmd.Stdout = &out
		var diagnostic bytes.Buffer
		cmd.Stderr = &diagnostic
		if len(args) > 0 && args[0] == "logs" {
			cmd.Stderr = &out
		}
		err := cmd.Run()
		if err != nil {
			err = fmt.Errorf("%w: %s %s", err, diagnostic.String(), out.String())
		}
		return out.String(), err
	}
	actual, err := command("image", "inspect", "--format", "{{.Id}}", image)
	if err != nil || !strings.HasPrefix(strings.TrimSpace(actual), "sha256:") {
		t.Fatal("fixture image unavailable")
	}
	image = strings.TrimSpace(actual)
	configContainer, err := command("create", "--network", "none", "--entrypoint", "/nonexistent", image)
	if err != nil {
		t.Fatal(err)
	}
	configContainer = strings.TrimSpace(configContainer)
	defer command("rm", "-fv", configContainer)
	configPath := filepath.Join(t.TempDir(), "Caddyfile")
	if _, err := command("cp", configContainer+":/etc/caddy/Caddyfile", configPath); err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(config)
	h, r, _ := staticActivationFixture(t)
	baselineHost := "app.ctcalc.com"
	if os.Getenv("KOMIZO_STATIC_FIXTURE_PROFILE") == "godot-v1" {
		h.policy.Static.Profile = "godot-v1"
		baselineHost = "prizm.avior.studio"
	}
	h.makeStaticDir = nil
	h.policy.Static.GateConfigSHA = hex.EncodeToString(sum[:])
	fake := h.run
	h.run = func(ctx context.Context, args ...string) (string, error) {
		if args[0] == "create" {
			args[len(args)-1] = image
			return command(args...)
		}
		if args[0] == "rm" {
			return command(args...)
		}
		if args[0] == "image" && len(args) > 2 && args[2] == "--format" {
			args[len(args)-1] = image
			return command(args...)
		}
		return fake(ctx, args...)
	}
	h.staticStream = dockerStaticStream
	if err := h.prepareStatic(ctx, r); err != nil {
		t.Fatal(err)
	}
	active, err := os.ReadFile(r.RoutePath)
	if err != nil {
		t.Fatal(err)
	}
	// Only the fixture's listener wrapper changes: real deployment retains the
	// parent's TLS policy. Both isolated containers expose only ephemeral loopback ports.
	fixtureRoute := strings.Replace(string(active), "example.test {", "http://example.test {", 1)
	proxyConfig := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(proxyConfig, []byte("{\n auto_https off\n admin 127.0.0.1:2019\n persist_config off\n}\n"+fixtureRoute+"\nhttp:// {\n respond \"no route for this hostname\" 404\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	start := func(extra ...string) string {
		t.Helper()
		args := []string{"run", "-d", "--publish", "127.0.0.1::80", "--user", "0:0", "--read-only", "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE", "--security-opt", "no-new-privileges:true", "--memory", "128m", "--memory-swap", "128m", "--cpus", "0.5", "--pids-limit", "64", "-e", "GOMEMLIMIT=32MiB", "-e", "GOGC=50", "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m"}
		args = append(args, extra...)
		entry := "/usr/bin/caddy"
		if h.policy.Static.Profile == "godot-v1" {
			entry = "/caddy"
		}
		args = append(args, "--entrypoint", entry, image, "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile")
		cid, err := command(args...)
		if err != nil {
			t.Fatal("fixture Caddy start failed", err)
		}
		cid = strings.TrimSpace(cid)
		t.Cleanup(func() { _, _ = command("rm", "-fv", cid) })
		return cid
	}
	gate := start()
	proxy := start("-v", proxyConfig+":/etc/caddy/Caddyfile:ro", "-v", filepath.Join(h.root, workload.StaticRoot)+":/srv/public:ro")

	type response struct {
		status   string
		headers  map[string]string
		body     []byte
		checksum string
		size     int64
	}
	addresses := map[string]string{}
	for _, cid := range []string{gate, proxy} {
		address, err := command("port", cid, "80/tcp")
		if err != nil || !strings.HasPrefix(strings.TrimSpace(address), "127.0.0.1:") {
			t.Fatal("fixture port is not loopback", err)
		}
		addresses[cid] = "http://" + strings.TrimSpace(address)
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableCompression: true}}
	t.Cleanup(func() { client.CloseIdleConnections() })
	fetchMethod := func(cid, host, path, encoding, method, byteRange string) response {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, addresses[cid]+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		req.Header.Set("Accept-Encoding", encoding)
		if byteRange != "" {
			req.Header.Set("Range", byteRange)
		}
		actual, err := client.Do(req)
		if err != nil {
			return response{headers: map[string]string{}}
		}
		defer actual.Body.Close()
		hash := sha256.New()
		body, err := io.ReadAll(io.LimitReader(io.TeeReader(actual.Body, hash), 2<<20))
		if err != nil {
			t.Fatal(err)
		}
		remaining, err := io.Copy(hash, io.LimitReader(actual.Body, workload.GodotStaticMaxFileBytes-int64(len(body))+1))
		if err != nil || int64(len(body))+remaining > workload.GodotStaticMaxFileBytes {
			t.Fatal("unbounded serving response", err)
		}
		out := response{status: fmt.Sprint(actual.StatusCode), body: body, checksum: hex.EncodeToString(hash.Sum(nil)), size: int64(len(body)) + remaining, headers: map[string]string{}}
		for key, values := range actual.Header {
			out.headers[strings.ToLower(key)] = strings.Join(values, ", ")
		}
		return out
	}
	fetch := func(cid, host, path, encoding string) response {
		return fetchMethod(cid, host, path, encoding, "GET", "")
	}
	var baseline response
	for attempt := 0; attempt < 40; attempt++ {
		baseline = fetch(gate, baselineHost, "/", "identity")
		if baseline.status == "200" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if baseline.status != "200" {
		t.Fatal("isolated gate failed readiness")
	}
	for attempt := 0; attempt < 40; attempt++ {
		if fetch(proxy, "example.test", "/", "identity").status == "200" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	state, _ := command("inspect", "--format", "{{.State.Status}} {{.State.ExitCode}} {{.State.OOMKilled}}", proxy)
	if !strings.HasPrefix(state, "running ") {
		log, _ := command("logs", proxy)
		t.Fatal("fixture proxy startup", state, log)
	}
	caddy := "/usr/bin/caddy"
	if h.policy.Static.Profile == "godot-v1" {
		caddy = "/caddy"
	}
	if _, err := command("exec", proxy, caddy, "validate", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"); err != nil {
		t.Fatal("whole fixture configuration invalid", err)
	}
	if _, err := command("exec", proxy, caddy, "reload", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"); err != nil {
		t.Fatal("fixture reload failed")
	}
	paths := []string{"/", "/index.html", "/deep/link", "/missing.html", "/../../secrets.env"}
	for _, match := range regexp.MustCompile(`(?:src|href)="(/[^"?#]+)"`).FindAllSubmatch(baseline.body, 16) {
		path := string(match[1])
		if !strings.HasPrefix(path, "//") {
			paths = append(paths, path)
		}
	}
	if h.policy.Static.Profile == "godot-v1" {
		paths = append(paths, "/index.js", "/index.wasm", "/index.pck")
		for _, match := range regexp.MustCompile(`releases/[a-f0-9]{64}/[^\"\x27\s<>]+`).FindAll(baseline.body, 16) {
			paths = append(paths, "/"+string(match))
		}
	}
	for _, path := range paths {
		for _, encoding := range []string{"identity", "gzip"} {
			old := fetch(gate, baselineHost, path, encoding)
			next := fetch(proxy, "example.test", path, encoding)
			if old.status != next.status || old.checksum != next.checksum || old.size != next.size || !bytes.Equal(old.body, next.body) {
				t.Fatalf("serving parity changed %s %s: %s/%s", path, encoding, old.status, next.status)
			}
			for _, header := range []string{"content-type", "content-encoding", "etag", "last-modified", "cache-control", "vary", "x-frame-options", "x-content-type-options", "referrer-policy", "cross-origin-opener-policy", "cross-origin-embedder-policy", "content-security-policy"} {
				if old.headers[header] != next.headers[header] {
					t.Fatalf("header parity changed %s %s: %s %q/%q", path, encoding, header, old.headers[header], next.headers[header])
				}
			}
			if next.status == "200" && next.headers["x-komizo-revision"] != r.Candidate {
				t.Fatal("shared serving lost candidate identity", path, encoding, next.status, next.headers)
			}
		}
	}
	for _, method := range []string{"HEAD", "GET"} {
		for _, path := range []string{"/", "/index.html"} {
			byteRange := ""
			if method == "GET" {
				byteRange = "bytes=0-63"
			}
			old := fetchMethod(gate, baselineHost, path, "identity", method, byteRange)
			next := fetchMethod(proxy, "example.test", path, "identity", method, byteRange)
			if old.status != next.status || old.checksum != next.checksum || old.size != next.size || !bytes.Equal(old.body, next.body) || old.headers["content-range"] != next.headers["content-range"] || old.headers["content-length"] != next.headers["content-length"] {
				t.Fatal("HEAD/range parity differs", path, method, old.status, next.status)
			}
		}
	}
	if fetch(proxy, "foreign.test", "/", "identity").status != "404" || fetch(gate, "foreign.test", "/", "identity").status != "404" {
		t.Fatal("unreviewed hostname served")
	}
	proof, _ := json.Marshal(map[string]any{"image": image, "configuration_sha256": h.policy.Static.GateConfigSHA, "tree_sha256": h.static.record.TreeSHA256, "paths": paths, "encodings": []string{"identity", "gzip"}, "methods": []string{"GET", "HEAD"}, "range": "bytes=0-63", "loopback_ports_only": true, "public_mount_read_only": true, "source_admission": "separate fixtures", "result": "passed"})
	fmt.Println(string(proof))
}
