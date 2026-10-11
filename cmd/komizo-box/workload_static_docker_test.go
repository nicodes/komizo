package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	// parent's TLS policy. Both isolated containers expose no host ports.
	fixtureRoute := strings.Replace(string(active), "example.test {", "http://example.test {", 1)
	proxyConfig := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(proxyConfig, []byte("{\n auto_https off\n admin 127.0.0.1:2019\n persist_config off\n}\n"+fixtureRoute+"\nhttp:// {\n respond \"no route for this hostname\" 404\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	start := func(extra ...string) string {
		t.Helper()
		args := []string{"run", "-d", "--network", "none", "--user", "0:0", "--read-only", "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE", "--security-opt", "no-new-privileges:true", "--memory", "128m", "--memory-swap", "128m", "--cpus", "0.5", "--pids-limit", "64", "-e", "GOMEMLIMIT=32MiB", "-e", "GOGC=50", "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m"}
		args = append(args, extra...)
		args = append(args, "--entrypoint", "/usr/bin/caddy", image, "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile")
		cid, err := command(args...)
		if err != nil {
			t.Fatal("fixture Caddy start failed")
		}
		cid = strings.TrimSpace(cid)
		t.Cleanup(func() { _, _ = command("rm", "-fv", cid) })
		return cid
	}
	gate := start()
	proxy := start("-v", proxyConfig+":/etc/caddy/Caddyfile:ro", "-v", filepath.Join(h.root, workload.StaticRoot)+":/srv/public:ro")

	type response struct {
		status  string
		headers map[string]string
		body    []byte
	}
	fetch := func(cid, host, path, encoding string) response {
		t.Helper()
		cmd := exec.CommandContext(ctx, "docker", "exec", cid, "wget", "-S", "-O", "-", "--header=Host: "+host, "--header=Accept-Encoding: "+encoding, "http://127.0.0.1"+path)
		var body, headers bytes.Buffer
		cmd.Stdout = &body
		cmd.Stderr = &headers
		_ = cmd.Run()
		out := response{body: body.Bytes(), headers: map[string]string{}}
		for _, line := range strings.Split(headers.String(), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "HTTP/") {
				parts := strings.Fields(line)
				if len(parts) > 1 {
					out.status = parts[1]
				}
			} else if key, value, ok := strings.Cut(line, ":"); ok {
				out.headers[strings.ToLower(key)] = strings.TrimSpace(value)
			}
		}
		return out
	}
	var baseline response
	for attempt := 0; attempt < 40; attempt++ {
		baseline = fetch(gate, "app.ctcalc.com", "/", "identity")
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
	if _, err := command("exec", proxy, "caddy", "validate", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"); err != nil {
		t.Fatal("whole fixture configuration invalid", err)
	}
	if _, err := command("exec", proxy, "caddy", "reload", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"); err != nil {
		t.Fatal("fixture reload failed")
	}
	paths := []string{"/", "/index.html", "/deep/link", "/missing.html", "/../../secrets.env"}
	for _, match := range regexp.MustCompile(`(?:src|href)="(/[^"?#]+)"`).FindAllSubmatch(baseline.body, 16) {
		path := string(match[1])
		if !strings.HasPrefix(path, "//") {
			paths = append(paths, path)
		}
	}
	for _, path := range paths {
		for _, encoding := range []string{"identity", "gzip"} {
			old := fetch(gate, "app.ctcalc.com", path, encoding)
			next := fetch(proxy, "example.test", path, encoding)
			if old.status != next.status || !bytes.Equal(old.body, next.body) {
				t.Fatalf("serving parity changed %s %s: %s/%s", path, encoding, old.status, next.status)
			}
			for _, header := range []string{"content-type", "content-encoding", "etag", "last-modified", "cache-control", "vary", "x-frame-options", "x-content-type-options", "referrer-policy"} {
				if old.headers[header] != next.headers[header] {
					t.Fatalf("header parity changed %s %s: %s %q/%q", path, encoding, header, old.headers[header], next.headers[header])
				}
			}
			if next.headers["x-komizo-revision"] != r.Candidate {
				t.Fatal("shared serving lost candidate identity")
			}
		}
	}
	if fetch(proxy, "foreign.test", "/", "identity").status != "404" || fetch(gate, "foreign.test", "/", "identity").status != "404" {
		t.Fatal("unreviewed hostname served")
	}
	proof, _ := json.Marshal(map[string]any{"image": image, "configuration_sha256": h.policy.Static.GateConfigSHA, "tree_sha256": h.static.record.TreeSHA256, "paths": paths, "encodings": []string{"identity", "gzip"}, "no_host_ports": true, "public_mount_read_only": true, "source_admission": "separate fixtures", "result": "passed"})
	fmt.Println(string(proof))
}
