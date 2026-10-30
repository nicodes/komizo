package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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
	cleanup := func(cid string) {
		cleanupContext, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		cmd := exec.CommandContext(cleanupContext, "docker", "rm", "-fv", cid)
		cmd.WaitDelay = 2 * time.Second
		if err := cmd.Run(); err != nil {
			t.Errorf("owned static fixture cleanup failed for %s: %v", cid, err)
		}
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
	t.Cleanup(func() { cleanup(configContainer) })
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
	baselineHost := os.Getenv("KOMIZO_STATIC_FIXTURE_HOST")
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`).MatchString(baselineHost) {
		t.Fatal("explicit fixture gate hostname required")
	}
	if name := os.Getenv("KOMIZO_STATIC_FIXTURE_SETTINGS"); name != "" {
		info, err := os.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 65536 {
			t.Fatal("explicit bounded static settings file required")
		}
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		var settings workload.StaticPolicy
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&settings); err != nil {
			t.Fatal(err)
		}
		h.policy.Static.ImageDirectory = settings.ImageDirectory
		h.policy.Static.Limits = settings.Limits
		h.policy.Static.Serving = settings.Serving
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
	proxyImage := os.Getenv("KOMIZO_STATIC_FIXTURE_PROXY_IMAGE")
	if proxyImage == "" {
		proxyImage = image
	}
	start := func(selectedImage string, extra ...string) string {
		t.Helper()
		args := []string{"run", "-d", "--label", "io.komizo.fixture=static-parity", "--publish", "127.0.0.1::80", "--user", "0:0", "--read-only", "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE", "--security-opt", "no-new-privileges:true", "--memory", "96m", "--memory-swap", "96m", "--cpus", "0.1", "--pids-limit", "64", "-e", "GOMEMLIMIT=32MiB", "-e", "GOGC=50", "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m"}
		args = append(args, extra...)
		entryJSON, err := command("image", "inspect", "--format", "{{json .Config.Entrypoint}}", selectedImage)
		var entries []string
		if err != nil || json.Unmarshal([]byte(entryJSON), &entries) != nil || len(entries) != 1 || (entries[0] != "/caddy" && entries[0] != "/usr/bin/caddy") {
			t.Fatal("unknown fixture Caddy entrypoint")
		}
		entry := entries[0]
		args = append(args, "--entrypoint", entry, selectedImage, "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile")
		cid, err := command(args...)
		if err != nil {
			t.Fatal("fixture Caddy start failed", err)
		}
		cid = strings.TrimSpace(cid)
		t.Cleanup(func() { cleanup(cid) })
		return cid
	}
	gate := start(image)
	proxy := start(proxyImage, "-v", proxyConfig+":/etc/caddy/Caddyfile:ro", "-v", filepath.Join(h.root, workload.StaticRoot)+":/srv/public:ro")
	// Compare the previous public path, including its front proxy. Comparing
	// directly to the gate misses response defaults introduced by proxying.
	gateIP, err := command("inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", gate)
	gateIP = strings.TrimSpace(gateIP)
	if err != nil || net.ParseIP(gateIP) == nil {
		t.Fatal("owned baseline gate address unavailable", err)
	}
	baselineConfig := filepath.Join(t.TempDir(), "Caddyfile")
	baselineBody := fmt.Sprintf("{\n auto_https off\n admin off\n persist_config off\n}\nhttp://example.test {\n header >X-Komizo-Revision %s\n reverse_proxy %s:80 {\n header_up Host %s\n }\n}\nhttp:// {\n respond 404\n}\n", r.Candidate, gateIP, baselineHost)
	if err := os.WriteFile(baselineConfig, []byte(baselineBody), 0644); err != nil {
		t.Fatal(err)
	}
	baselineProxy := start(proxyImage, "-v", baselineConfig+":/etc/caddy/Caddyfile:ro")

	type response struct {
		status   string
		headers  map[string]string
		body     []byte
		checksum string
		size     int64
		failure  string
	}
	addresses := map[string]string{}
	for _, cid := range []string{gate, proxy, baselineProxy} {
		address, err := command("port", cid, "80/tcp")
		if err != nil || !strings.HasPrefix(strings.TrimSpace(address), "127.0.0.1:") {
			t.Fatal("fixture port is not loopback", err)
		}
		addresses[cid] = "http://" + strings.TrimSpace(address)
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{DisableCompression: true}}
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
			return response{headers: map[string]string{}, failure: err.Error()}
		}
		defer actual.Body.Close()
		hash := sha256.New()
		body, err := io.ReadAll(io.LimitReader(io.TeeReader(actual.Body, hash), 2<<20))
		if err != nil {
			t.Fatal(err)
		}
		remaining, err := io.Copy(hash, io.LimitReader(actual.Body, workload.StaticFileBytesCeiling-int64(len(body))+1))
		if err != nil || int64(len(body))+remaining > workload.StaticFileBytesCeiling {
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
		baseline = fetch(baselineProxy, "example.test", "/", "identity")
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
	entryJSON, err := command("image", "inspect", "--format", "{{json .Config.Entrypoint}}", proxyImage)
	var entries []string
	if err != nil || json.Unmarshal([]byte(entryJSON), &entries) != nil || len(entries) != 1 {
		t.Fatal("proxy entrypoint unavailable")
	}
	caddy := entries[0]
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
	{
		for _, pattern := range h.policy.Static.Serving.DenyPaths {
			paths = append(paths, strings.TrimRight(pattern, "*"))
		}
		publicTree := filepath.Join(h.root, workload.StaticRoot, r.App, r.Candidate)
		if err := filepath.WalkDir(publicTree, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !entry.IsDir() {
				relative, err := filepath.Rel(publicTree, path)
				if err != nil {
					return err
				}
				paths = append(paths, "/"+filepath.ToSlash(relative))
			}
			return nil
		}); err != nil {
			t.Fatal("validated public-tree inventory unavailable", err)
		}
		for _, match := range regexp.MustCompile(`releases/[a-f0-9]{64}/[^\"\x27\s<>]+`).FindAll(baseline.body, 16) {
			paths = append(paths, "/"+string(match))
		}
	}
	for _, path := range paths {
		for _, encoding := range []string{"identity", "gzip", "br"} {
			old := fetch(baselineProxy, "example.test", path, encoding)
			next := fetch(proxy, "example.test", path, encoding)
			if old.status != next.status || old.checksum != next.checksum || old.size != next.size || !bytes.Equal(old.body, next.body) {
				t.Fatalf("serving parity changed %s %s: %s/%s", path, encoding, old.status, next.status)
			}
			for _, header := range []string{"content-type", "content-encoding", "etag", "last-modified", "cache-control", "vary", "x-frame-options", "x-content-type-options", "referrer-policy", "cross-origin-opener-policy", "cross-origin-embedder-policy", "content-security-policy"} {
				if old.headers[header] != next.headers[header] {
					t.Fatalf("header parity changed %s %s: %s %q/%q", path, encoding, header, old.headers[header], next.headers[header])
				}
			}
			if old.headers["x-komizo-revision"] != r.Candidate || next.headers["x-komizo-revision"] != r.Candidate {
				t.Fatal("shared serving lost candidate identity", path, encoding, next.status, next.headers)
			}
		}
	}
	for _, method := range []string{"HEAD", "GET"} {
		for _, path := range paths {
			byteRange := ""
			if method == "GET" {
				byteRange = "bytes=0-63"
			}
			old := fetchMethod(baselineProxy, "example.test", path, "identity", method, byteRange)
			next := fetchMethod(proxy, "example.test", path, "identity", method, byteRange)
			if old.status != next.status || old.checksum != next.checksum || old.size != next.size || !bytes.Equal(old.body, next.body) || old.headers["content-range"] != next.headers["content-range"] || old.headers["content-length"] != next.headers["content-length"] {
				t.Fatal("HEAD/range parity differs", path, method, old.status, next.status)
			}
			for _, header := range []string{"content-type", "content-encoding", "cache-control", "vary", "x-frame-options", "x-content-type-options", "referrer-policy", "cross-origin-opener-policy", "cross-origin-embedder-policy", "content-security-policy", "x-komizo-revision"} {
				if old.headers[header] != next.headers[header] {
					t.Fatalf("HEAD/range header parity differs %s %s: %s %q/%q", path, method, header, old.headers[header], next.headers[header])
				}
			}
		}
	}
	if fetch(proxy, "foreign.test", "/", "identity").status != "404" || fetch(gate, "foreign.test", "/", "identity").status != "404" {
		t.Fatal("unreviewed hostname served")
	}

	var limits struct {
		HostConfig struct {
			Memory   int64
			NanoCpus int64
		}
		State struct{ Pid int }
	}
	installed, err := command("inspect", "--format", "{{json .}}", proxy)
	if err != nil || json.Unmarshal([]byte(installed), &limits) != nil || limits.HostConfig.Memory != 96<<20 || limits.HostConfig.NanoCpus != 100000000 {
		t.Fatal("actual proxy fixture allocation differs")
	}
	cgroup := func() string {
		installed, err := command("inspect", "--format", "{{json .}}", proxy)
		if err != nil || json.Unmarshal([]byte(installed), &limits) != nil {
			t.Fatal("fixture PID unavailable")
		}
		body, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", limits.State.Pid))
		if err != nil || !strings.HasPrefix(string(body), "0::/") || strings.Contains(string(body), "..") {
			t.Fatal("fixture cgroup unavailable", err)
		}
		return filepath.Join("/sys/fs/cgroup", strings.TrimSpace(strings.TrimPrefix(string(body), "0::")))
	}
	counters := func(path string) map[string]int64 {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("fixture counter unavailable", err)
		}
		out := map[string]int64{}
		fields := strings.Fields(string(body))
		for i := 0; i+1 < len(fields); i += 2 {
			value, err := strconv.ParseInt(fields[i+1], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			out[fields[i]] = value
		}
		return out
	}
	group := cgroup()
	before := counters(filepath.Join(group, "memory.events"))
	cpuBefore := counters(filepath.Join(group, "cpu.stat"))
	loadPath := "/index.html"
	var largest int64
	for _, path := range paths {
		if strings.HasPrefix(path, "/") {
			info, err := os.Stat(filepath.Join(h.root, workload.StaticRoot, r.App, r.Candidate, filepath.FromSlash(strings.TrimPrefix(path, "/"))))
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			if response := fetch(baselineProxy, "example.test", path, "identity"); !strings.HasPrefix(response.status, "200 ") {
				continue
			}
			if info.Size() > largest {
				loadPath = path
				largest = info.Size()
			}
		}
	}
	expected := fetch(proxy, "example.test", loadPath, "identity")
	if expected.status != "200" {
		t.Fatal("fixture load asset unavailable")
	}
	type loaded struct {
		size     int64
		checksum string
		err      error
	}
	loads := make(chan loaded, 2)
	for worker := 0; worker < 2; worker++ {
		go func() {
			req, e := http.NewRequestWithContext(ctx, "GET", addresses[proxy]+loadPath, nil)
			if e != nil {
				loads <- loaded{err: e}
				return
			}
			req.Host = "example.test"
			req.Header.Set("Accept-Encoding", "identity")
			res, e := client.Do(req)
			if e != nil {
				loads <- loaded{err: e}
				return
			}
			defer res.Body.Close()
			if res.StatusCode != 200 || res.Header.Get("X-Komizo-Revision") != r.Candidate {
				loads <- loaded{err: fmt.Errorf("load serving identity differs")}
				return
			}
			hash := sha256.New()
			n, e := io.Copy(hash, io.LimitReader(res.Body, workload.StaticFileBytesCeiling+1))
			loads <- loaded{size: n, checksum: hex.EncodeToString(hash.Sum(nil)), err: e}
		}()
	}
	var maximumCore time.Duration
	for request := 0; request < 20; request++ {
		began := time.Now()
		core := fetch(proxy, "example.test", "/", "identity")
		elapsed := time.Since(began)
		if core.status != "200" || core.headers["x-komizo-revision"] != r.Candidate || elapsed > 2*time.Second {
			t.Fatal("core read exceeded the synthetic two-second allowance under two concurrent asset transfers", elapsed)
		}
		if elapsed > maximumCore {
			maximumCore = elapsed
		}
	}
	for worker := 0; worker < 2; worker++ {
		select {
		case result := <-loads:
			if result.err != nil || result.size != expected.size || result.checksum != expected.checksum {
				t.Fatal("concurrent transfer differs", result.err)
			}
		case <-ctx.Done():
			t.Fatal("concurrent transfer deadline")
		}
	}
	after := counters(filepath.Join(group, "memory.events"))
	cpuAfter := counters(filepath.Join(group, "cpu.stat"))
	if after["oom"] != before["oom"] || after["oom_kill"] != before["oom_kill"] {
		t.Fatal("proxy fixture OOM under declared load")
	}
	if _, err := command("restart", proxy); err != nil {
		t.Fatal("fixture proxy restart failed", err)
	}
	address, err := command("port", proxy, "80/tcp")
	if err != nil || !strings.HasPrefix(strings.TrimSpace(address), "127.0.0.1:") {
		t.Fatal("restarted fixture port is not loopback", err)
	}
	addresses[proxy] = "http://" + strings.TrimSpace(address)
	recovered := false
	var recoveryResponse response
	for attempt := 0; attempt < 40; attempt++ {
		check := fetch(proxy, "example.test", "/", "identity")
		recoveryResponse = check
		if check.status == "200" && check.headers["x-komizo-revision"] == r.Candidate {
			recovered = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !recovered {
		state, stateErr := command("inspect", "--format", "{{json .State}} {{json .NetworkSettings.Ports}}", proxy)
		logs, logErr := command("logs", "--tail", "40", proxy)
		t.Fatalf("proxy did not recover serving identity: response=%+v state=%s (%v) logs=%s (%v)", recoveryResponse, state, stateErr, logs, logErr)
	}
	recovery := fetchMethod(proxy, "example.test", loadPath, "identity", "GET", "bytes=0-63")
	if recovery.status != "206" || recovery.size != 64 {
		t.Fatal("asset range did not recover")
	}
	loadProof := map[string]any{"asset": loadPath, "asset_bytes": expected.size, "concurrent_transfers": 2, "core_reads": 20, "core_allowance_ms": 2000, "maximum_core_ms": float64(maximumCore.Microseconds()) / 1000, "memory_events_before": before, "memory_events_after": after, "cpu_before": cpuBefore, "cpu_after": cpuAfter, "process_restart_recovered": true}

	proof, _ := json.Marshal(map[string]any{"image": image, "configuration_sha256": h.policy.Static.GateConfigSHA, "tree_sha256": h.static.record.TreeSHA256, "paths": paths, "encodings": []string{"identity", "gzip", "br"}, "methods": []string{"GET", "HEAD"}, "range": "bytes=0-63", "serving": h.policy.Static.Serving, "image_directory": h.policy.Static.ImageDirectory, "limits": h.policy.Static.Limits, "proxy_image": proxyImage, "baseline_includes_front_proxy": true, "load": loadProof, "memory_bytes": 96 << 20, "milli_cpus": 100, "loopback_ports_only": true, "public_mount_read_only": true, "source_admission": "separate fixtures", "result": "passed"})
	fmt.Println(string(proof))
}
