//go:build linux || darwin

package workload

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type staticProxyLog struct {
	sync.Mutex
	body bytes.Buffer
}

func (l *staticProxyLog) Write(p []byte) (int, error) {
	l.Lock()
	defer l.Unlock()
	return l.body.Write(p)
}
func (l *staticProxyLog) String() string { l.Lock(); defer l.Unlock(); return l.body.String() }

func stockStaticProxy(t *testing.T, binary, fragment, public string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	root := t.TempDir()
	fragment = strings.ReplaceAll(fragment, "/srv/public/example/"+strings.Repeat("a", 40), strconv.Quote(filepath.ToSlash(public)))
	config := fmt.Sprintf("{\n admin off\n auto_https off\n}\nhttp://127.0.0.1:%d {\n header X-Komizo-Revision \"%s\"\n%s\n}\n", port, strings.Repeat("a", 40), fragment)
	file := filepath.Join(root, "Caddyfile")
	if err := os.WriteFile(file, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	command := exec.CommandContext(ctx, binary, "run", "--config", file, "--adapter", "caddyfile")
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + root, "XDG_CONFIG_HOME=" + root, "XDG_DATA_HOME=" + root}
	logs := new(staticProxyLog)
	command.Stdout, command.Stderr = logs, logs
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() { cancel(); <-done })
	endpoint := fmt.Sprintf("http://127.0.0.1:%d", port)
	client := http.Client{Timeout: time.Second, Transport: &http.Transport{DisableCompression: true}}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get(endpoint + "/index.html")
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode == 200 && response.Header.Get("X-Komizo-Revision") == strings.Repeat("a", 40) {
				return endpoint
			}
		}
		select {
		case status := <-done:
			// Cleanup still owns the completed process and consumes one result.
			done <- status
			t.Fatalf("stock proxy refused generated settings: %v\n%s", status, logs.String())
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("stock proxy did not become ready\n%s", logs.String())
	return ""
}

func TestExplicitStaticSettingsPreserveStockProxyHTTPBehavior(t *testing.T) {
	binary, err := exec.LookPath("caddy")
	if err != nil {
		if os.Getenv("CI") == "true" {
			t.Fatal("the pinned stock proxy is required for HTTP serving verification")
		}
		t.Skip("stock Caddy executable unavailable")
	}
	public := t.TempDir()
	script := []byte("console.log(42);\n")
	brotli, err := base64.StdEncoding.DecodeString("CwiAY29uc29sZS5sb2coNDIpOwoD")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"index.html": []byte("<!doctype html><p>" + strings.Repeat("fixture ", 600) + "</p>"),
		"index.js":   script, "assets/app.js": script, "releases/" + strings.Repeat("a", 64) + "/app.js": script,
		"data.json": []byte("{\"ready\":true}"), "assets/font.woff": []byte("public-font"),
	}
	stamp := time.Unix(1700000000, 0)
	write := func(name string, body []byte) {
		path := filepath.Join(public, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0444); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range files {
		write(name, body)
		if strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".html") {
			var output bytes.Buffer
			compressed := gzip.NewWriter(&output)
			_, _ = compressed.Write(body)
			if err := compressed.Close(); err != nil {
				t.Fatal(err)
			}
			write(name+".gz", output.Bytes())
		}
		if strings.HasSuffix(name, ".js") {
			write(name+".br", brotli)
		}
	}
	client := http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{DisableCompression: true}}
	request := func(t *testing.T, endpoint, method, path, encoding string, headers map[string]string) (int, http.Header, []byte) {
		t.Helper()
		req, err := http.NewRequest(method, endpoint+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Accept-Encoding", encoding)
		for name, value := range headers {
			req.Header.Set(name, value)
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, response.Header, body
	}
	compare := func(t *testing.T, before, after, method, path, encoding string, headers map[string]string) (int, http.Header, []byte) {
		t.Helper()
		status, old, body := request(t, before, method, path, encoding, headers)
		actual, next, payload := request(t, after, method, path, encoding, headers)
		if actual != status || !bytes.Equal(body, payload) {
			t.Fatalf("HTTP parity changed: %s %s %s: %d/%d", method, path, encoding, status, actual)
		}
		for _, name := range []string{"Content-Type", "Content-Encoding", "Content-Length", "Content-Range", "Etag", "Last-Modified", "Cache-Control", "Vary", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy", "Content-Security-Policy", "X-Komizo-Revision"} {
			if old.Get(name) != next.Get(name) {
				t.Fatalf("%s parity changed: %s %s %s: %q/%q", name, method, path, encoding, old.Get(name), next.Get(name))
			}
		}
		if next.Get("X-Komizo-Revision") != strings.Repeat("a", 40) {
			t.Fatal("response lost its immutable source identity")
		}
		return actual, next, payload
	}
	for _, name := range []string{"html_fallback", "cache_rules", "root_assets", "immutable_assets"} {
		t.Run(name, func(t *testing.T) {
			settings := staticFixture(t, name).Serving
			body, err := os.ReadFile(filepath.Join("testdata", "static", "before", name+".caddy"))
			if err != nil {
				t.Fatal(err)
			}
			before := stockStaticProxy(t, binary, string(body), public)
			after := stockStaticProxy(t, binary, staticServingRoute("example", strings.Repeat("a", 40), settings), public)
			for _, path := range []string{"/", "/index.html", "/deep/link", "/missing.html", "/missing.js", "/index.js", "/index.js.br", "/assets/app.js", "/assets/app.js.br", "/data.json", "/assets/font.woff", "/releases/" + strings.Repeat("a", 64) + "/app.js", "/releases/short/missing.js"} {
				for _, method := range []string{"GET", "HEAD"} {
					for _, encoding := range []string{"identity", "gzip", "br"} {
						compare(t, before, after, method, path, encoding, nil)
					}
				}
			}
			status, headers, _ := compare(t, before, after, "GET", "/assets/app.js", "identity", nil)
			if status != 200 || headers.Get("Etag") == "" {
				t.Fatal("regular public artifact has no cache validator")
			}
			status, _, payload := compare(t, before, after, "GET", "/assets/app.js", "identity", map[string]string{"Range": "bytes=0-5"})
			if status != 206 || !bytes.Equal(payload, script[:6]) {
				t.Fatal("byte range semantics changed")
			}
			status, _, payload = compare(t, before, after, "GET", "/assets/app.js", "identity", map[string]string{"If-None-Match": headers.Get("Etag")})
			if status != 304 || len(payload) != 0 {
				t.Fatal("conditional response semantics changed")
			}
		})
	}
	t.Run("denial_before_fallback", func(t *testing.T) {
		settings := staticFixture(t, "html_fallback").Serving
		settings.DenyPaths = []string{"/private/*"}
		endpoint := stockStaticProxy(t, binary, staticServingRoute("example", strings.Repeat("a", 40), settings), public)
		status, _, _ := request(t, endpoint, "GET", "/private/missing", "identity", nil)
		if status != 404 {
			t.Fatal("fallback bypassed explicit path denial")
		}
	})
}
