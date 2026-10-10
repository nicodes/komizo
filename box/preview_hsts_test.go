package box

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Exercise the actual proxy, including an upstream that tries to disable HSTS
// and the stable site's unrouted-path response. Template text alone cannot
// establish header precedence or coverage of fallback responses.
func TestPreviewHTTPSPolicyThroughRealProxy(t *testing.T) {
	caddy, err := exec.LookPath("caddy")
	if err != nil {
		t.Fatal("install the pinned test toolchain: caddy is required")
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=0")
		_, _ = io.WriteString(w, "synthetic upstream")
	}))
	defer upstream.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	root := t.TempDir()
	knob, _ := ParsePreviewKnob("DOMAIN=preview.example.invalid\n")
	generic := PreviewRecord{App: "app", PR: 1, Project: "app-pr-1", Host: "pr-1.preview.example.invalid", Images: []string{"gate", "api"}}
	path := PreviewRecord{App: "app", PR: 74, Project: "app-pr-74", Host: "app.preview.example.invalid", BasePath: "/74", Images: []string{"gate"}}
	localize := func(site string, hosts []string, project string) string {
		localHosts := make([]string, len(hosts))
		for i, host := range hosts {
			localHosts[i] = fmt.Sprintf("http://%s:%d", host, port)
		}
		site = strings.Replace(site, "\n"+strings.Join(hosts, ", ")+" {", "\n"+strings.Join(localHosts, ", ")+" {", 1)
		site = strings.ReplaceAll(site, "/etc/caddy/routes/", filepath.ToSlash(root)+"/")
		return strings.ReplaceAll(site, project+"-gate:80", strings.TrimPrefix(upstream.URL, "http://"))
	}
	route := localize(previewPathRoute(path), nil, path.Project)
	if err := os.WriteFile(filepath.Join(root, "_preview-pr-74.app.route"), []byte(route), 0o600); err != nil {
		t.Fatal(err)
	}
	config := "{\n admin off\n persist_config off\n auto_https off\n default_bind 127.0.0.1\n}\n" +
		localize(previewRoute(generic, knob), []string{generic.Host, generic.PublicAPIHost(knob)}, generic.Project) +
		localize(previewPathSite(path, knob), []string{path.Host}, path.Project)
	file := filepath.Join(root, "Caddyfile")
	if err := os.WriteFile(file, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	cmd := exec.CommandContext(ctx, caddy, "run", "--config", file, "--adapter", "caddyfile")
	cmd.Env = []string{"XDG_DATA_HOME=" + root, "XDG_CONFIG_HOME=" + root}
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() { once.Do(func() { cancel(); _ = cmd.Wait() }) }
	t.Cleanup(stop)
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	for _, tc := range []struct {
		host, path string
		status     int
	}{
		{generic.Host, "/", 200}, {generic.PublicAPIHost(knob), "/", 200},
		{path.Host, "/74/", 200}, {path.Host, "/74", 308}, {path.Host, "/75/", 404},
	} {
		request, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", port, tc.path), nil)
		request.Host = tc.host
		var response *http.Response
		deadline := time.Now().Add(5 * time.Second)
		for {
			response, err = client.Do(request)
			if err == nil || time.Now().After(deadline) {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			stop()
			t.Fatalf("proxy startup: %v\n%s", err, output.String())
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode != tc.status || response.Header.Get("Strict-Transport-Security") != "max-age=31536000" {
			t.Fatalf("%s%s: status=%d HSTS=%q", tc.host, tc.path, response.StatusCode, response.Header.Get("Strict-Transport-Security"))
		}
		if tc.status == 200 && string(body) != "synthetic upstream" {
			t.Fatal("request did not reach the synthetic upstream")
		}
	}
}
