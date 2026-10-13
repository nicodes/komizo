package box

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func metadataClient(t *testing.T, handler http.HandlerFunc) *http.Client {
	t.Helper()
	s := httptest.NewServer(handler)
	t.Cleanup(s.Close)
	address := strings.TrimPrefix(s.URL, "http://")
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("redirect refused")
	}}
}

func TestNativeReportReadsFreshStoppedHealthyAndUncheckedMetadataWithoutCLI(t *testing.T) {
	f := newFakeBox(t)
	f.write("/var/lib/komizo/apps/blog.env", "APP_DIR=/srv/blog\n")
	f.write("/srv/blog/.env", "APP_VERSION="+strings.Repeat("a", 40)+"\n")
	ids := []string{strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)}
	pid := 123
	client := metadataClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Host != "docker" {
			t.Errorf("unexpected request: %s %s", r.Method, r.Host)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/version":
			json.NewEncoder(w).Encode(map[string]string{"Version": "29.1.3", "GitCommit": "123abc", "ApiVersion": "1.53", "MinAPIVersion": "1.44"})
		case "/v1.45/containers/json":
			if r.URL.RawQuery != "all=1" {
				t.Error("stopped containers were excluded")
			}
			rows := []map[string]any{}
			for i, id := range ids {
				state := "running"
				if i == 2 {
					state = "exited"
				}
				rows = append(rows, map[string]any{"Id": id, "Names": []string{"/blog-" + state + id[:1]}, "State": state, "Status": "Up", "Image": "image", "Labels": map[string]string{"com.docker.compose.service": id[:1], "com.docker.compose.project.working_dir": "/srv/blog"}})
			}
			json.NewEncoder(w).Encode(rows)
		case "/v1.45/networks/edge":
			json.NewEncoder(w).Encode(map[string]any{"Driver": "bridge", "IPAM": map[string]any{"Config": []map[string]string{{"Subnet": "172.22.0.0/16"}}}})
		default:
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1.45/containers/"), "/json")
			state := map[string]any{"StartedAt": "2026-10-13T00:00:00Z", "FinishedAt": "0001-01-01T00:00:00Z", "ExitCode": 0, "Pid": pid}
			state["Status"] = "running"
			if id == ids[2] {
				state["Status"] = "exited"
			}
			if id == ids[0] {
				state["Health"] = map[string]string{"Status": "healthy"}
			}
			json.NewEncoder(w).Encode(map[string]any{"Id": id, "State": state, "Config": map[string]any{"Env": []string{"PRIVATE_KEY=never-serialize-this"}}, "NetworkSettings": map[string]any{"Networks": map[string]any{"edge": map[string]any{"Aliases": []string{id[:1]}}}}, "Mounts": []map[string]string{{"Type": "volume", "Name": "blog-data", "Source": "/var/lib/docker/volumes/blog-data/_data"}, {"Type": "bind", "Source": "/secret"}}})
		}
	})
	read := func() Report {
		p := &Probe{Root: f.root, engine: newDockerEngine(context.Background(), client), Docker: func(context.Context, ...string) (string, error) {
			t.Fatal("native reading invoked the CLI")
			return "", nil
		}}
		return p.Report(context.Background())
	}
	r := read()
	if !r.Server.Ready() || len(r.Apps) != 1 || len(r.Apps[0].Containers) != 3 || r.Network == nil || r.Network.Subnet != "172.22.0.0/16" {
		t.Fatalf("lost native metadata: %+v", r)
	}
	data, _ := json.Marshal(r)
	if bytes.Contains(data, []byte("never-serialize-this")) || bytes.Contains(data, []byte("PRIVATE_KEY")) {
		t.Fatal("engine environment leaked into report")
	}
	inv := newDockerEngine(context.Background(), client).inventory(context.Background())
	if inv.byID[ids[0]].health != "healthy" || inv.byID[ids[1]].health != "" || inv.byID[ids[2]].state != "exited" || inv.byID[ids[0]].pid != pid || len(inv.byID[ids[0]].mounts) != 1 {
		t.Fatalf("invented or discarded metadata: %+v", inv.byID)
	}
	pid = 456
	inv = newDockerEngine(context.Background(), client).inventory(context.Background())
	if inv.byID[ids[0]].pid != 456 {
		t.Fatal("later reading reused stale inspection")
	}
}

func TestInventoryFailureIsExplicitAndDoesNotInventSuccessfulOneShot(t *testing.T) {
	f := newFakeBox(t)
	f.write("/var/lib/komizo/apps/blog.env", "APP_DIR=/srv/blog\n")
	f.write("/srv/blog/compose.yml", `{"services":{"init":{"restart":"no"}}}`)
	id := strings.Repeat("a", 64)
	for _, failure := range []string{"list", "inspect", "incomplete"} {
		t.Run(failure, func(t *testing.T) {
			client := metadataClient(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/version":
					json.NewEncoder(w).Encode(map[string]string{"Version": "29.5.3", "ApiVersion": "1.53", "MinAPIVersion": "1.44"})
				case "/v1.45/containers/json":
					if failure == "list" {
						w.WriteHeader(503)
						return
					}
					json.NewEncoder(w).Encode([]map[string]any{{"Id": id, "Names": []string{"/blog-init"}, "State": "exited", "Labels": map[string]string{"com.docker.compose.service": "init", "com.docker.compose.project.working_dir": "/srv/blog"}}})
				default:
					if failure == "inspect" {
						w.WriteHeader(503)
						return
					}
					json.NewEncoder(w).Encode(map[string]any{"Id": id})
				}
			})
			p := &Probe{Root: f.root, engine: newDockerEngine(context.Background(), client)}
			r := p.Report(context.Background())
			if r.Inventory == nil || r.Inventory.Status == "current" || r.Apps[0].RuntimeState != "unknown" {
				t.Fatalf("failure became success: %+v", r)
			}
			found := false
			for _, problem := range r.Problems {
				if problem.Kind == "observation_incomplete" {
					found = true
				}
			}
			if !found {
				t.Fatal("incomplete inventory was silent")
			}
		})
	}
}

func TestMetadataTransportBoundsCancellationRedirectsAndPrivateErrors(t *testing.T) {
	client := metadataClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/large":
			w.Write(bytes.Repeat([]byte("private-token"), 100))
		case "/invalid":
			w.Write([]byte("private-token invalid JSON"))
		case "/refused":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("private-token"))
		case "/redirect":
			http.Redirect(w, r, "/unexpected", http.StatusTemporaryRedirect)
		case "/stall":
			<-r.Context().Done()
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
		}
	})
	for _, path := range []string{"/large", "/invalid", "/refused", "/redirect", "/stall"} {
		e := &dockerEngine{client: client, remaining: 1024}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		err := e.read(ctx, path, &map[string]any{}, 64)
		cancel()
		if err == nil || strings.Contains(err.Error(), "private-token") {
			t.Fatalf("unbounded or private failure at %s: %v", path, err)
		}
	}
	e := &dockerEngine{client: client, remaining: 0}
	if e.read(context.Background(), "/unexpected", &map[string]any{}, 64) == nil {
		t.Fatal("aggregate byte budget was bypassed")
	}
	for _, name := range []string{"../containers/json", "..", "a/b", "edge?all=1"} {
		if _, err := e.network(context.Background(), name); err == nil {
			t.Fatalf("network traversal accepted: %q", name)
		}
	}
}

func TestEngineCompatibilityAndContextSelection(t *testing.T) {
	for _, row := range []struct {
		min, max  string
		supported bool
	}{{"1.44", "1.53", true}, {"1.24", "1.45", true}, {"1.46", "1.53", false}, {"1.24", "1.43", false}, {"", "1.53", false}, {"1.44", "invalid", false}} {
		if apiContains(row.min, row.max, reportDockerAPI) != row.supported {
			t.Fatalf("API interval %q..%q", row.min, row.max)
		}
	}
	p := filepath.Join(t.TempDir(), "config.json")
	if !defaultDockerContext(p) {
		t.Fatal("absent context configuration blocked local API")
	}
	for _, row := range []struct {
		body  string
		local bool
	}{{`{}`, true}, {`{"currentContext":"default","auths":{"registry":{"auth":"private-token"}}}`, true}, {`{"currentContext":"remote"}`, false}, {`invalid`, false}} {
		if err := os.WriteFile(p, []byte(row.body), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := defaultDockerContext(p); got != row.local {
			t.Fatalf("context selection %q: %v", row.body, got)
		}
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", p); err != nil {
		t.Fatal(err)
	}
	if defaultDockerContext(p) {
		t.Fatal("symlink accepted as default context configuration")
	}
	if (&Probe{Root: t.TempDir()}).localEngineEligible() {
		t.Fatal("fixture filesystem selected real daemon")
	}
}

func TestNativeProtocolFailureDoesNotRetryThroughCLI(t *testing.T) {
	f := newFakeBox(t)
	client := metadataClient(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	e := newDockerEngine(context.Background(), client)
	if e == nil || e.available {
		t.Fatal("unavailable daemon was treated as compatible/ready")
	}
	p := &Probe{Root: f.root, engine: e, Docker: func(context.Context, ...string) (string, error) {
		t.Fatal("failed bounded request retried through CLI")
		return "", nil
	}}
	if r := p.Report(context.Background()); r.Server.State != "docker-stopped" || len(r.Apps) != 0 {
		t.Fatalf("unavailable metadata became a healthy reading: %+v", r)
	}
}

func TestIncompatibleDaemonRetainsCLICompatibility(t *testing.T) {
	client := metadataClient(t, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"Version": "future", "ApiVersion": "1.60", "MinAPIVersion": "1.50"})
	})
	if e := newDockerEngine(context.Background(), client); e != nil {
		t.Fatal("unsupported daemon lost existing CLI compatibility")
	}
}
