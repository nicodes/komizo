package box

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeCollectionAttributesServicesExcludesProxyAndPreservesFailedTail(t *testing.T) {
	f := newFakeBox(t)
	f.write("/var/lib/komizo/apps/blog.env", "APP_DIR=/srv/blog\n")
	id := strings.Repeat("a", 64)
	failed := false
	reads := 0
	client := metadataClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/version":
			json.NewEncoder(w).Encode(map[string]string{"Version": "29.5.3", "ApiVersion": "1.53", "MinAPIVersion": "1.44"})
		case "/v1.45/containers/json":
			json.NewEncoder(w).Encode([]map[string]any{{"Id": id, "Names": []string{"/blog-web-1"}, "State": "running", "Labels": map[string]string{"com.docker.compose.service": "web-1", "com.docker.compose.project.working_dir": "/srv/blog"}}})
		case "/v1.45/containers/" + id + "/json":
			json.NewEncoder(w).Encode(map[string]any{"Id": id, "State": map[string]any{"Status": "running", "Pid": 123, "ExitCode": 0}})
		case "/v1.45/containers/" + id + "/logs":
			reads++
			if failed {
				w.WriteHeader(503)
				return
			}
			if r.URL.RawQuery != "stdout=1&stderr=1&tail=500" {
				t.Error("unbounded log request")
			}
			body := []byte("actual\tmessage\n")
			header := make([]byte, 8)
			header[0] = 1
			binary.BigEndian.PutUint32(header[4:], uint32(len(body)))
			w.Write(header)
			w.Write(body)
		default:
			t.Errorf("foreign/proxy endpoint: %s", r.URL.Path)
			w.WriteHeader(404)
		}
	})
	dir := filepath.Join(f.root, "logs")
	collectEngineLogs(context.Background(), f.probe(), newDockerEngine(context.Background(), client), dir)
	body, err := os.ReadFile(filepath.Join(dir, "blog.log"))
	if err != nil || string(body) != "web-1\tactual\tmessage\n" {
		t.Fatalf("lost attributed log %q: %v", body, err)
	}
	failed = true
	collectEngineLogs(context.Background(), f.probe(), newDockerEngine(context.Background(), client), dir)
	later, _ := os.ReadFile(filepath.Join(dir, "blog.log"))
	if string(later) != string(body) || reads != 2 {
		t.Fatal("failed metadata erased prior tail")
	}
	f.write("/var/lib/komizo/apps/blog.env", "APP_DIR=/srv/blog\nSTOPPED=1\n")
	collectEngineLogs(context.Background(), f.probe(), newDockerEngine(context.Background(), client), dir)
	if reads != 2 {
		t.Fatal("deliberately stopped app was polled")
	}
}

func TestNativeLogFramesAreBoundedAndTTYIsExplicit(t *testing.T) {
	body := []byte("raw tty\n")
	client := metadataClient(t, func(w http.ResponseWriter, r *http.Request) { w.Write(body) })
	e := &dockerEngine{client: client, remaining: 1 << 20}
	c := &containerInfo{id: strings.Repeat("a", 64), tty: true}
	got, err := e.logs(context.Background(), c)
	if err != nil || string(got) != string(body) {
		t.Fatal("TTY lost", err)
	}
	c.tty = false
	for _, bad := range [][]byte{[]byte("bad"), {1, 0, 0, 0, 255, 255, 255, 255}, make([]byte, LogsMax+4001)} {
		body = bad
		e.remaining = 1 << 20
		if _, err := e.logs(context.Background(), c); err == nil {
			t.Fatal("invalid/oversized frame accepted")
		}
	}
	e.remaining = 0
	if _, err := e.logs(context.Background(), c); err == nil {
		t.Fatal("aggregate reading limit ignored")
	}
}
