package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nicodes/komizo/box"
)

// The read API over a real socket.
//
// box/api_test.go covers the handler through httptest; this covers the parts
// that only exist once something is actually listening -- the socket's mode,
// the stale-socket case, and a box that has nothing to verify against.

func serveFixture(t *testing.T) (dir string, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir = t.TempDir()
	conf := box.AgentConf{
		API:         "https://api.example.com",
		ServerID:    "srv_abc123",
		Token:       "kmz_agt_whatever",
		RegistryKey: base64Key(pub),
	}
	if err := box.WriteAgentConf(filepath.Join(dir, "agent.json"), conf); err != nil {
		t.Fatal(err)
	}
	rep := box.Report{V: box.Version, At: time.Now().UTC(),
		Server: box.Server{State: "ready", OS: "Alpine Linux v3.20"}}
	if err := box.WriteReport(filepath.Join(dir, "report.json"), rep); err != nil {
		t.Fatal(err)
	}
	return dir, priv
}

// base64Key is the key as enrolment stores it: raw URL-safe base64, one line.
func base64Key(pub ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pub)
}

// startServe runs the command until the test ends and returns the socket path.
func startServe(t *testing.T, dir string) string {
	t.Helper()
	sock := filepath.Join(dir, "api.sock")
	done := make(chan error, 1)
	go func() {
		done <- runServe([]string{
			"--socket", sock,
			"--config", filepath.Join(dir, "agent.json"),
			"--report", filepath.Join(dir, "report.json"),
			"--history", filepath.Join(dir, "history.jsonl"),
		})
	}()
	t.Cleanup(func() {
		// runServe returns on SIGTERM; the test process cannot signal only
		// itself usefully, so the socket is closed instead and the goroutine
		// is left to unwind with the test binary.
		_ = os.Remove(sock)
	})

	// Wait for the socket rather than sleeping a fixed amount.
	for range 200 {
		if _, err := os.Stat(sock); err == nil {
			return sock
		}
		select {
		case err := <-done:
			t.Fatalf("serve exited before listening: %v", err)
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the socket never appeared")
	return ""
}

func socketClient(sock string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
}

func TestItServesOverTheSocket(t *testing.T) {
	dir, priv := serveFixture(t)
	sock := startServe(t, dir)

	tok, err := box.SignReadToken(priv, "srv_abc123", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "http://box/v1/report", nil)
	req.Header.Set("Authorization", "Bearer "+tok)

	res, err := socketClient(sock).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("report over the socket = %d, want 200", res.StatusCode)
	}
	var got box.ReportResponse
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Report.Server.OS != "Alpine Linux v3.20" {
		t.Errorf("report did not come through the socket: %+v", got.Report.Server)
	}
}

// Owner and group only. Anything else on the box has no business opening it --
// the proxy connects as root, which is not subject to the mode.
func TestTheSocketIsNotWorldWritable(t *testing.T) {
	dir, _ := serveFixture(t)
	sock := startServe(t, dir)

	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != socketMode {
		t.Errorf("socket mode = %04o, want %04o", perm, socketMode)
	}
}

// A socket file outlives the process that made it, so a box powered off
// mid-request has one on disk that nothing is listening to. Binding over it
// fails -- and for a path rather than a port, that is a service that will not
// start until somebody deletes a file by hand.
func TestAStaleSocketDoesNotBlockStartup(t *testing.T) {
	dir, _ := serveFixture(t)
	sock := filepath.Join(dir, "api.sock")
	if err := os.WriteFile(sock, nil, 0o660); err != nil {
		t.Fatal(err)
	}

	ln, err := listenUnix(sock)
	if err != nil {
		t.Fatalf("a stale socket stopped the listener: %v", err)
	}
	ln.Close()
}

// A box with no key can only refuse every request, so it opens nothing at all
// rather than holding a socket that answers 401 forever.
func TestABoxWithNoRegistryKeyServesNothing(t *testing.T) {
	dir := t.TempDir()
	conf := box.AgentConf{API: "https://api.example.com", ServerID: "srv_abc123", Token: "kmz_agt_x"}
	if err := box.WriteAgentConf(filepath.Join(dir, "agent.json"), conf); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "api.sock")

	if err := runServe([]string{"--socket", sock, "--config", filepath.Join(dir, "agent.json")}); err != nil {
		t.Fatalf("a keyless box should exit quietly, got %v", err)
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Error("a box with no registry key opened a socket anyway")
	}
}
