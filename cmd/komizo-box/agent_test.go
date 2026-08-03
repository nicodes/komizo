package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nicodes/komizo/box"
)

// The agent's interesting behaviour is all in what it does when things go
// wrong, so that is what these are about: a refused credential, an unreachable
// service, and a report it has already sent.

// service is a fake komizo, recording what reached it.
type service struct {
	*httptest.Server
	posts  atomic.Int64
	status atomic.Int64
	last   atomic.Pointer[string]
	auth   atomic.Pointer[string]
}

func newService(t *testing.T) *service {
	t.Helper()
	s := &service{}
	s.status.Store(http.StatusNoContent)
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 1<<20)
		n, _ := r.Body.Read(body)
		got := string(body[:n])
		s.last.Store(&got)
		a := r.Header.Get("Authorization")
		s.auth.Store(&a)
		s.posts.Add(1)
		w.WriteHeader(int(s.status.Load()))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *service) conf() box.AgentConf {
	return box.AgentConf{API: s.URL, ServerID: "srv1", Token: "kmz_agt_test"}
}

// writeReport puts a report where the agent looks for it.
func writeReport(t *testing.T, dir string, r box.Report) string {
	t.Helper()
	p := filepath.Join(dir, "report.json")
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func aReport() box.Report {
	return box.Report{
		V: box.Version, At: time.Now().UTC(),
		Server: box.Server{State: "ready", OS: "Alpine Linux v3.20"},
	}
}

// The report is posted VERBATIM. It is root's document and the agent is a
// courier -- re-serialising it would let a bug here change what a server said
// about itself, which is the one thing this process must not be able to do.
func TestTheReportIsPostedByteForByte(t *testing.T) {
	svc := newService(t)
	dir := t.TempDir()
	// A field this binary's Report type does not know about, as a box running a
	// newer agent would send.
	raw := `{"v":1,"at":"2026-08-03T12:00:00Z","server":{"state":"ready"},"something_new":42}` + "\n"
	p := filepath.Join(dir, "report.json")
	if err := os.WriteFile(p, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := postReport(context.Background(), svc.Client(), svc.conf(), p); err != nil {
		t.Fatal(err)
	}
	if got := *svc.last.Load(); got != raw {
		t.Errorf("posted body was rewritten:\n got %q\nwant %q", got, raw)
	}
	if got := *svc.auth.Load(); got != "Bearer kmz_agt_test" {
		t.Errorf("authorization = %q", got)
	}
}

// A rejected credential is not transient. An agent that retries one turns a
// removed server into a machine quietly hammering an endpoint forever.
func TestARefusedCredentialIsNotRetried(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		svc := newService(t)
		svc.status.Store(int64(code))
		p := writeReport(t, t.TempDir(), aReport())

		err := postReport(context.Background(), svc.Client(), svc.conf(), p)
		if !errors.Is(err, errRevoked) {
			t.Errorf("%d gave %v, want errRevoked", code, err)
		}
	}
}

// Everything else is worth trying again -- a service being restarted, a
// network that came back.
func TestOtherFailuresAreOrdinaryErrors(t *testing.T) {
	svc := newService(t)
	svc.status.Store(http.StatusBadGateway)
	p := writeReport(t, t.TempDir(), aReport())

	err := postReport(context.Background(), svc.Client(), svc.conf(), p)
	if err == nil || errors.Is(err, errRevoked) {
		t.Errorf("502 gave %v, want a retryable error", err)
	}
}

// A box that has never enrolled is not broken. komizo works entirely without
// the service, so the agent says so once and exits rather than looping.
func TestAnUnenrolledBoxExitsCleanly(t *testing.T) {
	dir := t.TempDir()
	err := runAgent([]string{
		"--config", filepath.Join(dir, "nothing.json"),
		"--report", filepath.Join(dir, "report.json"),
	})
	if err != nil {
		t.Errorf("an unenrolled box should exit cleanly, got %v", err)
	}
}

// The loop posts a report once and does not post it again until root writes a
// new one. Without that it would resend the same document every few seconds.
func TestAReportIsSentOnceUntilItChanges(t *testing.T) {
	svc := newService(t)
	dir := t.TempDir()
	conf := svc.conf()
	if err := box.WriteAgentConf(filepath.Join(dir, "agent.json"), conf); err != nil {
		t.Fatal(err)
	}
	report := writeReport(t, dir, aReport())

	// Driven directly, with its own context and a fast interval. Signalling the
	// process would take the test binary with it.
	const watch = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- agentLoop(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)),
			svc.Client(), conf, report, watch)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the agent did not stop when its context was cancelled")
		}
	})

	waitFor(t, func() bool { return svc.posts.Load() == 1 }, "the first report to be posted")

	// Nothing changed. Many watch intervals later it must still be one.
	time.Sleep(20 * watch)
	if n := svc.posts.Load(); n != 1 {
		t.Fatalf("posts = %d after no change, want 1", n)
	}

	// Root writes a new one.
	r := aReport()
	r.Server.OS = "changed"
	writeReport(t, dir, r)
	waitFor(t, func() bool { return svc.posts.Load() == 2 }, "the new report to be posted")
	if got := *svc.last.Load(); !strings.Contains(got, "changed") {
		t.Errorf("the second post was not the new report: %q", got)
	}
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
