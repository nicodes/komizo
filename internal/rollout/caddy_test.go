package rollout

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCaddyReconcilesLostResponseAndSkipsNoOp(t *testing.T) {
	var mu sync.Mutex
	config := `{}`
	var loads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/config/":
			io.WriteString(w, config)
		case "/load":
			body, _ := io.ReadAll(r.Body)
			config = string(body)
			loads.Add(1)
			// Configuration committed, but its response is lost. Treating this
			// as rollback permission would route cleanup at the wrong instance.
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			conn.Close()
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	router, err := NewCaddy(server.URL, nil, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, wanted := range []string{`{"apps":{"http":{}}}`, "{ \"apps\": { \"http\": {} } }"} {
		if err := router.Apply(ctx, []byte(wanted)); err != nil {
			t.Fatal(err)
		}
	}
	if loads.Load() != 1 {
		t.Fatalf("ambiguous success/no-op caused %d loads, want 1", loads.Load())
	}
}

func TestCaddyRejectsWithoutLeakingDiagnostics(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/config/" {
			io.WriteString(w, `{}`)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "private-admin-diagnostic")
	}))
	defer server.Close()
	router, err := NewCaddy(server.URL, nil, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = router.Apply(ctx, []byte(`{"private-config":"private-value"}`))
	if err == nil || strings.Contains(err.Error(), "private-") {
		t.Fatalf("unsafe rejection: %v", err)
	}
}

func TestCaddyDeadlineBoundsUnconfirmedState(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/config/" {
			io.WriteString(w, `{}`)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	router, err := NewCaddy(server.URL, nil, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := router.Apply(ctx, []byte(`{"apps":{}}`)); err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("unconfirmed desired state: %v", err)
	}
	if err := router.Apply(context.Background(), []byte(`{}`)); err == nil {
		t.Fatal("unbounded update accepted")
	}
}

func TestCaddyWaitingForSerializationIsCancellable(t *testing.T) {
	router, err := NewCaddy("http://127.0.0.1:1", nil, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	router.lock <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := router.Apply(ctx, []byte(`{}`)); err == nil || !strings.Contains(err.Error(), "serialization") {
		t.Fatalf("lock wait was not cancellable: %v", err)
	}
}

func TestCaddyRefusesAdminChangeBeforeLoading(t *testing.T) {
	var loads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/config/" {
			io.WriteString(w, `{"admin":{"listen":":2019"}}`)
			return
		}
		loads.Add(1)
	}))
	defer server.Close()
	router, err := NewCaddy(server.URL, nil, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := router.Apply(ctx, []byte(`{"apps":{}}`)); err == nil || loads.Load() != 0 {
		t.Fatalf("administrative change reached load: %v, %d", err, loads.Load())
	}
}

func TestCaddyDoesNotFollowRedirects(t *testing.T) {
	var reached atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
	}))
	defer other.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	router, err := NewCaddy(server.URL, nil, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := router.Apply(ctx, []byte(`{}`)); err == nil || reached.Load() != 0 {
		t.Fatalf("redirect followed or accepted: %v, requests=%d", err, reached.Load())
	}
}

func TestCaddyValidatesInputBeforeNetworking(t *testing.T) {
	for _, endpoint := range []string{"", "http://user:password@localhost", "file:///tmp/admin", "http://localhost/config", "http://localhost/?secret=value"} {
		if _, err := NewCaddy(endpoint, nil, time.Millisecond); err == nil {
			t.Fatal("invalid endpoint accepted")
		}
	}
	if _, err := NewCaddy("http://localhost", nil, 0); err == nil {
		t.Fatal("zero polling interval accepted")
	}
	router, err := NewCaddy("http://127.0.0.1:1", nil, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, config := range []string{"null", "[]", "{}{}", "invalid", strings.Repeat(" ", maxConfigBytes+1)} {
		if err := router.Apply(ctx, []byte(config)); err == nil || !strings.Contains(err.Error(), "document") {
			t.Fatalf("invalid config: %v", err)
		}
	}
}
