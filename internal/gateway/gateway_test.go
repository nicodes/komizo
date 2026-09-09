package gateway

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func config(id, target string) Config {
	return Config{App: "app", Generation: id, Routes: []Route{{"api", []string{"api.test"}, target}}}
}

func TestAtomicSwitchAndRetainedRequestAccounting(t *testing.T) {
	entered, finish := make(chan struct{}), make(chan struct{})
	old := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-finish
		io.WriteString(w, "old-complete")
	}))
	defer old.Close()
	newServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "new") }))
	defer newServer.Close()
	g, err := New(config("old", old.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan string, 1)
	go func() {
		recorder := httptest.NewRecorder()
		g.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://api.test/", nil))
		result <- recorder.Body.String()
	}()
	<-entered
	next := config("new", newServer.URL)
	next.Parent = "old"
	if err := g.Swap(next); err != nil {
		close(finish)
		t.Fatal(err)
	}
	status, err := g.Status("old")
	if err != nil || status.Active || status.Requests != 1 {
		close(finish)
		t.Fatalf("old accounting lost on switch: %+v, %v", status, err)
	}
	if err := g.Forget("old"); err == nil {
		close(finish)
		t.Fatal("forgot a generation with admitted requests")
	}
	for range 100 {
		recorder := httptest.NewRecorder()
		g.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://api.test/", nil))
		if recorder.Body.String() != "new" {
			close(finish)
			t.Fatal("late request admitted to old generation")
		}
	}
	close(finish)
	if got := <-result; got != "old-complete" {
		t.Fatalf("old request interrupted: %q", got)
	}
	status, err = g.Status("old")
	if err != nil || status.Active || status.Requests != 0 {
		t.Fatalf("completed request still counted: %+v, %v", status, err)
	}
	if err := g.Forget("old"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Status("old"); err == nil {
		t.Fatal("unknown generation incorrectly proves drain completion")
	}
	if err := g.Forget("new"); err == nil {
		t.Fatal("active generation discarded")
	}
}

func TestConcurrentSwapsAndRequests(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer backend.Close()
	g, err := New(config("initial", backend.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				w := httptest.NewRecorder()
				g.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://api.test/", nil))
				if w.Code != http.StatusOK || w.Body.String() != "ok" {
					t.Errorf("request failed during swap: %d", w.Code)
				}
			}
		})
	}
	for i := range 30 {
		before, _ := g.Current()
		next := config(fmt.Sprintf("r%d", i), backend.URL)
		next.Parent = before.Generation
		if err := g.Swap(next); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	for i := range 29 {
		if err := g.Forget(fmt.Sprintf("r%d", i)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGatewayRoutesAndAdminAreSeparate(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Host+" "+r.URL.RequestURI())
	}))
	defer backend.Close()
	g, err := New(config("initial", backend.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://api.test/routes?x=1", nil))
	if w.Body.String() != "api.test /routes?x=1" {
		t.Fatalf("traffic path became admin or changed request: %q", w.Body.String())
	}
	w = httptest.NewRecorder()
	g.Admin().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://private/routes", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"generation":"initial"`) {
		t.Fatal("admin did not expose private route state")
	}
	w = httptest.NewRecorder()
	g.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://unclaimed.test/", nil))
	if w.Code != http.StatusNotFound {
		t.Fatal("unclaimed hostname routed")
	}
	if err := g.Swap(config("initial", "http://different:8080")); err == nil {
		t.Fatal("generation reused with different content")
	}
	if err := g.Swap(config("initial", backend.URL)); err != nil {
		t.Fatal("identical desired generation was not idempotent")
	}
}

func TestWebSocketRemainsCountedThroughSwitch(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		rw.Flush()
		io.Copy(conn, rw)
	}))
	defer backend.Close()
	g, err := New(config("old", backend.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(g)
	defer front.Close()
	request, _ := http.NewRequest(http.MethodGet, front.URL, nil)
	request.Host = "api.test"
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	response, err := front.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade failed: %d", response.StatusCode)
	}
	next := config("new", backend.URL)
	next.Parent = "old"
	if err := g.Swap(next); err != nil {
		t.Fatal(err)
	}
	status, _ := g.Status("old")
	if status.Active || status.Requests != 1 {
		t.Fatalf("live upgrade not counted: %+v", status)
	}
	duplex := response.Body.(io.ReadWriteCloser)
	if _, err := io.WriteString(duplex, "still-open\n"); err != nil {
		t.Fatal(err)
	}
	if value, err := bufio.NewReader(duplex).ReadString('\n'); err != nil || value != "still-open\n" {
		t.Fatalf("upgrade disconnected on swap: %q, %v", value, err)
	}
}

func TestConfigValidationAndIsolation(t *testing.T) {
	valid := config("initial", "http://api:8080")
	g, err := New(valid, nil)
	if err != nil {
		t.Fatal(err)
	}
	valid.Routes[0].Hosts[0] = "mutated.test"
	current, _ := g.Current()
	if current.Routes[0].Hosts[0] != "api.test" {
		t.Fatal("caller mutated live routes")
	}
	for _, input := range []string{
		`null`, `{}`, `{"generation":"x","routes":[]} {}`,
		`{"generation":"x","routes":[],"unknown":true}`,
		`{"generation":"x","routes":[{"service":"api","hosts":["api.test"],"target":"http://user:secret@api"}]}`,
	} {
		if _, err := Decode(strings.NewReader(input)); err == nil {
			t.Fatalf("invalid config accepted: %s", input)
		}
	}
}

func TestGatewayRejectsStaleParentAndCrossApp(t *testing.T) {
	g, err := New(config("initial", "http://backend:8080"), nil)
	if err != nil {
		t.Fatal(err)
	}
	stale := config("next", "http://new:8080")
	stale.Parent = "wrong"
	if err := g.Swap(stale); err == nil {
		t.Fatal("stale writer replaced current routing")
	}
	stale.Parent = "initial"
	stale.App = "other"
	if err := g.Swap(stale); err == nil {
		t.Fatal("gateway application scope changed")
	}
}

func TestForwardingTrustIsExplicit(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Header.Get("X-Forwarded-For")+"|"+r.Header.Get("X-Forwarded-Proto"))
	}))
	defer backend.Close()
	cfg := config("initial", backend.URL)
	cfg.TrustedProxies = []string{"192.0.2.1/32"}
	g, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ remote, want string }{{"192.0.2.1:1234", "203.0.113.1|https"}, {"198.51.100.1:1234", "198.51.100.1|http"}} {
		request := httptest.NewRequest(http.MethodGet, "http://api.test/", nil)
		request.RemoteAddr = tc.remote
		request.Header.Set("X-Forwarded-For", "203.0.113.1")
		request.Header.Set("X-Forwarded-Proto", "https")
		response := httptest.NewRecorder()
		g.ServeHTTP(response, request)
		if response.Body.String() != tc.want {
			t.Fatalf("forwarding trust: got %q want %q", response.Body.String(), tc.want)
		}
	}
}
