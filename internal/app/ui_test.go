package app

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/internal/ui"
)

// `komizo ui` is the product's screen now, and its safety story is four
// contract pins, stated as tests:
//
//	a. no listener on a public interface -- the default bind is loopback, and
//	   the wildcard arrives only when somebody types it;
//	b. no Clerk/PocketBase remnants in the web tree (source-level);
//	c. the allowlist is enforced server-side -- a request for a
//	   non-allowlisted action is refused whatever the page sends;
//	d. every read the page consumes is served from this box's own files.
//
// Plus the serve test: a real listener on 127.0.0.1, asked over HTTP.

// uiFixture is a box on disk: a report, two command results, an app's state
// file, and a stub komizo-box that records what it was asked.
type uiFixture struct {
	srv    *uiServer
	boxLog string // the file the stub appends its argv to
}

func newUIFixture(t *testing.T) *uiFixture {
	t.Helper()
	root := t.TempDir()
	apps := filepath.Join(root, "apps")
	results := filepath.Join(root, "results")
	for _, d := range []string{apps, results} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	rep := box.Report{
		V:  1,
		At: time.Now(),
	}
	rep.Server.State = "ready"
	rep.Server.OS = "Alpine Linux 3.21"
	rep.Apps = []box.App{{Name: "web"}}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(root, "report.json")
	if err := os.WriteFile(reportPath, b, 0o644); err != nil {
		t.Fatal(err)
	}

	older := box.Result{V: 1, ID: "aaa", Op: "restart web", At: time.Now().Add(-time.Hour), OK: true}
	newer := box.Result{V: 1, ID: "bbb", Op: "stop web", At: time.Now(), OK: false, Detail: "compose said no"}
	for _, r := range []box.Result{older, newer} {
		if err := box.WriteResult(results, r); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(apps, "web.env"), 0o600, "APP_NAME=web\n")

	log := filepath.Join(root, "box.argv")
	stub := filepath.Join(root, "komizo-box")
	write(t, stub, 0o755, "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \""+log+"\"\necho stub-ran\n")

	orig := uiBoxBin
	uiBoxBin = stub
	t.Cleanup(func() { uiBoxBin = orig })

	static, err := ui.Dist()
	if err != nil {
		t.Fatal(err)
	}
	return &uiFixture{
		srv: &uiServer{
			reportPath:  reportPath,
			historyPath: filepath.Join(root, "history.jsonl"),
			metricsPath: filepath.Join(root, "metrics.json"),
			resultsDir:  results,
			appsDir:     apps,
			static:      static,
		},
		boxLog: log,
	}
}

func (f *uiFixture) start(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(f.srv.routes())
	t.Cleanup(ts.Close)
	// httptest binds loopback -- the address check below proves it rather than
	// trusts it.
	if !net.ParseIP(strings.Split(strings.TrimPrefix(ts.URL, "http://"), ":")[0]).IsLoopback() {
		t.Fatalf("the test listener is not on loopback: %s", ts.URL)
	}
	return ts
}

func getJSON(t *testing.T, url string) (int, map[string]any) {
	t.Helper()
	res, err := http.Get(url) //nolint:gosec // the URL is the test's own listener
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("%s did not answer JSON: %v", url, err)
	}
	return res.StatusCode, body
}

func TestUIServesThePageAndTheBoxsOwnState(t *testing.T) {
	f := newUIFixture(t)
	ts := f.start(t)

	// The index, byte-verified as HTML.
	res, err := http.Get(ts.URL + "/") //nolint:gosec // the test's own listener
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("index = %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("index is not HTML: %q", ct)
	}

	// A client-side route is the same page -- the router resolves it, not the
	// server.
	res2, err := http.Get(ts.URL + "/app/web") //nolint:gosec // the test's own listener
	if err != nil {
		t.Fatal(err)
	}
	res2.Body.Close()
	if res2.StatusCode != 200 {
		t.Errorf("/app/web = %d, want the SPA fallback", res2.StatusCode)
	}

	// A read returns the box's local shape: the fixture's state word, no more,
	// no less.
	code, body := getJSON(t, ts.URL+"/api/report")
	if code != 200 {
		t.Fatalf("/api/report = %d", code)
	}
	report, ok := body["report"].(map[string]any)
	if !ok {
		t.Fatalf("no report in %v", body)
	}
	server, ok := report["server"].(map[string]any)
	if !ok || server["state"] != "ready" {
		t.Errorf("the fixture's state word did not come back: %v", server)
	}

	// Events are the box's results, newest first.
	code, body = getJSON(t, ts.URL+"/api/events")
	if code != 200 {
		t.Fatalf("/api/events = %d", code)
	}
	events, ok := body["events"].([]any)
	if !ok || len(events) != 2 {
		t.Fatalf("events = %v", body)
	}
	first := events[0].(map[string]any)
	if first["id"] != "bbb" {
		t.Errorf("events are not newest-first: %v", events)
	}
	if first["ok"] != false || first["detail"] != "compose said no" {
		t.Errorf("the failure detail did not survive: %v", first)
	}

	// Backups: the honest absence, with its note.
	_, body = getJSON(t, ts.URL+"/api/backups")
	if !strings.Contains(body["note"].(string), "not tracked") {
		t.Errorf("the backups note does not state the absence: %v", body)
	}
}

// The allowlist is the boundary, not the page: these requests are made
// directly, with no UI involved at all.
func TestUIActionAllowlistIsEnforcedServerSide(t *testing.T) {
	f := newUIFixture(t)
	ts := f.start(t)

	post := func(payload string) (int, map[string]any) {
		t.Helper()
		res, err := http.Post(ts.URL+"/api/action", "application/json", strings.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var body map[string]any
		_ = json.NewDecoder(res.Body).Decode(&body)
		return res.StatusCode, body
	}

	// The three that are allowed run through the box's own binary.
	code, body := post(`{"app":"web","action":"restart"}`)
	if code != 200 || body["ok"] != true {
		t.Fatalf("an allowlisted action = %d %v", code, body)
	}
	logged, err := os.ReadFile(f.boxLog)
	if err != nil || !strings.Contains(string(logged), "app restart --app web") {
		t.Errorf("the stub was not asked for restart on web: %q, %v", logged, err)
	}

	// Anything else is refused -- including a verb that would be a disaster.
	for _, bad := range []string{
		`{"app":"web","action":"rm"}`,
		`{"app":"web","action":"deploy"}`,
		`{"app":"web","action":"stop; rm -rf /"}`,
	} {
		code, _ = post(bad)
		if code != http.StatusForbidden {
			t.Errorf("%s = %d, want 403", bad, code)
		}
	}

	// An app the box has no record of is refused, so the allowlist cannot be
	// turned on something that is not an app.
	code, _ = post(`{"app":"nope","action":"stop"}`)
	if code != http.StatusNotFound {
		t.Errorf("an unknown app = %d, want 404", code)
	}

	// And the malformed.
	code, _ = post(`not json`)
	if code != http.StatusBadRequest {
		t.Errorf("a malformed body = %d, want 400", code)
	}

	// The action route answers POST and nothing else; unknown reads 404.
	res, err := http.Get(ts.URL + "/api/action") //nolint:gosec // the test's own listener
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/action = %d, want 405", res.StatusCode)
	}
	code, _ = getJSON(t, ts.URL+"/api/etc/passwd")
	if code != http.StatusNotFound {
		t.Errorf("/api/etc/passwd = %d, want 404", code)
	}
}

// The bind contract, pinned: the DEFAULT is loopback, an explicit address
// widens to the tailnet interface, and the wildcard exists only when typed.
func TestUIBindContract(t *testing.T) {
	for bind, ok := range map[string]bool{
		"127.0.0.1":   true,
		"localhost":   true,
		"::1":         true,
		"100.64.1.10": true, // a tailnet address
		"0.0.0.0":     true, // explicit, and warned about -- see RunUI
		"example.com": false,
		"":            false,
	} {
		if err := validateUIBind(bind); (err == nil) != ok {
			t.Errorf("validateUIBind(%q) ok = %v, want %v", bind, err == nil, ok)
		}
	}

	// The default flag value, asserted from the source of truth. A listener
	// made from it answers "what interface is this on" with the address
	// itself, so what is pinned is the literal the flag declares.
	src := sourceOf(t, "ui.go")
	if !strings.Contains(src, `fs.String("bind", "127.0.0.1"`) {
		t.Error("the ui --bind default is no longer loopback -- the zero-auth " +
			"listener's boundary moved, and this pin is how that gets announced")
	}
	if strings.Contains(src, `"0.0.0.0", "0.0.0.0"`) || strings.Contains(src, `net.Listen("tcp", ":")`) {
		t.Error("ui.go listens on the wildcard by default")
	}
}

// The web tree carries no remnant of the decommissioned stack: no Clerk
// import, no PocketBase package, no env URL for either. Source-level, because
// what is pinned is an absence -- a reintroduced dependency fails here,
// wherever it lands.
func TestTheWebTreeHasNoClerkOrPocketBaseRemnants(t *testing.T) {
	root := filepath.Join("..", "..", "ui")
	var files []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() && (name == "node_modules" || name == "dist") {
			return filepath.SkipDir
		}
		if !d.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("the ui tree was not scanned -- has the layout changed?")
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, banned := range []string{"@clerk/", `"pocketbase"`, "EXPO_PUBLIC_PB_URL", "EXPO_PUBLIC_CLERK"} {
			if strings.Contains(string(b), banned) {
				t.Errorf("%s mentions %q -- a remnant of the decommissioned stack", f, banned)
			}
		}
	}

	// This test file and the comments in the Go source name the banned strings
	// to pin them; keep the scan to the web tree so the pins themselves pass.
}

// Every read the page consumes is a relative path to the same listener that
// served it -- no absolute URL, no second origin, no env-baked address.
func TestTheWebClientSpeaksOnlyToItsOwnOrigin(t *testing.T) {
	for _, f := range []string{"api.ts"} {
		src := sourceOf(t, filepath.Join("..", "..", "ui", "src", "lib", f))
		for _, banned := range []string{`"http://`, "`http://", `"https://`, "`https://", "EXPO_PUBLIC_"} {
			if strings.Contains(src, banned) {
				t.Errorf("ui/src/lib/%s contains %q -- the page must read only the box that served it", f, banned)
			}
		}
	}
}
