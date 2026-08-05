package box

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func logsFixture(t *testing.T) (APIConfig, string, string) {
	t.Helper()
	regPub, regPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := APIConfig{ServerID: "srv_mine", RegistryKey: regPub, LogsDir: dir}
	tok, err := SignReadToken(regPriv, cfg.ServerID, time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return cfg, dir, tok
}

// A NAME IS NEVER JOINED TO A PATH UNCHECKED.
//
// It arrives in a query string on a route reachable through the box's proxy,
// which is the internet.
func TestALogNameThatIsAPathIsRefused(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"", "..", "a/b", "web.log", "../../etc/passwd", strings.Repeat("x", 101)} {
		if _, err := LogPath(dir, bad); err == nil {
			t.Errorf("%q was accepted as an app", bad)
		}
	}
	// The proxy is the one underscore name that exists; the rest of that
	// namespace is komizo's own and holds no logs.
	if _, err := LogPath(dir, ProxyLogName); err != nil {
		t.Errorf("the proxy's own log was refused: %v", err)
	}
	if _, err := LogPath(dir, "_secret"); err == nil {
		t.Error("a reserved name was accepted")
	}
	if _, err := LogPath(dir, "web"); err != nil {
		t.Errorf("an ordinary app was refused: %v", err)
	}
}

// A file is bounded, and trimmed from the FRONT.
//
// The end is the recent part, which is what anybody opening a log wants -- and
// it is cut at a line boundary so the first line shown is a line rather than the
// tail of one.
func TestALogIsBoundedAndKeepsTheRecentEnd(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	for i := 0; b.Len() < LogsMax*2; i++ {
		b.WriteString("line ")
		b.WriteString(strings.Repeat("x", 60))
		b.WriteString("\n")
	}
	b.WriteString("THE LAST LINE\n")

	if err := WriteLog(dir, "web", []byte(b.String())); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "web.log"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > LogsMax {
		t.Errorf("%d bytes, want at most %d", fi.Size(), LogsMax)
	}
	got, err := ReadLog(dir, "web", 5)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "THE LAST LINE") {
		t.Error("trimming kept the start rather than the recent end")
	}
	// And what survives starts at a line boundary.
	body, err := os.ReadFile(filepath.Join(dir, "web.log"))
	if err != nil {
		t.Fatal(err)
	}
	if first, _, _ := strings.Cut(string(body), "\n"); !strings.HasPrefix(first, "line ") {
		t.Errorf("the first line is a fragment: %q", first)
	}
	// 0640: root writes it, the serving account reads it, nothing else does.
	if perm := fi.Mode().Perm(); perm != 0o640 {
		t.Errorf("a log is %04o, want 0640", perm)
	}
}

// The route needs a token like every other route here, and bounds the tail.
func TestServingALog(t *testing.T) {
	cfg, dir, tok := logsFixture(t)
	if err := WriteLog(dir, "web", []byte("one\ntwo\nthree\n")); err != nil {
		t.Fatal(err)
	}
	get := func(q, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/v1/logs?"+q, nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		Handler(cfg).ServeHTTP(w, r)
		return w
	}

	if w := get("app=web", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("no token = %d, want 401", w.Code)
	}
	w := get("app=web&tail=2", tok)
	if w.Code != http.StatusOK {
		t.Fatalf("= %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "three") || strings.Contains(w.Body.String(), "one") {
		t.Errorf("tail=2 returned %q, want the last two lines", w.Body.String())
	}
	for _, bad := range []string{"app=web&tail=0", "app=web&tail=99999", "app=web&tail=x", "app=../etc"} {
		if w := get(bad, tok); w.Code == http.StatusOK {
			t.Errorf("%q was served", bad)
		}
	}
	// An app that has never started has nothing to say, and that is not an
	// error about the caller.
	if w := get("app=neverstarted", tok); w.Code != http.StatusNotFound {
		t.Errorf("an uncollected app = %d, want 404", w.Code)
	}
}

// A removed app's log goes with it.
func TestLogsOfRemovedAppsAreSweptAndTheProxyIsKept(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"web", "gone", ProxyLogName} {
		if err := WriteLog(dir, n, []byte("x\n")); err != nil {
			t.Fatal(err)
		}
	}
	if err := PruneLogs(dir, []string{"web"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLog(dir, "gone", 1); err == nil {
		t.Error("an app that no longer exists kept its log")
	}
	for _, n := range []string{"web", ProxyLogName} {
		if _, err := ReadLog(dir, n, 1); err != nil {
			t.Errorf("%s lost its log: %v", n, err)
		}
	}
}
