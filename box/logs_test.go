package box

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func logsFixture(t *testing.T) (APIConfig, string, string, ed25519.PrivateKey) {
	t.Helper()
	regPub, regPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	devPub, devPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := APIConfig{ServerID: "srv_mine", RegistryKey: regPub,
		OperatorKeys: []ed25519.PublicKey{devPub}, LogsDir: dir}
	tok, err := SignReadToken(regPriv, cfg.ServerID, time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return cfg, dir, tok, devPriv
}

// ask posts a signed logs.read, which is what §5 requires of a log.
func ask(t *testing.T, cfg APIConfig, tok string, dev ed25519.PrivateKey, args map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	env, err := SignCommand(dev, Command{Srv: cfg.ServerID,
		Exp: time.Now().Add(time.Minute).Unix(), Op: OpLogsRead, Args: args})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(body))
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	w := httptest.NewRecorder()
	Handler(cfg).ServeHTTP(w, r)
	return w
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
	// THE PROXY IS NOT SERVED HERE. Caddy's error logger puts full requests --
	// client IP, URI, query string -- on stdout, so collecting it would hand
	// them to the account that talks to the internet.
	for _, reserved := range []string{"_proxy", "_secret", "_"} {
		if _, err := LogPath(dir, reserved); err == nil {
			t.Errorf("%q was accepted", reserved)
		}
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

// BOTH, NOT EITHER — and for logs the signature is the half §5 insists on.
//
// A read token names a server and an expiry and no user, so the ownership check
// is the service's to make: whoever holds its signing key could mint one for any
// box. §5 refuses to put the most sensitive bytes on the machine behind that
// same single environment variable.
func TestALogNeedsATokenAndASignature(t *testing.T) {
	cfg, dir, tok, dev := logsFixture(t)
	if err := WriteLog(dir, "web", []byte("one\ntwo\nthree\n")); err != nil {
		t.Fatal(err)
	}
	args := map[string]string{"app": "web"}

	if w := ask(t, cfg, "", dev, args); w.Code != http.StatusUnauthorized {
		t.Errorf("no token = %d, want 401", w.Code)
	}
	// A valid token and a key this box does not trust: the door opens, the
	// answer does not.
	_, stranger, _ := ed25519.GenerateKey(nil)
	if w := ask(t, cfg, tok, stranger, args); w.Code != http.StatusForbidden {
		t.Errorf("an untrusted device = %d, want 403", w.Code)
	}
	// And a signed request for a DIFFERENT box is refused here too.
	other := cfg
	other.ServerID = "srv_theirs"
	env, err := SignCommand(dev, Command{Srv: "srv_theirs",
		Exp: time.Now().Add(time.Minute).Unix(), Op: OpLogsRead, Args: args})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(env)
	r := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	Handler(cfg).ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("a request for another box = %d, want 403", w.Code)
	}

	if w := ask(t, cfg, tok, dev, args); w.Code != http.StatusOK {
		t.Fatalf("a signed request with a good token = %d", w.Code)
	}
}

// An op that is not logs.read cannot be spent here.
func TestALogRouteRefusesAnotherOp(t *testing.T) {
	cfg, dir, tok, dev := logsFixture(t)
	if err := WriteLog(dir, "web", []byte("x\n")); err != nil {
		t.Fatal(err)
	}
	env, err := SignCommand(dev, Command{Srv: cfg.ServerID,
		Exp: time.Now().Add(time.Minute).Unix(), Op: OpAppStop,
		Args: map[string]string{"app": "web"}})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(env)
	r := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	Handler(cfg).ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("a stop signed for this box read a log: %d", w.Code)
	}
}

// The document states its schema, the default tail is the default, and every
// refusal is the status it should be.
func TestTheLogResponseAndItsRefusals(t *testing.T) {
	cfg, dir, tok, dev := logsFixture(t)
	if err := WriteLog(dir, "web", []byte("one\ntwo\nthree\n")); err != nil {
		t.Fatal(err)
	}

	// Decoded rather than grepped, so the schema and the app name are checked
	// rather than merely present somewhere in the body.
	w := ask(t, cfg, tok, dev, map[string]string{"app": "web"})
	var doc LogsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.V != APIVersion || doc.App != "web" {
		t.Errorf("document = %+v", doc)
	}
	// No tail asked for, so all three lines come back -- which pins the default
	// rather than leaving it to be whatever it is.
	if strings.Count(doc.Lines, "\n") != 2 || !strings.Contains(doc.Lines, "one") {
		t.Errorf("default tail returned %q, want all three lines", doc.Lines)
	}

	w = ask(t, cfg, tok, dev, map[string]string{"app": "web", "tail": "2"})
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(doc.Lines, "one") || !strings.Contains(doc.Lines, "three") {
		t.Errorf("tail=2 returned %q", doc.Lines)
	}

	// Told apart, because "that is not an app" and "nothing yet" are different
	// answers and only one is about the request.
	for name, want := range map[string]int{
		"":             http.StatusBadRequest,
		"../etc":       http.StatusBadRequest,
		"_proxy":       http.StatusBadRequest,
		"neverstarted": http.StatusNotFound,
	} {
		if w := ask(t, cfg, tok, dev, map[string]string{"app": name}); w.Code != want {
			t.Errorf("app=%q = %d, want %d", name, w.Code, want)
		}
	}
	for _, bad := range []string{"0", "99999", "x"} {
		if w := ask(t, cfg, tok, dev, map[string]string{"app": "web", "tail": bad}); w.Code != http.StatusBadRequest {
			t.Errorf("tail=%s = %d, want 400", bad, w.Code)
		}
	}

	// A box not collecting says so, rather than answering with an empty log.
	off := cfg
	off.LogsDir = ""
	if w := ask(t, off, tok, dev, map[string]string{"app": "web"}); w.Code != http.StatusServiceUnavailable {
		t.Errorf("a box not collecting = %d, want 503", w.Code)
	}
	// And one that takes orders from nobody cannot be asked at all.
	none := cfg
	none.OperatorKeys = nil
	if w := ask(t, none, tok, dev, map[string]string{"app": "web"}); w.Code != http.StatusConflict {
		t.Errorf("a box with no devices = %d, want 409", w.Code)
	}
}

// A removed app's log goes with it.
func TestLogsOfRemovedAppsAreSwept(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"web", "gone"} {
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
	if _, err := ReadLog(dir, "web", 1); err != nil {
		t.Errorf("web lost its log: %v", err)
	}
}

// The directory is the permission that decides whether any of this works.
//
// Nothing covered it: the file's 0640 was asserted and the directory it lives in
// was not, and a logs directory created 0750 root:root is one where every
// request answers "nothing collected yet" forever.
func TestTheLogsDirectoryIsGroupReadable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	if err := WriteLog(dir, "web", []byte("x\n")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o050 != 0o050 {
		t.Errorf("the logs directory is %04o: the account that serves it cannot enter", perm)
	}
	if perm := fi.Mode().Perm(); perm&0o007 != 0 {
		t.Errorf("the logs directory is %04o: anything on the box can read the logs", perm)
	}
}

// Pruning removes what this writes and nothing else.
//
// --logs is an operator flag; pointed one directory up, an unbounded prune would
// delete history.jsonl every fifteen seconds, silently.
func TestPruningTouchesOnlyLogs(t *testing.T) {
	dir := t.TempDir()
	if err := WriteLog(dir, "gone", []byte("x\n")); err != nil {
		t.Fatal(err)
	}
	for _, other := range []string{"history.jsonl", "report.json", "notes"} {
		if err := os.WriteFile(filepath.Join(dir, other), []byte("keep me"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "results"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := PruneLogs(dir, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLog(dir, "gone", 1); err == nil {
		t.Error("a removed app kept its log")
	}
	for _, other := range []string{"history.jsonl", "report.json", "notes", "results"} {
		if _, err := os.Stat(filepath.Join(dir, other)); err != nil {
			t.Errorf("pruning removed %s, which is not a log it wrote", other)
		}
	}
}

// Trimming cuts at a line boundary even when the overflow lands exactly on one.
func TestTrimmingHandlesAnExactBoundary(t *testing.T) {
	dir := t.TempDir()
	line := strings.Repeat("a", 63) + "\n"
	var b strings.Builder
	for b.Len() < LogsMax+len(line)*2 {
		b.WriteString(line)
	}
	if err := WriteLog(dir, "web", []byte(b.String())); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "web.log"))
	if err != nil {
		t.Fatal(err)
	}
	for _, ln := range strings.Split(strings.TrimRight(string(body), "\n"), "\n") {
		if len(ln) != 63 {
			t.Fatalf("a fragment survived trimming: %d chars", len(ln))
		}
	}
}

// UNREADABLE IS NOT ABSENT.
//
// Collapsing the two is the bug paths.go records as having shipped: ReadSamples
// treated an unreadable file as an empty one, so /v1/history said "no readings"
// on every box forever and nothing anywhere mentioned permission. A 404 here
// would send somebody looking for an app that never started, when what they have
// is a directory the serving account cannot open.
func TestAnUnreadableLogIsNotReportedAsUncollected(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the mode this test depends on")
	}
	cfg, dir, tok, dev := logsFixture(t)
	if err := WriteLog(dir, "web", []byte("x\n")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "web.log"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dir, "web.log"), 0o640) })

	w := ask(t, cfg, tok, dev, map[string]string{"app": "web"})
	if w.Code == http.StatusNotFound {
		t.Error("a log that exists and cannot be read was reported as never collected")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("= %d, want 503", w.Code)
	}
}
