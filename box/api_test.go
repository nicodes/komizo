package box

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The box answering for itself, and refusing to answer for anybody else.
//
// These are the tests for a wire format that is permanent from the moment it
// ships -- design/registry.md pins the shape before the code precisely because
// a published module version cannot be taken back.

// apiFixture is a box with a report, three samples, and ONE TRUSTED DEVICE.
//
// The device arrived with komizo-be#72. Before it, every test here read through
// `GET /v1/report`, which took the registry's token and nothing else -- and
// when that route was removed those reads would still have answered 401,
// because the catch-all refuses an unknown path with exactly the status an
// unauthorized one gets. Every token assertion in this file would have passed
// against a Handler with no token checking left in it at all.
//
// So they go through the signed route, which is the only way to read a box now.
func apiFixture(t *testing.T) (APIConfig, ed25519.PrivateKey, ed25519.PrivateKey, time.Time) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	devPub, devPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	cfg := APIConfig{
		ServerID:     "srv_abc123",
		RegistryKey:  pub,
		OperatorKeys: []ed25519.PublicKey{devPub},
		ReportPath:   filepath.Join(dir, "report.json"),
		HistoryPath:  filepath.Join(dir, "history.jsonl"),
		Now:          func() time.Time { return now },
	}
	rep := Report{V: Version, At: now, Server: Server{State: "ready", OS: "Alpine Linux v3.20"}}
	if err := WriteReport(cfg.ReportPath, rep); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		s := Sample{At: now.Add(time.Duration(-i) * time.Minute),
			System: System{Cores: 4, CPU: &CPU{Total: uint64(1000 * (i + 1)), Idle: uint64(800 * (i + 1))}}}
		if err := AppendSample(cfg.HistoryPath, s, HistoryMax, HistoryKeep); err != nil {
			t.Fatal(err)
		}
	}
	return cfg, priv, devPriv, now
}

func get(t *testing.T, h http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestAValidTokenReadsTheReport(t *testing.T) {
	cfg, priv, dev, now := apiFixture(t)
	tok, err := SignReadToken(priv, cfg.ServerID, now.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	res := signedRead(t, cfg, tok, dev, "/v1/report", OpReportRead, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("report = %d, want 200", res.Code)
	}
	var got ReportResponse
	if err := json.Unmarshal(res.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.V != APIVersion {
		t.Errorf("schema = %d, want %d -- every response states its own", got.V, APIVersion)
	}
	if got.Report.Server.OS != "Alpine Linux v3.20" {
		t.Errorf("report did not come through: %+v", got.Report.Server)
	}
}

// The property the whole design rests on: a token for one box is useless at
// another. Without it the registry is a skeleton key for every box it knows.
func TestATokenForAnotherBoxIsRefused(t *testing.T) {
	cfg, priv, dev, now := apiFixture(t)
	tok, err := SignReadToken(priv, "srv_somebody_else", now.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if res := signedRead(t, cfg, tok, dev, "/v1/report", OpReportRead, nil); res.Code != http.StatusUnauthorized {
		t.Errorf("a token for another box = %d, want 401", res.Code)
	}
}

func TestAnExpiredOrForgedTokenIsRefused(t *testing.T) {
	cfg, priv, dev, now := apiFixture(t)
	_, other, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	expired, _ := SignReadToken(priv, cfg.ServerID, now.Add(-time.Hour))
	forged, _ := SignReadToken(other, cfg.ServerID, now.Add(time.Hour))

	for name, tok := range map[string]string{
		"expired":                 expired,
		"signed by somebody else": forged,
		"not a token at all":      "kmz_rd_nonsense.nonsense",
		"empty":                   "",
	} {
		if res := signedRead(t, cfg, tok, dev, "/v1/report", OpReportRead, nil); res.Code != http.StatusUnauthorized {
			t.Errorf("%s = %d, want 401", name, res.Code)
		}
	}
}

// A box that has never enrolled has no id, so no token can name it. Refusing
// everything is the right answer for a machine no registry has heard of.
func TestAnUnenrolledBoxRefusesEverything(t *testing.T) {
	cfg, priv, dev, now := apiFixture(t)
	tok, _ := SignReadToken(priv, cfg.ServerID, now.Add(5*time.Minute))

	// SIGNED WHILE THE BOX STILL HAD AN ID, so what makes this refusable is the
	// box and not the request. Signing after would fail in SignCommand -- an
	// envelope must name the server it is for -- and would test the helper.
	env, err := SignCommand(dev, Command{Srv: cfg.ServerID,
		Exp: now.Add(time.Minute).Unix(), Op: OpReportRead})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	cfg.ServerID = ""
	r := httptest.NewRequest(http.MethodPost, "/v1/report", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	Handler(cfg).ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unenrolled box = %d, want 401", w.Code)
	}
}

// An unknown path must answer exactly as an unauthorized one does, or an
// unauthenticated caller can map the API by watching which paths 404.
func TestAnUnknownPathIsIndistinguishableFromUnauthorized(t *testing.T) {
	cfg, priv, dev, now := apiFixture(t)
	tok, _ := SignReadToken(priv, cfg.ServerID, now.Add(5*time.Minute))
	h := Handler(cfg)

	unknown := get(t, h, "/v1/secrets", tok)
	unauthorized := signedRead(t, cfg, "", dev, "/v1/report", OpReportRead, nil)
	if unknown.Code != unauthorized.Code {
		t.Errorf("unknown path = %d, unauthorized = %d -- they must match", unknown.Code, unauthorized.Code)
	}
}

// History carries the samples AS RECORDED -- cumulative counters, not rates.
// A rate needs two readings, and serving one would bake in an interval that a
// late poll makes wrong, unrecoverably.
func TestHistoryServesCountersARateCanBeDerivedFrom(t *testing.T) {
	cfg, priv, dev, now := apiFixture(t)
	tok, _ := SignReadToken(priv, cfg.ServerID, now.Add(5*time.Minute))

	res := signedRead(t, cfg, tok, dev, "/v1/history", OpHistoryRead, map[string]string{"from": "0", "to": "99999999999"})
	if res.Code != http.StatusOK {
		t.Fatalf("history = %d, want 200", res.Code)
	}
	var got HistoryResponse
	if err := json.Unmarshal(res.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Samples) < 2 {
		t.Fatalf("samples = %d, want the fixture's three", len(got.Samples))
	}
	for _, s := range got.Samples {
		if s.System.CPU == nil || s.System.CPU.Total == 0 {
			t.Fatalf("a sample lost its counters: %+v", s.System)
		}
	}
}

func TestHistoryRefusesABackwardsWindow(t *testing.T) {
	cfg, priv, dev, now := apiFixture(t)
	tok, _ := SignReadToken(priv, cfg.ServerID, now.Add(5*time.Minute))

	if res := signedRead(t, cfg, tok, dev, "/v1/history", OpHistoryRead, map[string]string{"from": "200", "to": "100"}); res.Code != http.StatusBadRequest {
		t.Errorf("backwards window = %d, want 400", res.Code)
	}
	if res := signedRead(t, cfg, tok, dev, "/v1/history", OpHistoryRead, map[string]string{"from": "abc"}); res.Code != http.StatusBadRequest {
		t.Errorf("unparseable window = %d, want 400", res.Code)
	}
}

// A box with no history yet is not a broken box.
func TestAnEmptyHistoryIsAnEmptyWindowNotAnError(t *testing.T) {
	cfg, priv, dev, now := apiFixture(t)
	cfg.HistoryPath = filepath.Join(t.TempDir(), "nothing-here.jsonl")
	tok, _ := SignReadToken(priv, cfg.ServerID, now.Add(5*time.Minute))

	res := signedRead(t, cfg, tok, dev, "/v1/history", OpHistoryRead, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("empty history = %d, want 200", res.Code)
	}
}

// A box whose agent has not written a report yet says so, rather than serving
// an empty document that reads as a broken machine.
func TestAMissingReportIsUnavailableNotEmpty(t *testing.T) {
	cfg, priv, dev, now := apiFixture(t)
	cfg.ReportPath = filepath.Join(t.TempDir(), "nothing-here.json")
	tok, _ := SignReadToken(priv, cfg.ServerID, now.Add(5*time.Minute))

	if res := signedRead(t, cfg, tok, dev, "/v1/report", OpReportRead, nil); res.Code != http.StatusServiceUnavailable {
		t.Errorf("missing report = %d, want 503", res.Code)
	}
}

// The key as enrolment stores it: raw base64, one line, no armour.
func TestThePlantedKeyRoundTrips(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePublicKey(b64(pub) + "\n")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := SignReadToken(priv, "srv_x", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReadToken(parsed, tok, "srv_x", time.Now()); err != nil {
		t.Errorf("a key read back from its stored form did not verify: %v", err)
	}

	for name, bad := range map[string]string{
		"not base64":   "!!!!",
		"wrong length": b64([]byte("too short")),
	} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("%s was accepted as a registry key", name)
		}
	}
}

// The socket directory has to be reachable by the box's proxy, which runs with
// every capability dropped but CAP_NET_BIND_SERVICE.
//
// That is komizo's own hardening and it means the proxy's root is NOT exempt
// from permission checks -- it cannot traverse a directory it does not own.
// This shipped as 0750 agent:agent and the proxy answered 502 with
// "connect: permission denied" on every request.
func TestTheSocketDirectoryIsSetgidSoTheProxyCanReachIt(t *testing.T) {
	if APISocketDirMode&os.ModeSetgid == 0 {
		t.Error("the socket directory is not setgid, so the socket inherits the agent's " +
			"group and the proxy -- which has no CAP_DAC_OVERRIDE -- cannot connect to it")
	}
	if perm := APISocketDirMode.Perm(); perm&0o050 == 0 {
		t.Errorf("the socket directory is %04o: the group cannot traverse it", perm)
	}
	if perm := APISocketDirMode.Perm(); perm&0o007 != 0 {
		t.Errorf("the socket directory is %04o: it is reachable by anything on the box", perm)
	}
}
