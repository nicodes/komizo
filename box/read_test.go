package box

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// readFixture is a box with a report, a history and a device it trusts.
func readFixture(t *testing.T) (APIConfig, string, ed25519.PrivateKey) {
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
	rep := Report{V: Version, At: time.Now().UTC()}
	rep.Server.State = "ready"
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(dir, "report.json")
	if err := os.WriteFile(reportPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := APIConfig{ServerID: "srv_mine", RegistryKey: regPub,
		OperatorKeys: []ed25519.PublicKey{devPub},
		ReportPath:   reportPath, HistoryPath: filepath.Join(dir, "history.jsonl")}
	tok, err := SignReadToken(regPriv, cfg.ServerID, time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return cfg, tok, devPriv
}

func signedRead(t *testing.T, cfg APIConfig, tok string, dev ed25519.PrivateKey,
	path, op string, args map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	body := []byte("{}")
	if dev != nil {
		env, err := SignCommand(dev, Command{Srv: cfg.ServerID,
			Exp: time.Now().Add(time.Minute).Unix(), Op: op, Args: args})
		if err != nil {
			t.Fatal(err)
		}
		if body, err = json.Marshal(env); err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	w := httptest.NewRecorder()
	Handler(cfg).ServeHTTP(w, r)
	return w
}

// A SIGNED READ NEEDS BOTH, and the token alone is not enough.
//
// komizo-be#58. The report and the history were behind the registry's token
// only, which meant whoever holds the service's signing key reads every
// enrolled box -- and "komizo cannot read your servers" was therefore false for
// two routes out of four.
func TestASignedReadNeedsATokenAndASignature(t *testing.T) {
	cfg, tok, dev := readFixture(t)
	_, stranger, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		what string
		path string
		op   string
	}{
		{"report", "/v1/report", OpReportRead},
		{"history", "/v1/history", OpHistoryRead},
	} {
		// Both: fine.
		if w := signedRead(t, cfg, tok, dev, tc.path, tc.op, nil); w.Code != http.StatusOK {
			t.Errorf("%s: signed and tokened = %d, want 200", tc.what, w.Code)
		}
		// No token: the door is shut before the signature is looked at.
		if w := signedRead(t, cfg, "", dev, tc.path, tc.op, nil); w.Code == http.StatusOK {
			t.Errorf("%s: answered with no token", tc.what)
		}
		// A token and NO signature. This is the whole point of the change: a
		// caller holding a minted token is not a device.
		if w := signedRead(t, cfg, tok, nil, tc.path, tc.op, nil); w.Code == http.StatusOK {
			t.Errorf("%s: answered a token with no signature", tc.what)
		}
		// A signature from a key this box was never given.
		if w := signedRead(t, cfg, tok, stranger, tc.path, tc.op, nil); w.Code != http.StatusForbidden {
			t.Errorf("%s: stranger = %d, want 403", tc.what, w.Code)
		}
		// A device it trusts, naming the wrong op. An envelope is not a
		// skeleton key for every signed route.
		if w := signedRead(t, cfg, tok, dev, tc.path, OpAppStop, nil); w.Code != http.StatusForbidden {
			t.Errorf("%s: wrong op = %d, want 403", tc.what, w.Code)
		}
	}
}

// A BOX THAT TAKES ORDERS FROM NOBODY SAYS SO.
//
// Which is every box until an operator plants a key. Answering with an empty
// document would send somebody to look at a machine that is fine.
func TestASignedReadOnABoxWithNoDevicesIsToldWhy(t *testing.T) {
	cfg, tok, dev := readFixture(t)
	cfg.OperatorKeys = nil
	// Each path signed for ITS OWN op. This used to sign report.read for both,
	// so on /v1/history the op was wrong and the test passed only because the
	// empty-keys check happens to precede the op check. That ordering is
	// correct and is asserted below -- but a test should not depend on it
	// silently.
	for _, tc := range []struct {
		path string
		op   string
	}{
		{"/v1/report", OpReportRead},
		{"/v1/history", OpHistoryRead},
	} {
		w := signedRead(t, cfg, tok, dev, tc.path, tc.op, nil)
		if w.Code != http.StatusConflict {
			t.Errorf("%s = %d, want 409", tc.path, w.Code)
		}
	}
	// AND THE ORDER IS DELIBERATE: "nobody may read this" is answered before
	// the op is looked at, so a box with no devices says the same thing however
	// the envelope was addressed rather than leaking which ops it knows.
	if w := signedRead(t, cfg, tok, dev, "/v1/history", OpReportRead, nil); w.Code != http.StatusConflict {
		t.Errorf("wrong op on a box with no devices = %d, want the same 409", w.Code)
	}
}

// THE UNSIGNED ROUTES STILL ANSWER, because boxes are updated by hand.
//
// An app that spoke only the signed form would go blind against every box that
// has not been updated yet. Removing these is the breaking step and is its own
// change -- komizo-be#58.
func TestTheUnsignedReadsStillAnswerDuringTheMigration(t *testing.T) {
	cfg, tok, _ := readFixture(t)
	for _, path := range []string{"/v1/report", "/v1/history"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		Handler(cfg).ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200 while both forms are served", path, w.Code)
		}
	}
}

// THE WINDOW COMES FROM WHAT WAS SIGNED.
//
// The point of the route is that the request came from a particular device, and
// a window read from the URL is one anything that relayed the request could
// rewrite without breaking the signature.
func TestASignedHistoryWindowComesFromTheEnvelope(t *testing.T) {
	cfg, tok, dev := readFixture(t)

	w := signedRead(t, cfg, tok, dev, "/v1/history", OpHistoryRead,
		map[string]string{"from": "1000", "to": "2000"})
	if w.Code != http.StatusOK {
		t.Fatalf("signed window = %d", w.Code)
	}
	var got HistoryResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.From != 1000 || got.To != 2000 {
		t.Errorf("window = %d..%d, want the signed one", got.From, got.To)
	}

	// A window in the QUERY STRING is not read. If it were, whoever relayed the
	// request could choose what the device was shown.
	env, err := SignCommand(dev, Command{Srv: cfg.ServerID,
		Exp: time.Now().Add(time.Minute).Unix(), Op: OpHistoryRead,
		Args: map[string]string{"from": "1000", "to": "2000"}})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/history?from=5000&to=6000", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	Handler(cfg).ServeHTTP(rec, r)
	var relayed HistoryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &relayed); err != nil {
		t.Fatal(err)
	}
	if relayed.From != 1000 || relayed.To != 2000 {
		t.Errorf("window = %d..%d, want the SIGNED one -- a relayer chose it", relayed.From, relayed.To)
	}

	// And a window that is not a window is refused rather than defaulted.
	if w := signedRead(t, cfg, tok, dev, "/v1/history", OpHistoryRead,
		map[string]string{"from": "2000", "to": "1000"}); w.Code != http.StatusBadRequest {
		t.Errorf("backwards window = %d, want 400", w.Code)
	}
}

// THE DEFAULT WINDOW IS THE SAME ON BOTH ROUTES.
//
// Two copies of "the last hour" is two answers to what asking for nothing
// means, and nothing failed when they drifted -- review moved one default to
// -24h and the whole suite stayed green.
func TestBothHistoryRoutesDefaultToTheSameWindow(t *testing.T) {
	cfg, tok, dev := readFixture(t)
	now := time.Now()
	cfg.Now = func() time.Time { return now }

	signed := signedRead(t, cfg, tok, dev, "/v1/history", OpHistoryRead, nil)
	r := httptest.NewRequest(http.MethodGet, "/v1/history", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	Handler(cfg).ServeHTTP(w, r)

	var a, b HistoryResponse
	if err := json.Unmarshal(signed.Body.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if a.From != b.From || a.To != b.To {
		t.Errorf("signed = %d..%d, unsigned = %d..%d -- one default, not two", a.From, a.To, b.From, b.To)
	}
	// And it is the last hour, so neither can drift while agreeing.
	if a.To != now.Unix() || a.From != now.Add(-time.Hour).Unix() {
		t.Errorf("default = %d..%d, want the last hour ending now", a.From, a.To)
	}
}

// A SIGNED READ IS BOUNDED BEFORE IT IS PARSED.
//
// This route is reachable from the internet through the box's proxy, and an
// unbounded read is an unbounded allocation before anything has been verified.
func TestASignedReadRefusesAnOversizeBody(t *testing.T) {
	cfg, tok, _ := readFixture(t)
	body := bytes.Repeat([]byte("a"), MaxCommandBytes+1)
	r := httptest.NewRequest(http.MethodPost, "/v1/report", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	Handler(cfg).ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize body = %d, want 413", w.Code)
	}
}

// A DEVICE THIS BOX TRUSTS GETS A SENTENCE, NOT A SILENCE.
//
// §4's split: a signature that verified means the caller is entitled to know
// what went wrong, where a stranger is told one thing about everything.
func TestASignedReadTellsATrustedDeviceAboutVersionSkew(t *testing.T) {
	cfg, tok, dev := readFixture(t)
	payload := []byte(fmt.Sprintf(
		`{"v":99,"id":"abc123","srv":"srv_mine","exp":%d,"op":"report.read"}`,
		time.Now().Add(time.Minute).Unix()))
	raw, err := json.Marshal(Signed{Payload: b64(payload), Sig: b64(ed25519.Sign(dev, payload))})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/report", bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	Handler(cfg).ServeHTTP(w, r)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a version this box does not speak = %d, want 422", w.Code)
	}
	if !strings.Contains(w.Body.String(), "speaks v") {
		t.Errorf("body = %q, want it to name both versions", w.Body.String())
	}
}

// A MISSING REPORT IS UNAVAILABLE, NOT EMPTY.
//
// The GET has had this test since it shipped; the POST had nothing, and an
// empty document reads as a broken box rather than one that has not been polled.
func TestASignedReportOfAMissingFileIsUnavailable(t *testing.T) {
	cfg, tok, dev := readFixture(t)
	if err := os.Remove(cfg.ReportPath); err != nil {
		t.Fatal(err)
	}
	w := signedRead(t, cfg, tok, dev, "/v1/report", OpReportRead, nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("missing report = %d, want 503", w.Code)
	}
}

// countingReader records how much of a body was actually consumed.
type countingReader struct {
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	// Endless. A route that reads without a bound would never stop.
	for i := range p {
		p[i] = 'a'
	}
	c.n += len(p)
	return len(p), nil
}

// THE BOUND IS ON THE READ, not only on what came back.
//
// The 413 above is satisfied by a route that reads a gigabyte and then measures
// it -- review moved the LimitReader out and the whole suite stayed green,
// because `len(raw) > MaxCommandBytes` still fired. On a route reachable from
// the internet the allocation IS the attack, so what has to be asserted is that
// the bytes were never taken in.
func TestASignedReadStopsReadingAtTheBound(t *testing.T) {
	cfg, tok, _ := readFixture(t)
	body := &countingReader{}
	r := httptest.NewRequest(http.MethodPost, "/v1/report", body)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	Handler(cfg).ServeHTTP(w, r)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("an endless body = %d, want 413", w.Code)
	}
	// Some slack for the reader's own buffering, and far below anything that
	// would matter -- the point is that it is BOUNDED, not that it is exact.
	if limit := 4 * MaxCommandBytes; body.n > limit {
		t.Errorf("read %d bytes of an endless body, want it stopped near %d", body.n, MaxCommandBytes)
	}
}
