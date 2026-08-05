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
	for _, path := range []string{"/v1/report", "/v1/history"} {
		w := signedRead(t, cfg, tok, dev, path, OpReportRead, nil)
		if w.Code != http.StatusConflict {
			t.Errorf("%s = %d, want 409", path, w.Code)
		}
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

// A read op is never something the command route hands to root.
func TestTheReadOpsAreNotApplied(t *testing.T) {
	for _, op := range []string{OpReportRead, OpHistoryRead} {
		if Applies(op) {
			t.Errorf("%s is a read and the command route accepts it", op)
		}
		if !knownOp(op) {
			t.Errorf("%s is a read no envelope may name", op)
		}
	}
}
