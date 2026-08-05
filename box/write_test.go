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

// writeFixture is a box that serves, takes orders from one device, and has an
// inbox and a results directory of its own.
func writeFixture(t *testing.T) (APIConfig, ed25519.PrivateKey, string, string) {
	t.Helper()
	regPub, regPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	devPub, devPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	inbox, results := t.TempDir(), t.TempDir()
	cfg := APIConfig{
		ServerID:     "srv_mine",
		RegistryKey:  regPub,
		OperatorKeys: []ed25519.PublicKey{devPub},
		InboxDir:     inbox,
		ResultsDir:   results,
		Now:          func() time.Time { return time.Now() },
	}
	tok, err := SignReadToken(regPriv, cfg.ServerID, time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return cfg, devPriv, tok, inbox
}

func post(t *testing.T, cfg APIConfig, tok string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/v1/commands", bytes.NewReader(body))
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	w := httptest.NewRecorder()
	Handler(cfg).ServeHTTP(w, r)
	return w
}

func signedCommand(t *testing.T, priv ed25519.PrivateKey, c Command) []byte {
	t.Helper()
	env, err := SignCommand(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func stopCmd() Command {
	return Command{Srv: "srv_mine", Exp: time.Now().Add(time.Minute).Unix(),
		Op: OpAppStop, Args: map[string]string{"app": "web"}}
}

// THE TOKEN GATES THE DOOR.
//
// The signature is the authority, but without a token an unauthenticated
// stranger can post blobs at this box until its memory is full -- and there is
// no unauthenticated route on this API at all, "not even a health check".
func TestPostingACommandNeedsAReadTokenToo(t *testing.T) {
	cfg, dev, tok, inbox := writeFixture(t)
	body := signedCommand(t, dev, stopCmd())

	if w := post(t, cfg, "", body); w.Code != http.StatusUnauthorized {
		t.Errorf("no token = %d, want 401", w.Code)
	}
	if w := post(t, cfg, "kmz_rd_nonsense", body); w.Code != http.StatusUnauthorized {
		t.Errorf("a junk token = %d, want 401", w.Code)
	}
	if n := inboxCount(t, inbox); n != 0 {
		t.Fatalf("%d commands were taken without a token", n)
	}
	// And a token minted for another box is refused, so a reader of one machine
	// cannot command a different one.
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	other, err := SignReadToken(otherPriv, cfg.ServerID, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if w := post(t, cfg, other, body); w.Code != http.StatusUnauthorized {
		t.Errorf("a token from another registry = %d, want 401", w.Code)
	}

	if w := post(t, cfg, tok, body); w.Code != http.StatusAccepted {
		t.Fatalf("a signed command with a good token = %d, want 202", w.Code)
	}
	if n := inboxCount(t, inbox); n != 1 {
		t.Errorf("%d commands in the inbox, want 1", n)
	}
}

// AND THE SIGNATURE STILL DECIDES.
//
// A valid read token is not authority to command: a reader who could mint one
// but has no device key must not be able to leave anything rootd would apply.
func TestAReadTokenIsNotAuthorityToCommand(t *testing.T) {
	cfg, _, tok, inbox := writeFixture(t)
	_, stranger, _ := ed25519.GenerateKey(nil)

	w := post(t, cfg, tok, signedCommand(t, stranger, stopCmd()))
	if w.Code != http.StatusForbidden {
		t.Errorf("a command signed by an untrusted device = %d, want 403", w.Code)
	}
	if n := inboxCount(t, inbox); n != 0 {
		t.Errorf("%d commands were left for rootd anyway", n)
	}
	// One answer for every reason, the same as the read routes.
	if strings.Contains(w.Body.String(), "signature") || strings.Contains(w.Body.String(), "key") {
		t.Errorf("the refusal explained itself: %q", w.Body.String())
	}
}

// A command for another box is refused here as well as at root.
func TestACommandForAnotherBoxIsNotTaken(t *testing.T) {
	cfg, dev, tok, inbox := writeFixture(t)
	c := stopCmd()
	c.Srv = "srv_theirs"

	if w := post(t, cfg, tok, signedCommand(t, dev, c)); w.Code != http.StatusForbidden {
		t.Errorf("a command for another box = %d, want 403", w.Code)
	}
	if n := inboxCount(t, inbox); n != 0 {
		t.Errorf("%d commands were taken", n)
	}
}

// A box nobody has given a device to says so, rather than accepting work it
// will never do.
func TestABoxWithNoDevicesRefusesPlainly(t *testing.T) {
	cfg, dev, tok, inbox := writeFixture(t)
	cfg.OperatorKeys = nil

	w := post(t, cfg, tok, signedCommand(t, dev, stopCmd()))
	if w.Code != http.StatusConflict {
		t.Errorf("a box with no devices = %d, want 409", w.Code)
	}
	if n := inboxCount(t, inbox); n != 0 {
		t.Errorf("%d commands were taken by a box that takes orders from nobody", n)
	}
}

// ARRIVAL IS IDEMPOTENT.
//
// The file is named by the command's id, so a retry after a dropped response is
// the same command rather than a second stop.
func TestTheSameCommandTwiceIsOneCommand(t *testing.T) {
	cfg, dev, tok, inbox := writeFixture(t)
	body := signedCommand(t, dev, stopCmd())

	for i := 0; i < 3; i++ {
		if w := post(t, cfg, tok, body); w.Code != http.StatusAccepted {
			t.Fatalf("attempt %d = %d", i, w.Code)
		}
	}
	if n := inboxCount(t, inbox); n != 1 {
		t.Errorf("%d files in the inbox, want 1 -- a retry queued a second stop", n)
	}
}

// And once it has been applied, posting it again returns what happened rather
// than doing it a second time.
func TestPostingAnAppliedCommandReturnsItsResult(t *testing.T) {
	cfg, dev, tok, inbox := writeFixture(t)
	c := stopCmd()
	c.ID = "alreadydone"
	if err := WriteResult(cfg.ResultsDir, Result{ID: c.ID, Op: c.Op, OK: true}); err != nil {
		t.Fatal(err)
	}

	w := post(t, cfg, tok, signedCommand(t, dev, c))
	if w.Code != http.StatusOK {
		t.Fatalf("an applied command = %d, want 200 with its result", w.Code)
	}
	var got resultResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Result.OK || got.Result.ID != c.ID {
		t.Errorf("result = %+v", got.Result)
	}
	if n := inboxCount(t, inbox); n != 0 {
		t.Error("an applied command was queued again")
	}
}

// The inbox is bounded, and a full one is a state that passes rather than an
// error: rootd drains it on its own timer.
func TestAFullInboxIsRefusedAndSaysTryAgain(t *testing.T) {
	cfg, dev, tok, inbox := writeFixture(t)
	for i := 0; i < InboxFull; i++ {
		if err := os.WriteFile(filepath.Join(inbox, "filler"+strings.Repeat("x", i%5)+itoa(i)), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w := post(t, cfg, tok, signedCommand(t, dev, stopCmd()))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("a full inbox = %d, want 503", w.Code)
	}
}

// A body larger than a command is refused before it is anything else.
func TestAnOversizedBodyIsRefused(t *testing.T) {
	cfg, _, tok, inbox := writeFixture(t)
	w := post(t, cfg, tok, bytes.Repeat([]byte("x"), MaxCommandBytes+1))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("an oversized body = %d, want 413", w.Code)
	}
	if n := inboxCount(t, inbox); n != 0 {
		t.Error("it was written anyway")
	}
}

// The result route answers what happened, and refuses an id that is not one.
func TestReadingAResult(t *testing.T) {
	cfg, _, tok, _ := writeFixture(t)
	if err := WriteResult(cfg.ResultsDir, Result{ID: "abc123", Op: OpAppStop, OK: true}); err != nil {
		t.Fatal(err)
	}

	get := func(id, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/v1/commands/"+id, nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		Handler(cfg).ServeHTTP(w, r)
		return w
	}

	if w := get("abc123", tok); w.Code != http.StatusOK {
		t.Errorf("a known result = %d, want 200", w.Code)
	}
	// Not yet applied is 404 and not an error: it is what the caller is polling
	// to see change.
	if w := get("neverheard", tok); w.Code != http.StatusNotFound {
		t.Errorf("an unknown id = %d, want 404", w.Code)
	}
	// And it needs a token like everything else here.
	if w := get("abc123", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("no token = %d, want 401", w.Code)
	}
}

// AN ID IS NEVER JOINED TO A PATH UNCHECKED, on the way in or the way out.
func TestTheResultRouteRefusesAnIDThatIsAPath(t *testing.T) {
	cfg, _, tok, _ := writeFixture(t)
	// 401, not 404. The difference is the point: 404 means "no result for that
	// command", which would mean the id had been LOOKED UP. Refusing it as a
	// name is what stops the lookup happening at all, and asserting only "not
	// 200" passes with that check deleted.
	for _, bad := range []string{"a.b", "a_b.json", strings.Repeat("x", 65)} {
		r := httptest.NewRequest(http.MethodGet, "/v1/commands/"+bad, nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		Handler(cfg).ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("id %q = %d, want it refused as a name (401) rather than looked up", bad, w.Code)
		}
	}
	// ".." never reaches the handler: ServeMux cleans the path and answers with
	// a redirect. Asserted so that a future router change which stops doing that
	// is caught here rather than at the filesystem.
	r := httptest.NewRequest(http.MethodGet, "/v1/commands/..", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	Handler(cfg).ServeHTTP(w, r)
	if w.Code == http.StatusOK {
		t.Error("a traversal in the path was served")
	}
}

// And an id is checked again where it becomes a path.
//
// Unreachable through the route today, because VerifyCommand checks it first --
// which is why it is tested directly. A check that is only load-bearing because
// of the one before it is a check that silently stops mattering when that one
// moves.
func TestStoringACommandRefusesAnIDThatIsAPath(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	rel, err := filepath.Rel(dir, filepath.Join(outside, "PWNED"))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{rel, "..", "a/b", "a.b", ""} {
		if err := writeCommand(dir, bad, []byte("x")); err == nil {
			t.Errorf("a command was stored under id %q", bad)
		}
	}
	if _, err := os.Stat(filepath.Join(outside, "PWNED")); err == nil {
		t.Fatal("a command was written outside the inbox")
	}
	// And an ordinary id still stores, so this is not refusing everything.
	id, err := NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeCommand(dir, id, []byte("x")); err != nil {
		t.Fatalf("an ordinary id was refused: %v", err)
	}
}

// The blob rootd reads is exactly the blob that arrived.
//
// Written to a temporary and renamed, so a reader never sees a partial file --
// and stored verbatim, because the signature covers those bytes and re-encoding
// them would be verifying something the signer never sent.
func TestWhatIsStoredIsWhatWasSigned(t *testing.T) {
	cfg, dev, tok, inbox := writeFixture(t)
	body := signedCommand(t, dev, stopCmd())

	if w := post(t, cfg, tok, body); w.Code != http.StatusAccepted {
		t.Fatalf("= %d", w.Code)
	}
	ents, err := os.ReadDir(inbox)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 {
		t.Fatalf("%d files", len(ents))
	}
	if strings.HasPrefix(ents[0].Name(), ".tmp-") {
		t.Error("a temporary was left where the final name should be")
	}
	stored, err := os.ReadFile(filepath.Join(inbox, ents[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, body) {
		t.Error("the stored bytes are not the bytes that were signed")
	}
	// And it verifies at root, which is the only opinion that matters.
	if _, _, err := VerifyCommand(cfg.OperatorKeys, stored, cfg.ServerID, time.Now()); err != nil {
		t.Errorf("what was stored does not verify: %v", err)
	}
}

func inboxCount(t *testing.T, dir string) int {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return len(ents)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
