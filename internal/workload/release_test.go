package workload

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func releaseFixture(t *testing.T) (Policy, ReleaseManifest, *rsa.PrivateKey, time.Time) {
	t.Helper()
	p, err := NewPolicy("demo", "/srv/demo", "ghcr.io/owner/demo-config", "edge")
	if err != nil {
		t.Fatal(err)
	}
	p.SourceRepository = "owner/source"
	p.RepositoryID = "1234"
	v := strings.Repeat("a", 40)
	m := ReleaseManifest{Version: 1, Repository: p.SourceRepository, RepositoryID: p.RepositoryID, Revision: v, TestedCommit: v, RunID: "12345", Images: map[string]string{p.ImagePrefix + "api:" + v: "sha256:" + strings.Repeat("1", 64), p.ImagePrefix + "config:" + v: "sha256:" + strings.Repeat("2", 64)}}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return p, m, key, time.Now().UTC().Truncate(time.Second)
}
func releaseProof(t *testing.T, p Policy, m ReleaseManifest, key *rsa.PrivateKey, now time.Time, alter func(jwt.MapClaims)) []byte {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	claims := jwt.MapClaims{"iss": actionsIssuer, "aud": fmt.Sprintf("komizo-release:sha256:%x", sum), "sub": "repo:" + p.SourceRepository + ":environment:production", "repository": p.SourceRepository, "repository_id": p.RepositoryID, "ref": "refs/heads/main", "sha": m.Revision, "workflow_ref": p.SourceRepository + "/.github/workflows/cd.yml@refs/heads/main", "workflow_sha": m.Revision, "run_id": m.RunID, "event_name": "push", "runner_environment": "github-hosted", "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}
	if alter != nil {
		alter(claims)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "fixture"
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(ReleaseEnvelope{Manifest: base64.StdEncoding.EncodeToString(raw), Token: signed})
	if err != nil {
		t.Fatal(err)
	}
	return body
}
func TestReleaseAuthenticatesExactMainWorkflowAndManifest(t *testing.T) {
	p, m, key, now := releaseFixture(t)
	keyFn := func(context.Context, string) (*rsa.PublicKey, error) { return &key.PublicKey, nil }
	good := releaseProof(t, p, m, key, now, nil)
	accepted, err := VerifyRelease(context.Background(), good, p, m.Revision, now, keyFn)
	if err != nil || accepted.Manifest.Revision != m.Revision || accepted.Authority != actionsIssuer {
		t.Fatalf("valid release refused: %v", err)
	}
	for field, value := range map[string]any{"repository": "attacker/repo", "repository_id": "999", "ref": "refs/pull/1/merge", "sha": strings.Repeat("b", 40), "workflow_ref": "owner/source/.github/workflows/ci.yml@refs/heads/main", "workflow_sha": strings.Repeat("c", 40), "run_id": "9999", "event_name": "pull_request", "runner_environment": "unknown", "aud": "unbound", "iss": "https://attacker.invalid", "iat": now.Add(time.Minute).Unix(), "exp": now.Add(-time.Minute).Unix(), "nbf": now.Add(time.Minute).Unix(), "sub": ""} {
		t.Run(field, func(t *testing.T) {
			proof := releaseProof(t, p, m, key, now, func(c jwt.MapClaims) { c[field] = value })
			if _, err := VerifyRelease(context.Background(), proof, p, m.Revision, now, keyFn); err == nil {
				t.Fatalf("accepted wrong %s", field)
			}
		})
	}
	var altered ReleaseEnvelope
	if err := json.Unmarshal(good, &altered); err != nil {
		t.Fatal(err)
	}
	m.Images[p.ImagePrefix+"api:"+m.Revision] = "sha256:" + strings.Repeat("f", 64)
	raw, _ := json.Marshal(m)
	altered.Manifest = base64.StdEncoding.EncodeToString(raw)
	tampered, _ := json.Marshal(altered)
	if _, err := VerifyRelease(context.Background(), tampered, p, m.Revision, now, keyFn); err == nil {
		t.Fatal("image substitution accepted")
	}
	if _, err := VerifyRelease(context.Background(), good, p, m.Revision, now.Add(6*time.Minute), keyFn); err == nil {
		t.Fatal("expired deployment authorization accepted")
	}
}
func TestReleaseRejectsAmbiguousDocuments(t *testing.T) {
	for _, body := range []string{`{"version":1,"version":2}`, `{"images":{"x":"one","x":"two"}}`, strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34)} {
		var out map[string]any
		if strictJSON([]byte(body), &out) == nil {
			t.Fatalf("ambiguous document accepted: %s", body)
		}
	}
}
func TestReleaseBindingRejectsSubstitutionBeforeStartingAndPinsDigest(t *testing.T) {
	p, m, _, _ := releaseFixture(t)
	compose := []byte(`{"services":{"api":{"image":"` + p.ImagePrefix + "api:" + m.Revision + `"},"postgres":{"image":"postgres@sha256:` + strings.Repeat("3", 64) + `"}}}`)
	changed := false
	var calls []string
	run := func(_ context.Context, args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
		if args[0] == "pull" {
			return "", nil
		}
		ref := args[2]
		id := m.Images[ref]
		if changed && strings.Contains(ref, "-api:") {
			id = "sha256:" + strings.Repeat("f", 64)
		}
		repo := strings.TrimSuffix(ref, ":"+m.Revision)
		body, _ := json.Marshal([]map[string]any{{"Id": id, "RepoDigests": []string{repo + "@sha256:" + strings.Repeat("9", 64)}}})
		return string(body), nil
	}
	pinned, err := BindRelease(context.Background(), run, p, ReleaseAcceptance{Manifest: m, Authority: actionsIssuer}, m.Revision, p.ImagePrefix+"config:"+m.Revision, compose)
	if err != nil || !strings.Contains(string(pinned), p.ImagePrefix+"api@sha256:") {
		t.Fatalf("binding failed: %v", err)
	}
	changed = true
	if _, err := BindRelease(context.Background(), run, p, ReleaseAcceptance{Manifest: m, Authority: actionsIssuer}, m.Revision, p.ImagePrefix+"config:"+m.Revision, compose); err == nil {
		t.Fatal("registry image substitution accepted")
	}
	for _, call := range calls {
		if strings.Contains(call, " up") || strings.Contains(call, "run ") {
			t.Fatalf("verification started a workload: %s", call)
		}
	}
}
func TestContainerdBindingUsesImmutableLocalConfiguration(t *testing.T) {
	p, m, _, _ := releaseFixture(t)
	compose := []byte(`{"services":{"api":{"image":"` + p.ImagePrefix + `api:` + m.Revision + `"}}}`)
	actual := ""
	target := "sha256:" + strings.Repeat("8", 64)
	descriptor := target
	run := func(_ context.Context, args ...string) (string, error) {
		if args[0] == "pull" {
			return "", nil
		}
		if args[0] == "config-digest" {
			if args[1] != target {
				t.Fatal("configuration looked up through mutable tag")
			}
			return actual, nil
		}
		ref := args[2]
		// Only the service uses the newer store for this fixture.
		id := m.Images[ref]
		if strings.Contains(ref, "-api:") {
			id = target
		}
		repo := strings.TrimSuffix(ref, ":"+m.Revision)
		b, _ := json.Marshal([]map[string]any{{"Id": id, "Descriptor": map[string]string{"digest": descriptor}, "RepoDigests": []string{repo + "@" + target}}})
		return string(b), nil
	}
	actual = m.Images[p.ImagePrefix+"api:"+m.Revision]
	if _, err := BindRelease(context.Background(), run, p, ReleaseAcceptance{Manifest: m, Authority: actionsIssuer}, m.Revision, p.ImagePrefix+"config:"+m.Revision, compose); err != nil {
		t.Fatal(err)
	}
	actual = "sha256:" + strings.Repeat("f", 64)
	if _, err := BindRelease(context.Background(), run, p, ReleaseAcceptance{Manifest: m, Authority: actionsIssuer}, m.Revision, p.ImagePrefix+"config:"+m.Revision, compose); err == nil {
		t.Fatal("changed local configuration accepted")
	}
	actual = m.Images[p.ImagePrefix+"api:"+m.Revision]
	descriptor = ""
	if _, err := BindRelease(context.Background(), run, p, ReleaseAcceptance{Manifest: m, Authority: actionsIssuer}, m.Revision, p.ImagePrefix+"config:"+m.Revision, compose); err == nil {
		t.Fatal("unexplained image mismatch accepted")
	}
}

func TestInterruptedActivationIsDurableAndRequiresReconciliation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operation.json")
	now := time.Now().UTC()
	for _, phase := range []string{"admitted", "configured", "activating"} {
		if err := RecordOperation(path, "demo", "candidate", "previous", phase, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := RecordOperation(path, "demo", "other", "candidate", "admitted", now); err == nil {
		t.Fatal("another release bypassed interrupted activation")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var operation Operation
	if json.Unmarshal(body, &operation) != nil || operation.Phase != "activating" {
		t.Fatal("lost interrupted state")
	}
	if err := RecordOperation(path, "demo", "candidate", "previous", "failed", now); err != nil {
		t.Fatal(err)
	}
	if err := RecordOperation(path, "demo", "other", "candidate", "admitted", now); err == nil {
		t.Fatal("failed activation bypassed reconciliation")
	}
	if err := RecordOperation(path, "demo", "candidate", "previous", "reconciled", now); err != nil {
		t.Fatal(err)
	}
	if err := RecordOperation(path, "demo", "other", "candidate", "admitted", now); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("journal is not private")
	}
}

func TestReleaseRejectsUnsignedHMACAndUnavailableIssuerKeys(t *testing.T) {
	p, m, key, now := releaseFixture(t)
	good := releaseProof(t, p, m, key, now, nil)
	var env ReleaseEnvelope
	if err := json.Unmarshal(good, &env); err != nil {
		t.Fatal(err)
	}
	parsed, _, err := new(jwt.Parser).ParseUnverified(env.Token, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []jwt.SigningMethod{jwt.SigningMethodNone, jwt.SigningMethodHS256} {
		token := jwt.NewWithClaims(method, parsed.Claims)
		token.Header["kid"] = "fixture"
		var signingKey any = []byte("fixture")
		if method == jwt.SigningMethodNone {
			signingKey = jwt.UnsafeAllowNoneSignatureType
		}
		env.Token, err = token.SignedString(signingKey)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(env)
		keyCalls := 0
		_, err = VerifyRelease(context.Background(), body, p, m.Revision, now, func(context.Context, string) (*rsa.PublicKey, error) { keyCalls++; return &key.PublicKey, nil })
		if err == nil || keyCalls != 0 {
			t.Fatal("unapproved algorithm reached issuer key lookup")
		}
	}
	if _, err := VerifyRelease(context.Background(), good, p, m.Revision, now, func(context.Context, string) (*rsa.PublicKey, error) { return nil, fmt.Errorf("offline") }); err == nil {
		t.Fatal("missing issuer key failed open")
	}
}
