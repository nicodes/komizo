package workload

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const actionsIssuer = "https://token.actions.githubusercontent.com"
const ReleaseMaxBytes = 64 << 10

var commitID = regexp.MustCompile(`^[a-f0-9]{40}$`)
var repositoryName = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
var numericID = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)

// ReleaseManifest binds the exact Docker configuration IDs validated by CI.
// The Actions identity authenticates this entire document through its audience.
type ReleaseManifest struct {
	Version      int               `json:"version"`
	Repository   string            `json:"repository"`
	RepositoryID string            `json:"repository_id"`
	Revision     string            `json:"revision"`
	TestedCommit string            `json:"tested_commit"`
	RunID        string            `json:"run_id"`
	Images       map[string]string `json:"images"`
}

type ReleaseEnvelope struct {
	Manifest string `json:"manifest"` // base64 of the exact audience-bound bytes
	Token    string `json:"token"`
}

type ReleaseAcceptance struct {
	Manifest       ReleaseManifest `json:"manifest"`
	VerifiedAt     time.Time       `json:"verified_at"`
	Authority      string          `json:"authority"`
	EvidenceSHA256 string          `json:"evidence_sha256,omitempty"`
}

func (m ReleaseManifest) Check(p Policy, version string) error { return m.check(p, version, true) }
func (m ReleaseManifest) check(p Policy, version string, actions bool) error {
	if m.Version != 1 || m.Repository != p.SourceRepository || m.RepositoryID != p.RepositoryID || m.Revision != version ||
		!commitID.MatchString(version) || len(m.Images) < 2 || len(m.Images) > 16 {
		return errors.New("release identity does not match host policy and tested source")
	}
	if actions && (m.TestedCommit != version || !numericID.MatchString(m.RunID)) {
		return errors.New("release has no matching tested workflow source")
	}
	if !actions && (m.TestedCommit != "" || m.RunID != "") {
		return errors.New("operator bootstrap must not claim Actions test evidence")
	}
	for image, id := range m.Images {
		if !strings.HasPrefix(image, p.ImagePrefix) || !strings.HasSuffix(image, ":"+version) || !digest.MatchString(id) {
			return errors.New("release image identity outside approved family")
		}
		component := strings.TrimSuffix(strings.TrimPrefix(image, p.ImagePrefix), ":"+version)
		if !identifier.MatchString(component) {
			return errors.New("invalid release component")
		}
	}
	if _, ok := m.Images[p.ImagePrefix+"config:"+version]; !ok {
		return errors.New("release has no configuration image")
	}
	return nil
}

// strictJSON uses the same duplicate/depth/alias rejection as workload input,
// then requires exactly the declared fields. JWT claims remain issuer-owned.
func strictJSON(body []byte, out any) error {
	if len(body) > ReleaseMaxBytes || !json.Valid(body) {
		return errors.New("invalid bounded release JSON")
	}
	if err := rejectDuplicateJSON(body); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return errors.New("invalid release fields")
	}
	return nil
}

func rejectDuplicateJSON(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return errors.New("release JSON exceeds nesting limit")
		}
		token, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				key, err := dec.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("duplicate release JSON key")
				}
				seen[name] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected release JSON delimiter")
		}
		_, err = dec.Token()
		return err
	}
	return walk(0)
}

type actionsClaims struct {
	jwt.RegisteredClaims
	Repository        string `json:"repository"`
	RepositoryID      string `json:"repository_id"`
	Ref               string `json:"ref"`
	SHA               string `json:"sha"`
	WorkflowRef       string `json:"workflow_ref"`
	WorkflowSHA       string `json:"workflow_sha"`
	RunID             string `json:"run_id"`
	EventName         string `json:"event_name"`
	RunnerEnvironment string `json:"runner_environment"`
}

type ReleaseKey func(context.Context, string) (*rsa.PublicKey, error)

func VerifyRelease(ctx context.Context, body []byte, p Policy, version string, now time.Time, key ReleaseKey) (ReleaseAcceptance, error) {
	var zero ReleaseAcceptance
	var envelope ReleaseEnvelope
	if err := strictJSON(body, &envelope); err != nil {
		return zero, err
	}
	manifest, err := base64.StdEncoding.DecodeString(envelope.Manifest)
	if err != nil {
		return zero, errors.New("invalid release manifest encoding")
	}
	var m ReleaseManifest
	if err := strictJSON(manifest, &m); err != nil {
		return zero, err
	}
	if err := m.Check(p, version); err != nil {
		return zero, err
	}
	if len(envelope.Token) > 24<<10 {
		return zero, errors.New("release token exceeds limit")
	}
	sum := sha256.Sum256(manifest)
	claims := actionsClaims{}
	_, err = jwt.ParseWithClaims(envelope.Token, &claims, func(token *jwt.Token) (any, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" || len(kid) > 128 {
			return nil, errors.New("missing Actions signing key")
		}
		return key(ctx, kid)
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(actionsIssuer), jwt.WithAudience(fmt.Sprintf("komizo-release:sha256:%x", sum)), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(5*time.Second), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil {
		return zero, errors.New("release Actions identity verification failed")
	}
	if claims.Repository != p.SourceRepository || claims.RepositoryID != p.RepositoryID || claims.Ref != "refs/heads/main" || claims.SHA != version ||
		claims.WorkflowRef != p.SourceRepository+"/.github/workflows/cd.yml@refs/heads/main" || claims.WorkflowSHA != version || claims.RunID != m.RunID ||
		(claims.EventName != "push" && claims.EventName != "workflow_dispatch") || (claims.RunnerEnvironment != "github-hosted" && claims.RunnerEnvironment != "self-hosted") || claims.IssuedAt == nil || claims.NotBefore == nil ||
		now.Sub(claims.IssuedAt.Time) > 10*time.Minute || claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time) > 10*time.Minute || !releaseSubject(claims.Subject, p) {
		return zero, errors.New("release Actions context is not the approved main workflow")
	}
	evidence := sha256.Sum256(body)
	return ReleaseAcceptance{Manifest: m, VerifiedAt: now, Authority: actionsIssuer, EvidenceSHA256: fmt.Sprintf("%x", evidence)}, nil
}

// GitHubReleaseKey fetches only the issuer's fixed HTTPS JWKS. Tokens cannot
// choose a URL, and no registry credential is sent to this public endpoint.
func GitHubReleaseKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("JWKS redirect refused") }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, actionsIssuer+"/.well-known/jwks", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("Actions signing keys unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("Actions signing keys unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, ReleaseMaxBytes+1))
	if err != nil || len(body) > ReleaseMaxBytes {
		return nil, errors.New("invalid Actions signing key response")
	}
	var set struct {
		Keys []struct{ Kty, Use, Kid, Alg, N, E string }
	}
	if json.Unmarshal(body, &set) != nil || len(set.Keys) > 64 {
		return nil, errors.New("invalid Actions signing key set")
	}
	for _, jwk := range set.Keys {
		if jwk.Kid != kid || jwk.Kty != "RSA" || jwk.Use != "sig" || (jwk.Alg != "" && jwk.Alg != "RS256") {
			continue
		}
		n, errN := base64.RawURLEncoding.DecodeString(jwk.N)
		e, errE := base64.RawURLEncoding.DecodeString(jwk.E)
		if errN != nil || errE != nil || len(n) < 256 || len(n) > 1024 || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("invalid Actions RSA key")
		}
		exp := new(big.Int).SetBytes(e).Int64()
		if exp < 3 || exp > 1<<31-1 || exp%2 == 0 {
			return nil, errors.New("invalid Actions RSA exponent")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exp)}, nil
	}
	return nil, errors.New("Actions signing key not found")
}

func releaseSubject(subject string, p Policy) bool {
	suffixes := []string{":ref:refs/heads/main", ":environment:production", ":environment:Production"}
	for _, suffix := range suffixes {
		if subject == "repo:"+p.SourceRepository+suffix {
			return true
		}
		owner, repo, _ := strings.Cut(p.SourceRepository, "/")
		pattern := `^repo:` + regexp.QuoteMeta(owner) + `@[1-9][0-9]*/` + regexp.QuoteMeta(repo) + `@` + regexp.QuoteMeta(p.RepositoryID) + regexp.QuoteMeta(suffix) + `$`
		if regexp.MustCompile(pattern).MatchString(subject) {
			return true
		}
	}
	return false
}

func (a ReleaseAcceptance) Check(p Policy, version string) error {
	switch a.Authority {
	case actionsIssuer:
		return a.Manifest.Check(p, version)
	case "operator-bootstrap":
		return a.Manifest.check(p, version, false)
	default:
		return errors.New("unknown host release authority")
	}
}
