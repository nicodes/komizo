package workload

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func backupProof(t *testing.T, p Policy, m BackupManifest, key *rsa.PrivateKey, now time.Time, alter func(jwt.MapClaims)) []byte {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	claims := jwt.MapClaims{"iss": actionsIssuer, "aud": fmt.Sprintf("komizo-operation:sha256:%x", sum), "sub": "repo:" + p.SourceRepository + ":ref:refs/heads/main",
		"repository": p.SourceRepository, "repository_id": p.RepositoryID, "ref": "refs/heads/main", "sha": m.Revision,
		"workflow_ref": p.SourceRepository + "/.github/workflows/backup.yml@refs/heads/main", "workflow_sha": m.Revision,
		"job_workflow_ref": p.RoutineBackup.WorkflowRepository + "/.github/workflows/backup.yml@" + p.RoutineBackup.WorkflowRevision, "job_workflow_sha": p.RoutineBackup.WorkflowRevision,
		"run_id": m.RunID, "run_attempt": m.Attempt, "event_name": "schedule", "runner_environment": "github-hosted", "jti": "synthetic-token",
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}
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

func TestBackupPurposeServingSourceAndReusableWorkflow(t *testing.T) {
	p, release, key, now := releaseFixture(t)
	p.RoutineBackup = &BackupPolicy{WorkflowRepository: "operator/tools", WorkflowRevision: strings.Repeat("b", 40), ProgramSHA256: strings.Repeat("c", 64), TimeoutSeconds: 900}
	m := BackupManifest{Version: 1, Purpose: "routine-backup", Repository: p.SourceRepository, RepositoryID: p.RepositoryID, Revision: release.Revision, RunID: "12345", Attempt: "2"}
	keyFn := func(context.Context, string) (*rsa.PublicKey, error) { return &key.PublicKey, nil }
	good := backupProof(t, p, m, key, now, nil)
	a, err := VerifyBackup(context.Background(), good, p, m.Revision, now, keyFn)
	if err != nil || a.Manifest != m || a.EvidenceSHA256 == "" {
		t.Fatalf("approved routine backup refused: %v", err)
	}
	for field, value := range map[string]any{"repository": "attacker/source", "repository_id": "999", "ref": "refs/pull/1/merge", "sha": strings.Repeat("f", 40),
		"workflow_ref": p.SourceRepository + "/.github/workflows/cd.yml@refs/heads/main", "workflow_sha": strings.Repeat("f", 40),
		"job_workflow_ref": "attacker/tools/.github/workflows/backup.yml@" + p.RoutineBackup.WorkflowRevision, "job_workflow_sha": strings.Repeat("f", 40),
		"run_id": "999", "run_attempt": "3", "event_name": "push", "runner_environment": "self-hosted", "jti": "", "sub": "",
		"iat": now.Add(time.Minute).Unix(), "nbf": now.Add(time.Minute).Unix(), "exp": now.Add(-time.Minute).Unix(), "aud": "komizo-release:sha256:unbound"} {
		t.Run(field, func(t *testing.T) {
			proof := backupProof(t, p, m, key, now, func(c jwt.MapClaims) { c[field] = value })
			if _, err := VerifyBackup(context.Background(), proof, p, m.Revision, now, keyFn); err == nil {
				t.Fatalf("accepted foreign backup %s", field)
			}
		})
	}
	if _, err := VerifyBackup(context.Background(), good, p, strings.Repeat("d", 40), now, keyFn); err == nil {
		t.Fatal("old serving revision authorized a new source")
	}
	if _, err := VerifyBackup(context.Background(), good, p, m.Revision, now.Add(6*time.Minute), keyFn); err == nil {
		t.Fatal("expired token authorized a backup")
	}
	long := backupProof(t, p, m, key, now, func(c jwt.MapClaims) { c["exp"] = now.Add(11 * time.Minute).Unix() })
	if _, err := VerifyBackup(context.Background(), long, p, m.Revision, now, keyFn); err == nil {
		t.Fatal("unbounded token lifetime accepted")
	}
	// A valid release proof has no routine-backup authority, even with identical
	// repository/source. The operation's audience and declared purpose differ.
	if _, err := VerifyBackup(context.Background(), releaseProof(t, p, release, key, now, nil), p, m.Revision, now, keyFn); err == nil {
		t.Fatal("CD proof borrowed routine-backup authority")
	}
	called := false
	noNetwork := func(context.Context, string) (*rsa.PublicKey, error) { called = true; return &key.PublicKey, nil }
	m.Purpose = "restore"
	if _, err := VerifyBackup(context.Background(), backupProof(t, p, m, key, now, nil), p, m.Revision, now, noNetwork); err == nil || called {
		t.Fatal("recovery operation reached signing-key lookup")
	}
	p.RoutineBackup = nil
	if _, err := VerifyBackup(context.Background(), good, p, release.Revision, now, noNetwork); err == nil || called {
		t.Fatal("missing protected capability reached signing-key lookup")
	}
}
