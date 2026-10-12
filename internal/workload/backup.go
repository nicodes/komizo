package workload

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// BackupPolicy grants only ciphertext export through an operator-installed
// program. It conveys no deployment, arbitrary task or recovery-key authority.
type BackupPolicy struct {
	WorkflowRepository string `json:"workflow_repository"`
	WorkflowRevision   string `json:"workflow_revision"`
	ProgramSHA256      string `json:"program_sha256"`
	TimeoutSeconds     int    `json:"timeout_seconds"`
}

func (p BackupPolicy) Check() error {
	if !repositoryName.MatchString(p.WorkflowRepository) || !commitID.MatchString(p.WorkflowRevision) ||
		!contentIdentity.MatchString(p.ProgramSHA256) || p.TimeoutSeconds < 1 || p.TimeoutSeconds > 900 {
		return errors.New("backup authority needs an immutable reusable workflow, fixed program and finite deadline")
	}
	return nil
}

type BackupManifest struct {
	Version      int    `json:"version"`
	Purpose      string `json:"purpose"`
	Repository   string `json:"repository"`
	RepositoryID string `json:"repository_id"`
	Revision     string `json:"revision"`
	RunID        string `json:"run_id"`
	Attempt      string `json:"attempt"`
}

type BackupAcceptance struct {
	Manifest       BackupManifest `json:"manifest"`
	VerifiedAt     time.Time      `json:"verified_at"`
	ExpiresAt      time.Time      `json:"expires_at"`
	EvidenceSHA256 string         `json:"evidence_sha256"`
}

// VerifyBackup is purpose-specific. A current-main backup run never borrows or
// renews an expiring delivery grant. The caller, called workflow and serving
// source must all match protected authority before any host operation begins.
func VerifyBackup(ctx context.Context, body []byte, p Policy, serving string, now time.Time, key ReleaseKey) (BackupAcceptance, error) {
	var zero BackupAcceptance
	if err := p.Check(); err != nil {
		return zero, err
	}
	if p.RoutineBackup == nil {
		return zero, errors.New("routine backup has no protected capability")
	}
	var envelope ReleaseEnvelope
	if err := strictJSON(body, &envelope); err != nil {
		return zero, err
	}
	raw, err := base64.StdEncoding.DecodeString(envelope.Manifest)
	if err != nil {
		return zero, errors.New("invalid backup manifest encoding")
	}
	var m BackupManifest
	if err := strictJSON(raw, &m); err != nil {
		return zero, err
	}
	if m.Version != 1 || m.Purpose != "routine-backup" || m.Repository != p.SourceRepository || m.RepositoryID != p.RepositoryID ||
		!commitID.MatchString(serving) || m.Revision != serving || !numericID.MatchString(m.RunID) || !numericID.MatchString(m.Attempt) || len(envelope.Token) > 24<<10 {
		return zero, errors.New("backup identity differs from the accepted serving source and scope")
	}
	sum := sha256.Sum256(raw)
	claims := actionsClaims{}
	_, err = jwt.ParseWithClaims(envelope.Token, &claims, func(token *jwt.Token) (any, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" || len(kid) > 128 {
			return nil, errors.New("missing Actions signing key")
		}
		return key(ctx, kid)
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(actionsIssuer), jwt.WithAudience(fmt.Sprintf("komizo-operation:sha256:%x", sum)), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(5*time.Second), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil {
		return zero, errors.New("backup Actions identity verification failed")
	}
	called := p.RoutineBackup.WorkflowRepository + "/.github/workflows/backup.yml@" + p.RoutineBackup.WorkflowRevision
	if claims.Repository != p.SourceRepository || claims.RepositoryID != p.RepositoryID || claims.Ref != "refs/heads/main" || claims.SHA != serving ||
		claims.WorkflowRef != p.SourceRepository+"/.github/workflows/backup.yml@refs/heads/main" || claims.WorkflowSHA != serving ||
		claims.JobWorkflowRef != called || claims.JobWorkflowSHA != p.RoutineBackup.WorkflowRevision || claims.RunID != m.RunID || claims.RunAttempt != m.Attempt ||
		(claims.EventName != "schedule" && claims.EventName != "workflow_dispatch") || claims.RunnerEnvironment != "github-hosted" ||
		claims.IssuedAt == nil || claims.NotBefore == nil || claims.ID == "" || len(claims.ID) > 128 || strings.ContainsAny(claims.ID, "\x00\r\n") ||
		!claims.ExpiresAt.Time.After(now) || now.Sub(claims.IssuedAt.Time) > 10*time.Minute || claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time) > 10*time.Minute || !releaseSubject(claims.Subject, p) {
		return zero, errors.New("backup Actions context is not the approved routine workflow")
	}
	evidence := sha256.Sum256(body)
	return BackupAcceptance{Manifest: m, VerifiedAt: now, ExpiresAt: claims.ExpiresAt.Time, EvidenceSHA256: fmt.Sprintf("%x", evidence)}, nil
}
