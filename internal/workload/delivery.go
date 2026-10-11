package workload

import (
	"errors"
	"time"
)

// DeliveryAuthorization is issued by the root operator after observing the
// actual merge and its immutable CI integration. Workflow code cannot issue it.
// The separately authenticated release envelope binds shipping image digests.
type DeliveryAuthorization struct {
	Version               int       `json:"version"`
	Repository            string    `json:"repository"`
	RepositoryID          string    `json:"repository_id"`
	App                   string    `json:"app"`
	Revision              string    `json:"revision"`
	Tree                  string    `json:"tree"`
	Head                  string    `json:"head"`
	Base                  string    `json:"base"`
	CIRunID               int64     `json:"ci_run_id"`
	CIAttempt             int       `json:"ci_attempt"`
	IntegrationArtifactID int64     `json:"integration_artifact_id"`
	InputsSHA256          string    `json:"inputs_sha256"`
	Kind                  string    `json:"kind"`
	Scope                 string    `json:"scope"`
	IssuedAt              time.Time `json:"issued_at"`
	ExpiresAt             time.Time `json:"expires_at"`
}

func (a DeliveryAuthorization) Check(p Policy, revision string, now time.Time) error {
	if a.Version != 1 || a.Repository != p.SourceRepository || a.RepositoryID != p.RepositoryID ||
		a.App != p.App || a.Revision != revision || !commitID.MatchString(a.Revision) ||
		!commitID.MatchString(a.Tree) || !commitID.MatchString(a.Head) || !commitID.MatchString(a.Base) ||
		a.CIRunID <= 0 || a.CIAttempt <= 0 || a.IntegrationArtifactID <= 0 ||
		!contentIdentity.MatchString(a.InputsSHA256) || (a.Kind != "merge" && a.Kind != "owner") ||
		a.Scope != "production-delivery" || a.IssuedAt.After(now) || !a.ExpiresAt.After(now) ||
		!a.ExpiresAt.After(a.IssuedAt) || a.ExpiresAt.Sub(a.IssuedAt) > 4*time.Hour {
		return errors.New("delivery authorization identity, scope or lifetime differs")
	}
	return nil
}
