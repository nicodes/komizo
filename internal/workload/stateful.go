package workload

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
)

var contractIdentity = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$`)
var contractChecksum = regexp.MustCompile(`^[a-f0-9]{64}$`)

// StatefulContract describes the binary's data and credential-grant interface.
// CredentialRevision identifies that interface, never a key or key contents.
// Migration execution remains product-owned. An image rollback never grants
// authority to restore data, and a declaration alone cannot enable automation.
type StatefulContract struct {
	Version            int                 `json:"version"`
	SourceRevision     string              `json:"source_revision"`
	Schema             SchemaRange         `json:"schema"`
	DataRevision       string              `json:"data_revision"`
	CredentialRevision string              `json:"credential_revision"`
	Migrations         []MigrationIdentity `json:"migrations"`
	RecoveryAction     string              `json:"recovery_action"`
}
type SchemaRange struct {
	Minimum int `json:"minimum"`
	Maximum int `json:"maximum"`
	Write   int `json:"write"`
}
type MigrationIdentity struct {
	Identity string `json:"identity"`
	SHA256   string `json:"sha256"`
}

func (c StatefulContract) Check(revision string) error {
	if c.Version != 1 || !commitID.MatchString(c.SourceRevision) || c.SourceRevision != revision || !contractIdentity.MatchString(c.DataRevision) || !contractIdentity.MatchString(c.CredentialRevision) || len(c.Migrations) < 1 || len(c.Migrations) > 128 {
		return errors.New("invalid stateful release identity")
	}
	if c.Schema.Minimum < 1 || c.Schema.Maximum > 1000000 || c.Schema.Minimum > c.Schema.Write || c.Schema.Write > c.Schema.Maximum {
		return errors.New("invalid required schema range")
	}
	if c.RecoveryAction != "forward_only" && c.RecoveryAction != "image_rollback" {
		return errors.New("unsupported data recovery authority")
	}
	names := make(map[string]bool)
	for _, m := range c.Migrations {
		if !contractIdentity.MatchString(m.Identity) || !contractChecksum.MatchString(m.SHA256) || names[m.Identity] {
			return errors.New("invalid or duplicate migration identity/checksum")
		}
		names[m.Identity] = true
	}
	return nil
}

func (c StatefulContract) SHA256() (string, error) {
	if err := c.Check(c.SourceRevision); err != nil {
		return "", err
	}
	// Canonical map encoding matches the reusable producer's sorted compact
	// JSON. ASCII-only identifiers avoid cross-runtime Unicode/HTML escaping.
	body, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	var value map[string]any
	if err := json.Unmarshal(body, &value); err != nil {
		return "", err
	}
	body, err = json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

// SupportsPostWriteState refuses a rollback binary that cannot read and write
// the observed schema or grant/data interface. Exact fixture evidence remains
// an additional prerequisite in the reusable rollback decision, not inferred
// from this compatibility declaration or an encrypted backup.
func (c StatefulContract) SupportsPostWriteState(current StatefulContract, observedSchema int) error {
	if err := c.Check(c.SourceRevision); err != nil {
		return err
	}
	if err := current.Check(current.SourceRevision); err != nil {
		return err
	}
	if observedSchema != current.Schema.Write || observedSchema < c.Schema.Minimum || observedSchema > c.Schema.Maximum || c.DataRevision != current.DataRevision || c.CredentialRevision != current.CredentialRevision {
		return errors.New("rollback target does not support post-write state")
	}
	new := make(map[string]string)
	for _, m := range current.Migrations {
		new[m.Identity] = m.SHA256
	}
	for _, m := range c.Migrations {
		if new[m.Identity] != m.SHA256 {
			return errors.New("applied migration changed or disappeared")
		}
	}
	return nil
}
