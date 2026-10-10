package workload

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func statefulFixture() StatefulContract {
	return StatefulContract{Version: 1, SourceRevision: strings.Repeat("a", 40), Schema: SchemaRange{Minimum: 1, Maximum: 2, Write: 2}, DataRevision: "records-v1", CredentialRevision: "runtime-grants-v1", Migrations: []MigrationIdentity{{Identity: "001.sql", SHA256: strings.Repeat("b", 64)}}, RecoveryAction: "forward_only"}
}

func TestStatefulContractCanonicalIdentityAndIncompatibleTargets(t *testing.T) {
	current := statefulFixture()
	hash, err := current.SHA256()
	if err != nil || hash != "e8e790b253bd846e99adc4d63d399272f932bd9193957c08dee80806c2fd8fc3" {
		t.Fatal("producer/host canonical contract differs", hash, err)
	}
	previous := current
	previous.SourceRevision = strings.Repeat("c", 40)
	previous.Schema.Write = 1
	if err := previous.SupportsPostWriteState(current, 2); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*StatefulContract){
		func(c *StatefulContract) { c.Schema.Maximum = 1 },
		func(c *StatefulContract) { c.CredentialRevision = "owner-grants-v0" },
		func(c *StatefulContract) { c.DataRevision = "records-v0" },
		func(c *StatefulContract) {
			c.Migrations = []MigrationIdentity{{Identity: "001.sql", SHA256: strings.Repeat("f", 64)}}
		},
	} {
		bad := previous
		change(&bad)
		if err := bad.SupportsPostWriteState(current, 2); err == nil {
			t.Fatal("incompatible rollback declaration accepted")
		}
	}
	if err := previous.SupportsPostWriteState(current, 3); err == nil {
		t.Fatal("unobserved schema inferred")
	}
}

func TestStatefulContractIsRequiredByPolicyAndAudienceBound(t *testing.T) {
	p, m, key, now := releaseFixture(t)
	p.RequireStatefulContract = true
	keyFn := func(context.Context, string) (*rsa.PublicKey, error) { return &key.PublicKey, nil }
	if _, err := VerifyRelease(context.Background(), releaseProof(t, p, m, key, now, nil), p, m.Revision, now, keyFn); err == nil {
		t.Fatal("stateful release accepted without its contract")
	}
	c := statefulFixture()
	m.StatefulContract = &c
	proof := releaseProof(t, p, m, key, now, nil)
	if _, err := VerifyRelease(context.Background(), proof, p, m.Revision, now, keyFn); err != nil {
		t.Fatal(err)
	}
	var wire ReleaseEnvelope
	if err := json.Unmarshal(proof, &wire); err != nil {
		t.Fatal(err)
	}
	m.StatefulContract.CredentialRevision = "changed-grants-v2"
	body, _ := json.Marshal(m)
	wire.Manifest = base64.StdEncoding.EncodeToString(body)
	tampered, _ := json.Marshal(wire)
	if _, err := VerifyRelease(context.Background(), tampered, p, m.Revision, now, keyFn); err == nil {
		t.Fatal("data/credential contract changed without matching release authority")
	}
	m.StatefulContract.SourceRevision = strings.Repeat("d", 40)
	if err := m.Check(p, m.Revision); err == nil {
		t.Fatal("contract from another candidate accepted")
	}
}

func TestStatefulContractsRejectAmbiguousOrDestructiveDeclarations(t *testing.T) {
	for _, change := range []func(*StatefulContract){
		func(c *StatefulContract) { c.Migrations = append(c.Migrations, c.Migrations[0]) },
		func(c *StatefulContract) { c.Schema.Write = 3 },
		func(c *StatefulContract) { c.RecoveryAction = "restore_snapshot" },
		func(c *StatefulContract) { c.CredentialRevision = "private key contents" },
	} {
		c := statefulFixture()
		change(&c)
		if err := c.Check(c.SourceRevision); err == nil {
			t.Fatal("unsafe declaration accepted")
		}
	}
	var c StatefulContract
	if err := strictJSON([]byte(`{"version":1,"version":1}`), &c); err == nil {
		t.Fatal("duplicate fields accepted")
	}
}
