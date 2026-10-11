package workload

import (
	"testing"
	"time"
)

func TestDeliveryAuthorizationBindsActualSourceScopeAndDeadline(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	p := Policy{App: "example", SourceRepository: "owner/example", RepositoryID: "123"}
	a := DeliveryAuthorization{Version: 1, Repository: p.SourceRepository, RepositoryID: p.RepositoryID, App: p.App,
		Revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Tree: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Head: "cccccccccccccccccccccccccccccccccccccccc", Base: "dddddddddddddddddddddddddddddddddddddddd",
		CIRunID: 42, CIAttempt: 2, IntegrationArtifactID: 55, InputsSHA256: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		Kind: "merge", Scope: "production-delivery", IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := a.Check(p, a.Revision, now); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*DeliveryAuthorization){
		func(a *DeliveryAuthorization) { a.Revision = a.Head }, func(a *DeliveryAuthorization) { a.App = "foreign" },
		func(a *DeliveryAuthorization) { a.RepositoryID = "999" }, func(a *DeliveryAuthorization) { a.Scope = "all" },
		func(a *DeliveryAuthorization) { a.ExpiresAt = now }, func(a *DeliveryAuthorization) { a.ExpiresAt = now.Add(5 * time.Hour) },
		func(a *DeliveryAuthorization) { a.IssuedAt = now.Add(time.Minute) }, func(a *DeliveryAuthorization) { a.IntegrationArtifactID = 0 },
	} {
		bad := a
		change(&bad)
		if err := bad.Check(p, a.Revision, now); err == nil {
			t.Fatal("foreign/expired authority accepted")
		}
	}
	a.Kind = "owner"
	if err := a.Check(p, a.Revision, now); err != nil {
		t.Fatal("explicit reviewed owner route unavailable", err)
	}
}
