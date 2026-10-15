package main

import (
	"testing"

	"github.com/nicodes/komizo/internal/workload"
)

func TestSetupBootstrapCannotReplaceEstablishedAuthority(t *testing.T) {
	base, err := workload.NewPolicy("mailroom", "/srv/mailroom", "ghcr.io/courier/mailroom-config", "edge")
	if err != nil {
		t.Fatal(err)
	}
	next := base
	next.SourceRepository = "courier/source"
	next.RepositoryID = "123"
	if err := checkBootstrapPolicy(base, base, next, false); err != nil {
		t.Fatal(err)
	}
	if err := checkBootstrapPolicy(base, next, next, true); err != nil {
		t.Fatal("identical established authority must remain usable", err)
	}
	changed := next
	changed.RepositoryID = "456"
	if err := checkBootstrapPolicy(base, next, changed, false); err == nil {
		t.Fatal("established authority replaced")
	}
	if err := checkBootstrapPolicy(base, base, next, true); err == nil {
		t.Fatal("operation fence bypassed")
	}
	foreign := next
	foreign.App = "other"
	if err := checkBootstrapPolicy(base, base, foreign, false); err == nil {
		t.Fatal("cross-app authority accepted")
	}
}
