package main

import (
	"strings"
	"testing"

	"github.com/nicodes/komizo/internal/workload"
)

func TestBootstrapDistinguishesRegistrationScaffoldFromServingState(t *testing.T) {
	for _, tc := range []struct {
		compose, env             string
		record, serving, invalid bool
	}{
		{"services: {}\n", "", false, false, false},
		{"services: {}\n", "APP_VERSION=\n", false, false, false},
		{"services: {}\n", "APP_VERSION=" + strings.Repeat("a", 40) + "\n", false, true, false},
		{"services: {}\n", "APP_VERSION=\nAPP_VERSION=\n", false, true, true},
		{"services: {web: {image: existing}}\n", "", false, true, false},
		{"services: {}\n", "", true, true, false},
		{"", "", false, true, false},
	} {
		serving, err := bootstrapServingState([]byte(tc.compose), []byte(tc.env), tc.record)
		if serving != tc.serving || (err != nil) != tc.invalid {
			t.Fatalf("%+v: serving=%v error=%v", tc, serving, err)
		}
	}
}

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
