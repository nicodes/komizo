package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nicodes/komizo/internal/workload"
)

func TestDeliveryMissingAuthorizationRefusesBeforeProofAdmissionOrWrites(t *testing.T) {
	root := t.TempDir()
	p := workload.Policy{App: "example", SourceRepository: "owner/example", RepositoryID: "123", RequireDeliveryAuthorization: true}
	version := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	output := filepath.Join(root, "accepted.json")
	err := admitWorkloadReleaseFrom(p, version, root, output, bytes.NewBufferString("komizo-release/v1:untrusted"))
	if err == nil {
		t.Fatal("unauthorized source accepted")
	}
	if entries, _ := os.ReadDir(root); len(entries) != 0 {
		t.Fatal("unauthorized admission caused writes")
	}
	for _, invalid := range []string{"../../etc/shadow", "", "a"} {
		if err := checkDeliveryAuthorizationAt(p, invalid, time.Now(), root); err == nil {
			t.Fatal("invalid authorization source accepted")
		}
	}
}

func TestDeliverySecretSetRejectsIncompleteOrUnrepresentableInputs(t *testing.T) {
	if err := validateSecretSet(map[string]string{"API_KEY": "synthetic"}); err != nil {
		t.Fatal(err)
	}
	for _, values := range []map[string]string{nil, {"API_KEY": ""}, {"API_KEY": "line\nbreak"}, {"GITHUB_TOKEN": "fixture"}, {"../escape": "fixture"}} {
		if err := validateSecretSet(values); err == nil {
			t.Fatal("invalid set accepted")
		}
	}
}
