package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestDeliveryCachedOrEmptyProofCannotSkipAuthorization(t *testing.T) {
	root := t.TempDir()
	p := workload.Policy{App: "example", SourceRepository: "owner/example", RepositoryID: "123", RequireDeliveryAuthorization: true}
	version := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	// Even corrupt cached evidence must not be read before the protected grant.
	cached := filepath.Join(root, version+".json")
	if err := os.WriteFile(cached, []byte("untrusted cached evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "accepted.json")
	for _, proof := range []string{"", "komizo-release/v1:untrusted"} {
		err := admitWorkloadReleaseFrom(p, version, root, output, bytes.NewBufferString(proof))
		if err == nil || !strings.Contains(err.Error(), "protected delivery authorization is missing") {
			t.Fatalf("authorization fence skipped: %v", err)
		}
		entries, _ := os.ReadDir(root)
		if len(entries) != 1 {
			t.Fatal("refused admission modified the store")
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

func TestNamedTaskProofCannotSkipProtectedDeliveryAuthorization(t *testing.T) {
	p := workload.Policy{App: "example", SourceRepository: "owner/example", RepositoryID: "123", RequireDeliveryAuthorization: true}
	manifest, _ := json.Marshal(workload.ReleaseManifest{Revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
	body, _ := json.Marshal(workload.ReleaseEnvelope{Manifest: base64.StdEncoding.EncodeToString(manifest)})
	wire := []byte("komizo-release/v1:" + base64.StdEncoding.EncodeToString(body))
	err := verifyTaskRelease(context.Background(), p, wire)
	if err == nil || !strings.Contains(err.Error(), "protected delivery authorization is missing") {
		t.Fatalf("task source fence skipped: %v", err)
	}
}
