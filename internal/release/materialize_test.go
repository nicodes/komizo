package release

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestBindSecretVersionsUsesOnlyHostEvidence(t *testing.T) {
	f := modelFixture()
	fixtureService(f, "api")["environment"] = map[string]any{"TOKEN": "${TOKEN}"}
	f["x-komizo"].(map[string]any)["secret_versions"] = map[string]any{"TOKEN": "artifact-claim"}
	raw, _ := json.Marshal(f)
	bound, err := BindSecretVersions(raw, map[string]string{"TOKEN": "host-version"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(bound, []byte("artifact-claim")) || !bytes.Contains(bound, []byte("host-version")) {
		t.Fatalf("host version was not authoritative: %s", bound)
	}
	if _, err := Resolve(bound, bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatal(err)
	}
}

func TestBindSecretVersionsRequiresExactInventory(t *testing.T) {
	f := modelFixture()
	raw, _ := json.Marshal(f)
	for _, versions := range []map[string]string{{"extra": "v1"}, {"missing": ""}} {
		if _, err := BindSecretVersions(raw, versions); err == nil {
			t.Fatalf("accepted mismatched versions: %#v", versions)
		}
	}
	if _, err := BindSecretVersions([]byte(`{"x-komizo":{},"x-komizo":{}}`), nil); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("ambiguous input accepted or reflected: %v", err)
	}
}

func TestBindSecretVersionsRejectsModelSelectedSecretFilesAndInterpolation(t *testing.T) {
	f := modelFixture()
	f["secrets"] = map[string]any{"token": map[string]any{"file": "/etc/shadow"}}
	fixtureService(f, "api")["secrets"] = []any{map[string]any{"source": "token", "target": "token"}}
	raw, _ := json.Marshal(f)
	if _, err := BindSecretVersions(raw, map[string]string{"token": "host-version"}); err == nil {
		t.Fatal("model-selected host secret file was accepted")
	}

	delete(f, "secrets")
	delete(fixtureService(f, "api"), "secrets")
	fixtureService(f, "api")["environment"] = map[string]any{"TOKEN": "prefix-${TOKEN}"}
	raw, _ = json.Marshal(f)
	if _, err := BindSecretVersions(raw, map[string]string{"TOKEN": "host-version"}); err == nil {
		t.Fatal("non-exact secret interpolation was accepted")
	}
}
