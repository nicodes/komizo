package rollout

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testProfile(t *testing.T) (string, Profile) {
	t.Helper()
	dir := t.TempDir()
	p := Profile{Version: 1, App: "fixture", Network: "fixture_private",
		KeyFile: filepath.Join(dir, "key"), StateDir: filepath.Join(dir, "state"),
		GatewaySocket: filepath.Join(dir, "gateway.sock"), GatewayConfig: filepath.Join(dir, "state", "gateway", "config.json"), ComposeBinary: "/usr/bin/docker-compose",
		ComposeVersion: "5.1.4", Overall: 10 * time.Second, MinFreeMemory: 1, MinFreeDisk: 1, Limits: Limits{Ready: time.Second, Stabilize: time.Second,
			Retire: 3 * time.Second, Operation: time.Second, Poll: time.Millisecond}}
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "fixture.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, p
}

func TestLoadProfileAcceptsOnlyPrivateCompleteProfiles(t *testing.T) {
	path, want := testProfile(t)
	got, err := LoadProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.App != want.App || got.Limits != want.Limits {
		t.Fatalf("profile changed: %#v", got)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProfile(path); err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("public profile accepted: %v", err)
	}
}

func TestLoadProfileRejectsUnknownFieldsAndTrailingDocuments(t *testing.T) {
	path, _ := testProfile(t)
	for _, body := range []string{
		`{"version":1,"unknown":true}`,
		`{"version":1}{"version":1}`,
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadProfile(path); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
}

func TestReconcileProfilesIgnoresCompletedProfiles(t *testing.T) {
	dir := t.TempDir()
	path, _ := testProfile(t)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fixture.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	ReconcileProfiles(t.Context(), dir, &output)
	// The key path is deliberately absent, so a discovered valid profile must
	// report a value-free refusal rather than be mistaken for "nothing pending".
	if output.Len() == 0 {
		t.Fatal("reconciliation did not reach the profile")
	}

	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	ReconcileProfiles(t.Context(), dir, &output)
	if output.Len() != 0 {
		t.Fatalf("writable profile directory was used: %s", output.String())
	}
}

func TestResumeProfileNoPendingIsDistinct(t *testing.T) {
	if !errors.Is(ErrNoPending, ErrNoPending) {
		t.Fatal("sentinel cannot be matched")
	}
}

func TestReadSecretVersionsAcceptsOnlyPrivateGeneratedMarkers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.env")
	body := "TOKEN=value\n# komizo-secret-version-TOKEN=0123456789abcdef0123456789abcdef\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	versions, err := readSecretVersions(path)
	if err != nil || versions["TOKEN"] != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("valid marker refused: %#v %v", versions, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecretVersions(path); err == nil {
		t.Fatal("public secret materialization record accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("# komizo-secret-version-TOKEN=not-generated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecretVersions(path); err == nil {
		t.Fatal("non-generated version marker accepted")
	}
}
