package rollout

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/internal/release"
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

func TestProvisionProfileCreatesOnlyScopedAuthorityAndRefusesPolicyReplacement(t *testing.T) {
	root := t.TempDir()
	roots := provisionRoots{
		Profiles: filepath.Join(root, "etc", "komizo", "rollouts"),
		Keys:     filepath.Join(root, "etc", "komizo", "rollout-keys"),
		States:   filepath.Join(root, "var", "lib", "komizo", "rollouts"),
		Gateways: filepath.Join(root, "run", "komizo", "gateways"),
	}
	_, p := testProfile(t)
	p.App = "cazper"
	p.KeyFile = filepath.Join(roots.Keys, "cazper.key")
	p.StateDir = filepath.Join(roots.States, "cazper")
	p.GatewaySocket = filepath.Join(roots.Gateways, "cazper", "admin.sock")
	p.GatewayConfig = filepath.Join(p.StateDir, "gateway", "config.json")
	source := filepath.Join(root, "candidate.json")
	body, _ := json.Marshal(p)
	if err := os.WriteFile(source, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := provisionProfile(source, "cazper", roots); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(p.KeyFile)
	if err != nil || len(key) != 32 {
		t.Fatalf("identity key was not generated privately: len=%d err=%v", len(key), err)
	}
	for _, path := range []string{p.KeyFile, filepath.Join(roots.Profiles, "cazper.json"), p.GatewayConfig} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Errorf("%s is missing: %v", path, err)
			continue
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Errorf("%s is not a private regular authority file: %#o", path, info.Mode().Perm())
		}
	}
	if _, err := LoadProfile(filepath.Join(roots.Profiles, "cazper.json")); err != nil {
		t.Fatalf("installed profile does not load: %v", err)
	}
	if err := provisionProfile(source, "cazper", roots); err != nil {
		t.Fatalf("identical reprovision was not idempotent: %v", err)
	}
	p.Overall++
	body, _ = json.Marshal(p)
	if err := os.WriteFile(source, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := provisionProfile(source, "cazper", roots); err == nil || !strings.Contains(err.Error(), "policy") {
		t.Fatalf("changed policy replaced without explicit authorization: %v", err)
	}
}

func TestProvisionProfileRefusesPathsOutsideTheAppScope(t *testing.T) {
	root := t.TempDir()
	roots := provisionRoots{filepath.Join(root, "profiles"), filepath.Join(root, "keys"), filepath.Join(root, "states"), filepath.Join(root, "gateways")}
	path, p := testProfile(t)
	p.App = "cazper"
	p.KeyFile = filepath.Join(roots.Keys, "other.key")
	p.StateDir = filepath.Join(roots.States, "cazper")
	p.GatewaySocket = filepath.Join(roots.Gateways, "cazper", "admin.sock")
	p.GatewayConfig = filepath.Join(p.StateDir, "gateway", "config.json")
	body, _ := json.Marshal(p)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := provisionProfile(path, "cazper", roots); err == nil || !strings.Contains(err.Error(), "scoped") {
		t.Fatalf("unscoped authority paths accepted: %v", err)
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

func TestScopedResumeRejectsAnotherAppAndAbsentJournal(t *testing.T) {
	path, profile := testProfile(t)
	if _, err := ResumeProfileForApp(t.Context(), path, "another", strings.NewReader("")); err == nil || !strings.Contains(err.Error(), "broker application scope") {
		t.Fatalf("another app used the fixed profile: %v", err)
	}
	if _, err := ResumeProfileForApp(t.Context(), path, "../fixture", strings.NewReader("")); err == nil || !strings.Contains(err.Error(), "invalid rollout broker scope") {
		t.Fatalf("invalid broker app accepted: %v", err)
	}
	if err := os.WriteFile(profile.KeyFile, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResumeProfileForApp(t.Context(), path, "fixture", strings.NewReader("")); !errors.Is(err, ErrNoPending) {
		t.Fatalf("absent journal did not fail distinctly: %v", err)
	}
}

func TestRegistryCredentialProtocolIsExactBoundedAndClearable(t *testing.T) {
	username, token, err := readRegistryCredentials(strings.NewReader("workflow-actor\nworkflow-token\n"))
	if err != nil || username != "workflow-actor" || string(token) != "workflow-token" {
		t.Fatalf("valid credential protocol: user=%q token=%q err=%v", username, token, err)
	}
	clear(token)
	if strings.Trim(string(token), "\x00") != "" {
		t.Fatal("token copy could not be cleared")
	}
	for _, input := range []string{
		"", "actor\ntoken", "actor\ntoken\nextra\n", "../actor\ntoken\n", "actor\ntok\nen\n",
		"actor\n" + strings.Repeat("x", 16<<10+1) + "\n", strings.Repeat("x", 64<<10+1),
	} {
		if _, token, err := readRegistryCredentials(strings.NewReader(input)); err == nil || token != nil {
			t.Fatalf("invalid credential protocol accepted: length=%d", len(input))
		}
	}
}

func TestPendingRegistryScopeComesOnlyFromAllSignedCandidates(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	source := sourceModel("b")
	tx := &Transaction{Network: "app-private", Source: source, Candidates: map[string]Instance{
		"api": {Name: "kmz-0123456789abcdef0123456789abcdef01234567", App: "app", Service: "api", Generation: "generation", Identity: "identity", Mode: "request", Port: 8080, ReadyPath: "/readyz", Lifecycle: &release.Lifecycle{Version: 1, Command: []string{"/fixture", "lifecycle"}}},
		"ui":  {Name: "kmz-1123456789abcdef0123456789abcdef01234567", App: "app", Service: "ui", Generation: "generation", Identity: "identity", Mode: "static", Port: 8080, ReadyPath: "/readyz", Lifecycle: &release.Lifecycle{Version: 1, Command: []string{"/fixture", "lifecycle"}}},
	}}
	if registry, err := pendingRegistry(tx, key); err != nil || registry != "docker.io" {
		t.Fatalf("derived registry=%q err=%v", registry, err)
	}
	tx.Source = bytes.Replace(source, []byte("example/ui@"), []byte("ghcr.io/owner/ui@"), 1)
	if _, err := pendingRegistry(tx, key); err == nil || !strings.Contains(err.Error(), "one fixed registry") {
		t.Fatalf("multiple registry authority accepted: %v", err)
	}
	for _, image := range []string{"", "private.example/repo:tag", "private.example@sha256:" + strings.Repeat("a", 64), "private.example/owner/repo@sha256:" + strings.Repeat("a", 63)} {
		if _, ok := imageRegistryHost(image); ok {
			t.Fatalf("invalid immutable image scope accepted: %q", image)
		}
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
