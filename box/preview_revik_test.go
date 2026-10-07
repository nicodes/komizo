package box

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func revikImages() []string {
	var images []string
	for _, component := range []string{"gate", "api", "godot-api", "postgres"} {
		images = append(images, "ghcr.io/aviorstudio/fieldsofrevik-preview-"+component+":"+strings.Repeat("a", 40))
	}
	return images
}

func TestRevikPreviewRejectsMixedRevisionsAndProductionAuth(t *testing.T) {
	images := revikImages()
	images[2] = strings.ReplaceAll(images[2], strings.Repeat("a", 40), strings.Repeat("b", 40))
	if validateRevikPreviewImages(images) == nil || validateRevikPreviewImages(revikImages()[:3]) == nil {
		t.Fatal("accepted incomplete or mixed release")
	}
	path := filepath.Join(t.TempDir(), "stack.env")
	good := "CLERK_SECRET_KEY=sk_test_fixtureonly\nCLERK_ISSUER=https://fixture.clerk.accounts.dev\nCLERK_JWKS_URL=https://fixture.clerk.accounts.dev/.well-known/jwks.json\n"
	for _, bad := range []string{
		strings.Replace(good, "sk_test_", "sk_live_", 1),
		strings.ReplaceAll(good, "fixture.clerk.accounts.dev", "clerk.revik.gg"),
		good + "DATABASE_URL=production\n", good + "CLERK_SECRET_KEY=sk_test_duplicate\n",
	} {
		os.WriteFile(path, []byte(bad), 0600)
		if validateRevikPreviewAuth(path) == nil {
			t.Fatal("accepted non-preview configuration")
		}
	}
	os.WriteFile(path, []byte(good), 0600)
	if err := validateRevikPreviewAuth(path); err != nil {
		t.Fatal(err)
	}
}

func TestRevikPreviewOwnsItsServicesAndNeverTouchesSharedDatabase(t *testing.T) {
	cfg := previewTestConfig(t)
	dir := previewDir(cfg.Root, PreviewProject("fieldsofrevik", 321))
	os.MkdirAll(dir, 0750)
	os.WriteFile(filepath.Join(dir, "stack.env"), []byte("CLERK_SECRET_KEY=sk_test_fixtureonly\nCLERK_ISSUER=https://fixture.clerk.accounts.dev\nCLERK_JWKS_URL=https://fixture.clerk.accounts.dev/.well-known/jwks.json\n"), 0600)
	f := &fakeDocker{previewDBDown: true}
	r, err := PreviewUp(context.Background(), f.run, cfg, "fieldsofrevik", 321, revikImages(), previewNow)
	if err != nil {
		t.Fatal(err)
	}
	if r.DBName != "" || r.DBPassword == "" {
		t.Fatal("isolated profile must have private seed but no shared database")
	}
	compose, err := os.ReadFile(filepath.Join(dir, "compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(compose)
	for _, want := range []string{"  postgres:", "  migrate:", "  api:", "  godot-api:", "  redis:", "  gate:", "db: {internal: true}", "networks: [app, shared]", "127.0.0.1:", "env_file: [stack.env]", "TEST_MODE: \"false\""} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Contains(text, r.DBPassword) || strings.Contains(text, "app.revik.gg") || strings.Contains(text, "komizo-previews") {
		t.Fatal("seed or production/shared database reference in compose")
	}
	passwords := map[string]bool{}
	for _, role := range []string{"admin", "migrator", "runtime", "backup", "bridge"} {
		password := revikPreviewCredential(r.DBPassword, role)
		if passwords[password] || !strings.Contains(text, password) {
			t.Fatal("role credentials must be distinct and present")
		}
		passwords[password] = true
	}
	encoded, _ := json.Marshal(r)
	if strings.Contains(string(encoded), r.DBPassword) {
		t.Fatal("seed exposed in public record")
	}
	if err := PreviewDown(context.Background(), f.run, cfg, r); err != nil {
		t.Fatal(err)
	}
	for _, args := range f.calls {
		if strings.Contains(strings.Join(args, " "), PreviewDBContainer) {
			t.Fatal("Revik lifecycle touched the shared preview database")
		}
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("preview state survived teardown")
	}
}

func TestRevikPreviewComposeParsesWithPrivateNetworksAndScopedVolumes(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker compose unavailable")
	}
	if err := exec.Command("docker", "compose", "version").Run(); err != nil {
		t.Skip("docker compose unavailable")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "stack.env"), []byte("CLERK_SECRET_KEY=sk_test_fixtureonly\n"), 0600)
	r := PreviewRecord{App: "fieldsofrevik", PR: 321, Project: "fieldsofrevik-pr-321", GatePort: 20001, DBPassword: "fixture-seed", Images: revikImages()}
	path := filepath.Join(dir, "compose.yml")
	os.WriteFile(path, []byte(previewCompose(r, PreviewKnob{Domain: "preview.revik.gg", MemLimit: "256m", CPULimit: "0.5"}, "edge", true, "")), 0600)
	body, err := exec.Command("docker", "compose", "-p", r.Project, "-f", path, "config", "--format", "json").Output()
	if err != nil {
		t.Fatal("preview compose could not be parsed", err)
	}
	var doc struct {
		Services map[string]struct {
			Networks    map[string]any
			Ports       []any
			Environment map[string]string
		}
		Volumes map[string]struct{ Name string }
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Services) != 6 {
		t.Fatal("expected six preview services")
	}
	for name, svc := range doc.Services {
		_, shared := svc.Networks["shared"]
		if shared != (name == "gate") || (name != "gate" && len(svc.Ports) != 0) {
			t.Fatalf("%s reaches shared network or publishes a port", name)
		}
	}
	if doc.Volumes["pg_data"].Name != r.Project+"_pg_data" || doc.Volumes["redis_data"].Name != r.Project+"_redis_data" {
		t.Fatal("preview volumes are not project scoped")
	}
	if strings.Contains(doc.Services["api"].Environment["DATABASE_URL"], "revik_migrator") ||
		doc.Services["api"].Environment["CLERK_SECRET_KEY"] != "sk_test_fixtureonly" ||
		doc.Services["gate"].Environment["CLERK_SECRET_KEY"] != "" {
		t.Fatal("preview secrets crossed service boundaries")
	}
}

func TestRevikPreviewStartupFailureCleansOnlyItsProject(t *testing.T) {
	cfg := previewTestConfig(t)
	dir := previewDir(cfg.Root, PreviewProject("fieldsofrevik", 322))
	os.MkdirAll(dir, 0750)
	os.WriteFile(filepath.Join(dir, "stack.env"), []byte("CLERK_SECRET_KEY=sk_test_fixtureonly\nCLERK_ISSUER=https://fixture.clerk.accounts.dev\nCLERK_JWKS_URL=https://fixture.clerk.accounts.dev/.well-known/jwks.json\n"), 0600)
	f := &fakeDocker{composeUpErr: fmt.Errorf("migration failed")}
	if _, err := PreviewUp(context.Background(), f.run, cfg, "fieldsofrevik", 322, revikImages(), previewNow); err == nil {
		t.Fatal("startup failure was ignored")
	}
	for _, args := range f.calls {
		if strings.Contains(strings.Join(args, " "), PreviewDBContainer) {
			t.Fatal("failure recovery touched shared preview database")
		}
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("failed preview left state behind")
	}
}
