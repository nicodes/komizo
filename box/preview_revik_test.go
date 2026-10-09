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
	for _, want := range []string{"  postgres:", "  migrate:", "  api:", "  godot-api:", "  redis:", "  " + r.Project + "-gate:", "db: {internal: true}", "networks: [app, shared]", "127.0.0.1:", "env_file: [stack.env]", "TEST_MODE: \"false\""} {
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
			Tmpfs       []string
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
		wantTmpfs := []string{"/tmp:rw,noexec,nosuid,size=64m,mode=1777"}
		if name == "postgres" {
			wantTmpfs = []string{"/tmp:rw,nosuid,size=32m,mode=1777", "/var/run/postgresql:rw,nosuid,size=16m,mode=1777"}
		}
		if strings.Join(svc.Tmpfs, "\n") != strings.Join(wantTmpfs, "\n") {
			t.Fatalf("%s has invalid temporary filesystem mounts: %v", name, svc.Tmpfs)
		}
		_, shared := svc.Networks["shared"]
		if shared != (name == r.Project+"-gate") || (name != r.Project+"-gate" && len(svc.Ports) != 0) {
			t.Fatalf("%s reaches shared network or publishes a port", name)
		}
	}
	if doc.Volumes["pg_data"].Name != r.Project+"_pg_data" || doc.Volumes["redis_data"].Name != r.Project+"_redis_data" {
		t.Fatal("preview volumes are not project scoped")
	}
	if strings.Contains(doc.Services["api"].Environment["DATABASE_URL"], "revik_migrator") ||
		doc.Services["api"].Environment["CLERK_SECRET_KEY"] != "sk_test_fixtureonly" ||
		doc.Services[r.Project+"-gate"].Environment["CLERK_SECRET_KEY"] != "" {
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

func TestRevikPreviewRebuildPreservesPrivateDatabaseCredentials(t *testing.T) {
	cfg := previewTestConfig(t)
	up := func(pr int, images []string, f *fakeDocker) PreviewRecord {
		dir := previewDir(cfg.Root, PreviewProject("fieldsofrevik", pr))
		if err := os.MkdirAll(dir, 0750); err != nil {
			t.Fatal(err)
		}
		auth := "CLERK_SECRET_KEY=sk_test_fixtureonly\nCLERK_ISSUER=https://fixture.clerk.accounts.dev\nCLERK_JWKS_URL=https://fixture.clerk.accounts.dev/.well-known/jwks.json\n"
		if err := os.WriteFile(filepath.Join(dir, "stack.env"), []byte(auth), 0600); err != nil {
			t.Fatal(err)
		}
		r, err := PreviewUp(context.Background(), f.run, cfg, "fieldsofrevik", pr, images, previewNow)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	first := up(321, revikImages(), &fakeDocker{previewDBDown: true})
	nextImages := revikImages()
	for i := range nextImages {
		nextImages[i] = strings.ReplaceAll(nextImages[i], strings.Repeat("a", 40), strings.Repeat("b", 40))
	}
	f := &fakeDocker{previewDBDown: true}
	rebuilt := up(321, nextImages, f)
	if rebuilt.DBPassword != first.DBPassword || rebuilt.GatePort != first.GatePort || strings.Join(rebuilt.Images, ",") != strings.Join(nextImages, ",") {
		t.Fatal("rebuild rotated credentials, changed its port, or kept the prior release")
	}
	for _, args := range f.calls {
		call := strings.Join(args, " ")
		if strings.Contains(call, " down") || strings.Contains(call, "psql") || strings.Contains(call, PreviewDBContainer) {
			t.Fatal("rebuild reset or reached another database")
		}
	}
	another := up(322, revikImages(), &fakeDocker{previewDBDown: true})
	if another.DBPassword == first.DBPassword {
		t.Fatal("another PR reused the private credential seed")
	}
	public, err := json.Marshal(rebuilt)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(public), first.DBPassword) {
		t.Fatal("rebuild disclosed the seed")
	}
}

func TestRevikPreviewRefusesCorruptExistingSeedBeforeMutation(t *testing.T) {
	for _, seed := range []string{"", "invalid", strings.Repeat("a", 23), strings.Repeat("a", 25)} {
		cfg := previewTestConfig(t)
		rec := PreviewRecord{V: 1, App: "fieldsofrevik", PR: 321, Project: "fieldsofrevik-pr-321", GatePort: 20001, DBPassword: seed, Images: revikImages(), CreatedAt: previewNow, LastUsed: previewNow}
		if err := writePreviewRecord(cfg.Root, rec); err != nil {
			t.Fatal(err)
		}
		dir := previewDir(cfg.Root, rec.Project)
		auth := "CLERK_SECRET_KEY=sk_test_fixtureonly\nCLERK_ISSUER=https://fixture.clerk.accounts.dev\nCLERK_JWKS_URL=https://fixture.clerk.accounts.dev/.well-known/jwks.json\n"
		if err := os.WriteFile(filepath.Join(dir, "stack.env"), []byte(auth), 0600); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(filepath.Join(dir, "preview.env"))
		if err != nil {
			t.Fatal(err)
		}
		f := &fakeDocker{previewDBDown: true}
		if _, err := PreviewUp(context.Background(), f.run, cfg, "fieldsofrevik", 321, revikImages(), previewNow); err == nil {
			t.Fatal("corrupt seed was accepted")
		}
		after, err := os.ReadFile(filepath.Join(dir, "preview.env"))
		if err != nil {
			t.Fatal(err)
		}
		if len(f.calls) != 0 || string(before) != string(after) {
			t.Fatal("corrupt seed caused mutation")
		}
	}
}
