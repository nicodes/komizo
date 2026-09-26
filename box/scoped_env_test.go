package box

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRefuseScopedStartLeavesOtherAppsAlone(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "srv", "blog")
	if err := os.MkdirAll(filepath.Join(root, "var/lib/komizo/apps"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "var/lib/komizo/apps/blog.env"), []byte("APP_DIR="+appDir+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := RefuseScopedStart(root, "blog"); err != nil {
		t.Fatal(err)
	}
}

func TestRefuseScopedStartWithoutGeneration(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "srv", "fieldsofrevik")
	if err := os.MkdirAll(filepath.Join(root, "var/lib/komizo/apps"), 0o750); err != nil {
		t.Fatal(err)
	}
	rec := "APP_NAME=fieldsofrevik\nAPP_DIR=" + appDir + "\nSCOPED_ENV=fields-postgres-v2\n"
	if err := os.WriteFile(filepath.Join(root, "var/lib/komizo/apps/fieldsofrevik.env"), []byte(rec), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := RefuseScopedStart(root, "fieldsofrevik"); err == nil {
		t.Fatal("start without a generation succeeded")
	}
}

func TestRefuseScopedStartRejectsWithdrawnV1(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "srv", "fieldsofrevik")
	if err := os.MkdirAll(filepath.Join(root, "var/lib/komizo/apps"), 0o750); err != nil {
		t.Fatal(err)
	}
	rec := "APP_NAME=fieldsofrevik\nAPP_DIR=" + appDir + "\nSCOPED_ENV=fields-postgres-v1\nSCOPED_GENERATION=0123456789abcdef0123456789abcdef\n"
	if err := os.WriteFile(filepath.Join(root, "var/lib/komizo/apps/fieldsofrevik.env"), []byte(rec), 0o640); err != nil {
		t.Fatal(err)
	}
	err := RefuseScopedStart(root, "fieldsofrevik")
	if err == nil || !strings.Contains(err.Error(), "withdrawn") || strings.Contains(err.Error(), "ready") {
		t.Fatalf("v1 start = %v", err)
	}
}

func TestRefuseScopedStartUsesProvenanceNotEnvBytes(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "srv", "fieldsofrevik")
	id := "0123456789abcdef0123456789abcdef"
	gen := filepath.Join(appDir, "secrets", "generations", id)
	if err := os.MkdirAll(filepath.Join(root, "var/lib/komizo/apps"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(gen, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("generations/"+id, filepath.Join(appDir, "secrets", "current")); err != nil {
		t.Fatal(err)
	}
	sentinel := "START_SENTINEL_MUST_NOT_ECHO"
	for _, name := range []string{"postgres.env", "migrate.env", "api.env", "godot-api.env"} {
		if err := os.WriteFile(filepath.Join(gen, name), []byte("CLERK_SECRET_KEY="+sentinel+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rec := "APP_NAME=fieldsofrevik\nAPP_DIR=" + appDir + "\nSCOPED_ENV=fields-postgres-v2\nSCOPED_GENERATION=" + id + "\n"
	if err := os.WriteFile(filepath.Join(root, "var/lib/komizo/apps/fieldsofrevik.env"), []byte(rec), 0o640); err != nil {
		t.Fatal(err)
	}
	err := RefuseScopedStart(root, "fieldsofrevik")
	if err == nil || strings.Contains(err.Error(), sentinel) {
		t.Fatalf("missing provenance start = %v", err)
	}
	marker := filepath.Join(gen, "provenance")
	body := []byte("profile=fields-postgres-v2\nschema=11\ngeneration=" + id + "\n")
	if err := os.WriteFile(marker, body, 0o400); err != nil {
		t.Fatal(err)
	}
	err = RefuseScopedStart(root, "fieldsofrevik")
	if os.Getuid() == 0 {
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	if err == nil || strings.Contains(err.Error(), sentinel) {
		t.Fatalf("non-root marker was started or echoed: %v", err)
	}
}
