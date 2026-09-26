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
