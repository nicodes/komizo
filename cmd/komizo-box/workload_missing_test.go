package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nicodes/komizo/internal/workload"
)

func TestProtectedReadersPreserveAbsenceWithoutAcceptingUnsafeFiles(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "missing")
	var record map[string]any
	if err := protectedActivationJSON(missing, &record); !os.IsNotExist(err) {
		t.Fatalf("JSON reader hid missing record: %v", err)
	}
	if _, err := protectedActivationBytes(missing); !os.IsNotExist(err) {
		t.Fatalf("byte reader hid missing input: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(missing, link); err != nil {
		t.Fatal(err)
	}
	if err := protectedActivationJSON(link, &record); err == nil || os.IsNotExist(err) {
		t.Fatal("unsafe link confused with absent metadata", err)
	}
	if _, err := protectedActivationBytes(link); err == nil || os.IsNotExist(err) {
		t.Fatal("unsafe link confused with absent input", err)
	}
}
func TestFirstStaticActivationUsesProductionMissingRecordSemantics(t *testing.T) {
	h, r, _ := staticActivationFixture(t)
	read := h.readJSON
	h.readJSON = func(path string, out any) error {
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			return protectedActivationJSON(path, out)
		}
		return read(path, out)
	}
	result, err := workload.Activate(context.Background(), r, h)
	if err != nil || !result.OK || result.Phase != "ready" {
		t.Fatalf("first deployment refused absent optional record: %+v %v", result, err)
	}
}
