package operator

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestColdExportIdentifiesEveryByteAndNeverOverwritesPriorStage(t *testing.T) {
	root := t.TempDir()
	stage := filepath.Join(root, "stage")
	plan, err := Plan()
	if err != nil {
		t.Fatal(err)
	}
	if err := Export(stage); err != nil {
		t.Fatal(err)
	}
	for name, want := range plan {
		body, err := os.ReadFile(filepath.Join(stage, name))
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(body)) != want {
			t.Fatal("export differs from embedded release")
		}
		info, _ := os.Stat(filepath.Join(stage, name))
		if info.Mode().Perm() != 0600 {
			t.Fatal("export is not private")
		}
	}
	if err := Export(stage); err == nil {
		t.Fatal("prior reviewed stage was replaced")
	}
}
