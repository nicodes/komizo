package box

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPlatformRecoveryFenceRefusesWorkloadEffectsAndReleasesLocks(t *testing.T) {
	for _, linked := range []bool{false, true} {
		t.Run(map[bool]string{false: "journal", true: "broken-link"}[linked], func(t *testing.T) {
			root := t.TempDir()
			pending := filepath.Join(root, "var/lib/komizo/upgrades/pending.json")
			if err := os.MkdirAll(filepath.Dir(pending), 0700); err != nil {
				t.Fatal(err)
			}
			var err error
			if linked {
				err = os.Symlink("missing", pending)
			} else {
				err = os.WriteFile(pending, []byte("synthetic interrupted operation"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if unlock, err := LockDeployment(context.Background(), root, "example"); err == nil {
				unlock()
				t.Fatal("interrupted platform operation allowed a workload")
			}
			if _, unlock, err := previewOperation(context.Background(), root); err == nil {
				unlock()
				t.Fatal("interrupted platform operation allowed a preview")
			}
			if err := os.Remove(pending); err != nil {
				t.Fatal(err)
			}
			unlock, err := LockDeployment(context.Background(), root, "example")
			if err != nil {
				t.Fatal(err)
			}
			unlock()
		})
	}
}
