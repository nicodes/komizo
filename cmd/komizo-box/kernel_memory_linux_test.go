//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func kernelMemoryFixture(t *testing.T, mode string) string {
	t.Helper()
	root := t.TempDir()
	base := filepath.Join(root, "sys/kernel/mm/transparent_hugepage")
	if err := os.MkdirAll(filepath.Join(base, "khugepaged"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"enabled": mode, "defrag": "always defer defer+madvise [madvise] never", "khugepaged/max_ptes_none": "511"} {
		if err := os.WriteFile(filepath.Join(base, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
func TestSmallHostKernelMemoryDefaultsAndPreservedDisabledOrLargeHosts(t *testing.T) {
	for _, tt := range []struct {
		mode   string
		memory int64
		change bool
	}{{"[always] madvise never", 1 << 30, true}, {"always [madvise] never", 1 << 30, true}, {"always madvise [never]", 1 << 30, false}, {"[always] madvise never", 4 << 30, false}} {
		root := kernelMemoryFixture(t, tt.mode)
		if err := applySmallHostKernelMemoryAt(root, tt.memory, uint32(os.Geteuid())); err != nil {
			t.Fatal(err)
		}
		base := filepath.Join(root, "sys/kernel/mm/transparent_hugepage")
		want := map[string]string{"enabled": tt.mode, "defrag": "always defer defer+madvise [madvise] never", "khugepaged/max_ptes_none": "511"}
		if tt.change {
			want = map[string]string{"enabled": "madvise", "defrag": "defer+madvise", "khugepaged/max_ptes_none": "0"}
		}
		for name, value := range want {
			body, _ := os.ReadFile(filepath.Join(base, name))
			if string(body) != value {
				t.Fatalf("%s=%q want%q", name, body, value)
			}
		}
	}
}
func TestKernelMemoryMissingOrSymlinkControlRefusesBeforeEffects(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		root := kernelMemoryFixture(t, "[always] madvise never")
		base := filepath.Join(root, "sys/kernel/mm/transparent_hugepage")
		p := filepath.Join(base, "defrag")
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if symlink {
			other := filepath.Join(root, "outside")
			os.WriteFile(other, []byte("defer+madvise"), 0600)
			os.Symlink(other, p)
		}
		if err := applySmallHostKernelMemoryAt(root, 1<<30, uint32(os.Geteuid())); err == nil {
			t.Fatal("unsafe control accepted")
		}
		body, _ := os.ReadFile(filepath.Join(base, "enabled"))
		if string(body) != "[always] madvise never" {
			t.Fatal("failed preflight changed mode")
		}
	}
}
