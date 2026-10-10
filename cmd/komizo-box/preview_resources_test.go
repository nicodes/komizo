package main

import (
	"github.com/nicodes/komizo/internal/workload"
	"os"
	"path/filepath"
	"testing"
)

func TestPreviewRefusesMissingUnlimitedOrDriftedParentControllers(t *testing.T) {
	p := &workload.HostResources{Previews: workload.HostGroup{MemoryBytes: 64 << 20, MilliCPUs: 100, PIDs: 128}}
	root := t.TempDir()
	dir := filepath.Join(root, "komizo-previews")
	if err := verifyPreviewControllers(p, root); err == nil {
		t.Fatal("missing controllers accepted")
	}
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	good := map[string]string{"memory.max": "67108864", "memory.swap.max": "0", "cpu.max": "10000 100000", "pids.max": "128"}
	for name, value := range good {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := verifyPreviewControllers(p, root); err != nil {
		t.Fatal(err)
	}
	for name, wrong := range map[string]string{"memory.max": "max", "memory.swap.max": "4096", "cpu.max": "max 100000", "pids.max": "max"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(wrong), 0600); err != nil {
			t.Fatal(err)
		}
		if err := verifyPreviewControllers(p, root); err == nil {
			t.Fatalf("drifted %s accepted", name)
		}
		if err := os.WriteFile(path, []byte(good[name]), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPreviewPolicyRefusesAbsentPublicOrSymlinkedFiles(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "resources.json")
	if _, err := previewHostResources(path); err == nil {
		t.Fatal("missing protected policy accepted")
	}
	if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := previewHostResources(path); err == nil {
		t.Fatal("public policy accepted")
	}
	link := filepath.Join(root, "linked.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := previewHostResources(link); err == nil {
		t.Fatal("symlinked policy accepted")
	}
}
