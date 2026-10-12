package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCandidateResourceCheckIsReadOnlyAndCannotSelectApplyAuthority(t *testing.T) {
	for _, args := range [][]string{
		{"--policy", "/etc/foreign.json"},
		{"--apply", "--policy", "/etc/foreign.json"},
		{"--check", "--policy", "relative.json"},
		{"--check", "--policy", "/etc/../foreign.json"},
		{"--check-usage"},
	} {
		if err := runHostResources(args); err == nil {
			t.Fatal("candidate path widened installed apply authority", args)
		}
	}
	if os.Geteuid() != 0 {
		t.Skip("native protected-file acceptance requires root")
	}
	// The production reader rejects writable ancestry, including shared /tmp.
	dir, err := os.MkdirTemp(".", ".resource-check-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path, err := filepath.Abs(filepath.Join(dir, "candidate.json"))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"version":1,"physical_memory_bytes":536870912,"os_reserve_bytes":134217728,"physical_milli_cpus":1000,"os_reserve_milli_cpus":200,"production":{"memory_bytes":67108864,"swap_bytes":0,"milli_cpus":200,"pids":128},"proxy":{"memory_bytes":67108864,"swap_bytes":0,"milli_cpus":200,"pids":128},"previews":{"memory_bytes":67108864,"swap_bytes":0,"milli_cpus":200,"pids":128},"preview_database":{"memory_bytes":67108864,"swap_bytes":0,"milli_cpus":200,"pids":128}}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := runHostResources([]string{"--check", "--policy", path}); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatal("candidate check wrote output", files, err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if err := runHostResources([]string{"--check", "--policy", path}); err == nil {
		t.Fatal("writable resource authority admitted")
	}
}
