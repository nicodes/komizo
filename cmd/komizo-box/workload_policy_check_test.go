package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyCheckNeedsNoComposeAndCreatesNoOutput(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native root policy validation; signed cold acceptance also covers this command")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	body := []byte(`{"version":1,"app":"demo","app_dir":"/srv/demo","image_prefix":"ghcr.io/example/demo-","shared_network":"edge"}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := runWorkload([]string{"policy-check", "--policy", path}); err != nil {
		t.Fatalf("policy-only authority validation refused: %v", err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatal("policy preflight created a workload or output")
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"unexpected":"authority"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runWorkload([]string{"policy-check", "--policy", path}); err == nil {
		t.Fatal("unknown policy fields were admitted")
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if err := runWorkload([]string{"policy-check", "--policy", path}); err == nil {
		t.Fatal("writable policy admitted")
	}
}
