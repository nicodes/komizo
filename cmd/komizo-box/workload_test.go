package main

import (
	"github.com/nicodes/komizo/internal/workload"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkloadInitializationNeverWidensExistingPolicy(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("policy ownership requires root")
	}
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy.json")
	args := []string{"init", "--policy", policy, "--app", "example", "--app-dir", dir, "--config-image", "ghcr.io/owner/example-config"}
	if err := runWorkload(args); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(policy)
	if err := runWorkload(args); err != nil {
		t.Fatal(err)
	}
	args[len(args)-1] = "ghcr.io/other/example-config"
	if err := runWorkload(args); err == nil {
		t.Fatal("provisioning changed policy authority")
	}
	after, _ := os.ReadFile(policy)
	if string(before) != string(after) {
		t.Fatal("policy changed")
	}
}

func TestWorkloadValidationDoesNotReadOrExposeExternalFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("policy ownership requires root")
	}
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy.json")
	if err := runWorkload([]string{"init", "--policy", policy, "--app", "example", "--app-dir", dir, "--config-image", "ghcr.io/owner/example-config"}); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(dir, "compose.yml")
	output := filepath.Join(dir, "approved.json")
	if err := os.WriteFile(input, []byte("include: /etc/private\nservices:\n  api:\n    image: ghcr.io/owner/example-api:commit123\n"), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"validate", "--policy", policy, "--app", "example", "--app-dir", dir, "--version", "commit123", "--compose", input, "--output", output}
	if err := runWorkload(args); err == nil {
		t.Fatal("external include accepted")
	} else if strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("error exposed file contents")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("failed validation wrote configuration")
	}
	if err := os.Chmod(policy, 0666); err != nil {
		t.Fatal(err)
	}
	if err := runWorkload(args); err == nil {
		t.Fatal("writable policy trusted")
	}
}

func TestCachedRollbackRequiresProtectedCurrentOrPrevious(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("protected root-owned retention requires root")
	}
	dir := t.TempDir()
	p, err := workload.NewPolicy("demo", dir, "ghcr.io/owner/demo-config", "edge")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, ".komizo-image-retention")
	if err := os.WriteFile(path, []byte("CURRENT=current\nPREVIOUS=previous\nOTHER=older\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if !cachedRollbackAllowed(p, "current") || !cachedRollbackAllowed(p, "previous") || cachedRollbackAllowed(p, "older") {
		t.Fatal("wrong rollback authority")
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if cachedRollbackAllowed(p, "current") {
		t.Fatal("writable retention granted rollback")
	}
}
