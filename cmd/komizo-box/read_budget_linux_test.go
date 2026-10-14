//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFreshReadEnvelopeRequiresMatchingProtectedAuthority(t *testing.T) {
	root := t.TempDir()
	policy := filepath.Join(root, "resources.json")
	cg := filepath.Join(root, "cgroup")
	dir := filepath.Join(cg, "openrc.komizo-rootd")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policy, []byte(`{"controls":{"openrc.komizo-rootd":{"memory_bytes":184549376}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	max := filepath.Join(dir, "memory.max")
	procs := filepath.Join(dir, "cgroup.procs")
	os.WriteFile(max, []byte("184549376\n"), 0644)
	os.WriteFile(procs, []byte("unchanged"), 0644)
	if err := enterReadBudgetAt(policy, cg, 123, uint32(os.Geteuid())); err != nil {
		t.Fatal(err)
	}
	if body, _ := os.ReadFile(procs); string(body) != "123" {
		t.Fatal("fresh reader did not join envelope")
	}
	for _, limit := range []string{"max", "201326592"} {
		os.WriteFile(max, []byte(limit), 0644)
		os.WriteFile(procs, []byte("unchanged"), 0644)
		if err := enterReadBudgetAt(policy, cg, 123, uint32(os.Geteuid())); err == nil {
			t.Fatal("mismatched limit accepted")
		}
		if body, _ := os.ReadFile(procs); string(body) != "unchanged" {
			t.Fatal("effects before refusal")
		}
	}
	os.WriteFile(max, []byte("184549376"), 0644)
	os.Chmod(policy, 0644)
	if enterReadBudgetAt(policy, cg, 123, uint32(os.Geteuid())) == nil {
		t.Fatal("public authority accepted")
	}
	os.Chmod(policy, 0600)
	os.Remove(procs)
	os.Symlink(filepath.Join(root, "foreign"), procs)
	if enterReadBudgetAt(policy, cg, 123, uint32(os.Geteuid())) == nil {
		t.Fatal("symlinked interface accepted")
	}
}

func TestLegacyReadHasNoDeclaredEnvelope(t *testing.T) {
	root := t.TempDir()
	policy := filepath.Join(root, "resources.json")
	if err := enterReadBudgetAt(policy, root, 123, uint32(os.Geteuid())); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(policy, []byte(`{"controls":{}}`), 0600)
	if err := enterReadBudgetAt(policy, root, 123, uint32(os.Geteuid())); err != nil {
		t.Fatal(err)
	}
}
