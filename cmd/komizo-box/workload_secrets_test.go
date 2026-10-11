package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretSetRefusalLeavesCompletePreviousStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.env")
	previous := []byte("UNCHANGED=synthetic\n")
	if err := os.WriteFile(path, previous, 0600); err != nil {
		t.Fatal(err)
	}
	for _, values := range []map[string]string{nil, {"NEW": ""}, {"NEW": "line\nbreak"}, {"GITHUB_TOKEN": "synthetic"}, {"NEW": strings.Repeat("x", (1<<20)+1)}} {
		if err := writeSecretSet(dir, values); err == nil {
			t.Fatal("invalid set accepted")
		}
		if body, _ := os.ReadFile(path); string(body) != string(previous) {
			t.Fatal("partial invalid set replaced current credentials")
		}
	}
	if os.Geteuid() == 0 {
		if err := writeSecretSet(dir, map[string]string{"SECOND": "synthetic-b", "FIRST": "synthetic-a"}); err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(path)
		if err != nil || string(body) != "UNCHANGED=synthetic\nFIRST=synthetic-a\nSECOND=synthetic-b\n" {
			t.Fatal("complete batch was not preserved", err)
		}
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0600 || !workloadRootOwner(info) {
			t.Fatal("writer widened secret access")
		}
	}
}

func TestSecretDestinationLinksCannotChangeAnotherStore(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(dir, "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "secrets.env")); err != nil {
		t.Fatal(err)
	}
	if writeSecretSet(dir, map[string]string{"NEW": "synthetic"}) == nil {
		t.Fatal("linked secret store accepted")
	}
	if body, _ := os.ReadFile(outside); string(body) != "unchanged" {
		t.Fatal("linked store overwritten")
	}
}
