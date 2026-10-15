package app

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestScopedSpecLoadsOnlyExplicitSiblingAdaptersAndPreservesTheirBytes(t *testing.T) {
	dir := t.TempDir()
	provision := []byte("#!/bin/sh\n# unrelated credential service\nexit 0\n")
	status := []byte("#!/bin/sh\n[ \"$#\" -eq 0 ] || exit 1\nprintf ready\n")
	for name, body := range map[string][]byte{"provision.sh": provision, "status.sh": status} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	row := map[string]any{"version": 1, "profile": "unrelated-owner-profile-v3", "schema": 27, "files": []string{"mailer.env", "tls.pem"}, "provision_script": "provision.sh", "status_script": "status.sh"}
	path := filepath.Join(dir, "spec.json")
	write := func() {
		body, _ := json.Marshal(row)
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	spec, err := readScopedSpec(path)
	if err != nil {
		t.Fatal(err)
	}
	body, err := base64.StdEncoding.DecodeString(scopedSpecValue(spec, "provision"))
	if err != nil || string(body) != string(provision) {
		t.Fatal("adapter transport changed", err)
	}
	if scopedSpecValue(spec, "files") != "mailer.env,tls.pem" {
		t.Fatal("file declaration changed")
	}
	for _, name := range []string{"../other.sh", "/root/private.sh", "missing.sh"} {
		row["provision_script"] = name
		write()
		if _, err := readScopedSpec(path); err == nil {
			t.Fatalf("unreviewed path accepted %s", name)
		}
	}
	row["provision_script"] = "link.sh"
	if err := os.Symlink(filepath.Join(dir, "provision.sh"), filepath.Join(dir, "link.sh")); err != nil {
		t.Fatal(err)
	}
	write()
	if _, err := readScopedSpec(path); err == nil {
		t.Fatal("linked adapter accepted")
	}
	row["provision_script"] = "provision.sh"
	row["files"] = []string{"../other"}
	write()
	if _, err := readScopedSpec(path); err == nil {
		t.Fatal("cross-app declaration accepted")
	}
}
