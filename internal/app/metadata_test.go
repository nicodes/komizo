package app

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestDependencyMetadataRejectsAmbiguousYAMLAndParsesScalarUpdates(t *testing.T) {
	valid := "updated-dependencies:\n- dependency-name: example\n  dependency-version: 1.2.3\n  update-type: version-update:semver-patch\n"
	if value, err := dependencyMetadata([]byte(valid)); err != nil || len(value["updated-dependencies"].([]any)) != 1 {
		t.Fatal(value, err)
	}
	for _, bad := range []string{
		"", strings.Repeat("x", 65537), "updated-dependencies: null", "updated-dependencies: {}", "other: []",
		valid + "updated-dependencies: []\n", valid + "---\nupdated-dependencies: []\n",
		"updated-dependencies: &x []", "updated-dependencies: [*x]", "updated-dependencies: !!seq []",
		"updated-dependencies:\n- dependency-name: example\n  dependency-name: other\n",
	} {
		if _, err := dependencyMetadata([]byte(bad)); err == nil {
			t.Fatalf("unsafe metadata accepted: %q", bad)
		}
	}
}

func TestDependencyClientDoesNotLoadProjectToolHooks(t *testing.T) {
	t.Setenv("KOMIZO_CACHE_DIR", t.TempDir())
	t.Setenv("GITHUB_REPOSITORY", "invalid repository")
	t.Setenv("GH_TOKEN", "never-print-this-token")
	// A project hook would execute if this command used project preparation.
	root := t.TempDir()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(previous)
	manifest := `{"version":1,"recipe":"static-site","tools":{"python":{"version":"3.13.11","postinstall":"touch leaked-hook"}}}`
	if err = os.WriteFile("komizo.json", []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	var out, progress bytes.Buffer
	code := CLI([]string{"--json", "dependencies", "inspect"}, strings.NewReader(""), &out, &progress)
	var result MachineResult
	if err = json.Unmarshal(out.Bytes(), &result); err != nil || code == 0 || result.Error == nil || result.Error.ReconciliationRequired {
		t.Fatalf("%s %s", out.String(), progress.String())
	}
	if _, err = os.Stat("leaked-hook"); !os.IsNotExist(err) {
		t.Fatal("executed a project tool hook")
	}
	if strings.Contains(out.String()+progress.String(), "never-print-this-token") {
		t.Fatal("printed a client credential")
	}
}
