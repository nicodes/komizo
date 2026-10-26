package project

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestCIAdapterPreservesArgumentsAndRejectsShellTargetText(t *testing.T) {
	body, err := os.ReadFile("../../run/action.yml")
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Runs struct {
			Steps []struct {
				Name string `yaml:"name"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err = yaml.Unmarshal(body, &action); err != nil {
		t.Fatal(err)
	}
	var script string
	for _, step := range action.Runs.Steps {
		if step.Name == "Run project stages" {
			script = step.Run
		}
	}
	if script == "" {
		t.Fatal("no execution step")
	}
	directory := t.TempDir()
	if err = os.WriteFile(filepath.Join(directory, "komizo"), []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	runConfigured := func(targets, selected, base string) (string, error) {
		command := exec.Command("bash", "-c", script)
		command.Env = []string{"PATH=" + directory + ":/usr/bin:/bin", "ENGINEERING_TARGET=" + targets, "KOMIZO_DIRECTORY=project with spaces", "KOMIZO_TIMEOUT=2h", "KOMIZO_TOOLS=" + selected, "KOMIZO_BASE=" + base, "CACHE_ENABLED=false", "WEB_CACHE_ENABLED=false", "GO_CACHE_ENABLED=false"}
		output, err := command.Output()
		return string(output), err
	}
	run := func(targets string) (string, error) { return runConfigured(targets, "python", "") }
	output, err := run("install build artifact-check e2e")
	want := []string{"run", "--directory", "project with spaces", "--timeout", "2h", "--tools", "python", "install", "build", "artifact-check", "e2e"}
	if err != nil || !reflect.DeepEqual(strings.Split(strings.TrimSuffix(output, "\n"), "\n"), want) {
		t.Fatal(err, output)
	}
	for _, bad := range []string{"build;true", "build\ne2e", " build", "build  e2e", "build -f other", "$(true)"} {
		if output, err := run(bad); err == nil || output != "" {
			t.Fatalf("unsafe target %q: %v %s", bad, err, output)
		}
	}
	base := strings.Repeat("a", 40)
	output, err = runConfigured("check", "", base)
	want = []string{"check", "--directory", "project with spaces", "--timeout", "2h", "--base", base}
	if err != nil || !reflect.DeepEqual(strings.Split(strings.TrimSuffix(output, "\n"), "\n"), want) {
		t.Fatal(err, output)
	}
	for _, invalid := range [][3]string{{"unit", "", base}, {"check", "python", base}, {"check", "", "main;true"}} {
		if output, err := runConfigured(invalid[0], invalid[1], invalid[2]); err == nil || output != "" {
			t.Fatal("invalid affected-check command executed", invalid, output, err)
		}
	}

}
