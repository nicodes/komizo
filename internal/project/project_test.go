package project

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/format"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func manifestFixture(t *testing.T, data string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ManifestName), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestManifestRejectsAmbiguousOrUnboundedInputs(t *testing.T) {
	for _, data := range []string{
		`{"version":1,"version":1,"recipe":"static-site"}`,
		`{"version":1,"recipe":"static-site","tools":{"bun":"1.4.1","bun":"1.3.0"}}`,
		`{"version":1,"recipe":"static-site","unknown":true}`,
		`{"version":1,"recipe":"unknown"}`,
		`{"version":1,"recipe":"static-site","tools":{"bun":"latest"}}`,
		`{"version":1,"recipe":"static-site","tools":{"bun":"1.4"}}`,
		`{"version":1,"recipe":"static-site","tools":{"http:cicd-engineering":"0.27.5"}}`,
		`{"version":1,"recipe":"static-site","artifacts":["../other"]}`,
		`{"version":1,"recipe":"static-site","artifacts":["."]}`,
		`{"version":1,"recipe":"static-site","artifacts":["*"]}`,
		`{"version":1,"recipe":"static-site","stages":{"typo":[["true"]]}}`,
		`{"version":1,"recipe":"static-site","stages":{"unit":[]}}`,
		`{"version":1,"recipe":"static-site","stages":{"unit":{"inapplicable":""}}}`,
		`{"version":1,"recipe":"static-site","stages":{"unit":[["echo",""]]}}`,
		`{"version":1,"recipe":"static-site","validation":{"../../outside":{}}}`,
		`{"version":1,"recipe":"static-site","development":{"repository":"foreign/project"}}`,
		`{"version":1,"recipe":"static-site"} {}`,
	} {
		t.Run(data, func(t *testing.T) {
			if _, _, err := Read(manifestFixture(t, data)); err == nil {
				t.Fatal("accepted invalid manifest")
			}
		})
	}
}

func TestLockBindsPlatformRecipeAndManifest(t *testing.T) {
	root := manifestFixture(t, `{"version":1,"recipe":"static-site","tools":{"bun":"1.4.1"}}`)
	if _, err := WriteLock(root, "test-platform"); err != nil {
		t.Fatal(err)
	}
	m, data, _ := Read(root)
	if err := CheckLock(root, "test-platform", data, m); err != nil {
		t.Fatal(err)
	}
	if err := CheckLock(root, "different-platform", data, m); err == nil {
		t.Fatal("accepted a different platform")
	}
	if err := os.WriteFile(filepath.Join(root, ManifestName), append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	m, data, _ = Read(root)
	if err := CheckLock(root, "test-platform", data, m); err == nil {
		t.Fatal("accepted changed project input")
	}
	if _, err := WriteLock(root, "test-platform"); err != nil {
		t.Fatal(err)
	}
	if err := CheckLock(root, "test-platform", data, m); err != nil {
		t.Fatal(err)
	}
}

func TestInitPreservesExistingInputs(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("owned/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(root, "static-site", "test-platform"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(root, ".gitignore"))
	if !bytes.Contains(b, []byte("owned/\n")) || !bytes.Contains(b, []byte(".komizo.mise*.toml")) {
		t.Fatal(string(b))
	}
	before, _ := os.ReadFile(filepath.Join(root, ManifestName))
	if _, err := Init(root, "go-service", "test-platform"); err == nil {
		t.Fatal("overwrote an existing project")
	}
	after, _ := os.ReadFile(filepath.Join(root, ManifestName))
	if !bytes.Equal(before, after) {
		t.Fatal("project changed on refusal")
	}
}

func TestRuntimeRefusesTamperingAndLinks(t *testing.T) {
	t.Setenv("KOMIZO_CACHE_DIR", t.TempDir())
	root, err := Runtime()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Runtime(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "helpers", "contract.py")
	if err = os.WriteFile(path, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = Runtime(); err == nil {
		t.Fatal("accepted modified helper")
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join(root, "SOURCE.json"), path); err != nil {
		t.Fatal(err)
	}
	if _, err = Runtime(); err == nil {
		t.Fatal("accepted linked helper")
	}
}

func TestRuntimeRefusesChangedSourceManifest(t *testing.T) {
	t.Setenv("KOMIZO_CACHE_DIR", t.TempDir())
	root, err := Runtime()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "SOURCE.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = Runtime(); err == nil {
		t.Fatal("accepted replaced source manifest")
	}
}

func TestRecipeKeepsCompleteStagesAndOnlyExplicitOverrides(t *testing.T) {
	m := Manifest{Version: 1, Recipe: "go-service", Stages: map[string]json.RawMessage{"unit": command("go", "test", "./...")}}
	c, err := m.Contract()
	if err != nil {
		t.Fatal(err)
	}
	s := c["stages"].(map[string]json.RawMessage)
	if len(s) != len(stageNames) || !strings.Contains(string(s["integration"]), "inapplicable") {
		t.Fatal(s)
	}
	if string(s["unit"]) != string(command("go", "test", "./...")) {
		t.Fatal(s)
	}
}

func TestActualArtifactReuseAndFailurePropagation(t *testing.T) {
	t.Setenv("KOMIZO_CACHE_DIR", t.TempDir())
	root := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		c := exec.Command("git", args...)
		c.Dir = root
		if b, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git: %v %s", err, b)
		}
	}
	git("init", "-q")
	git("config", "user.email", "fixture@example.test")
	git("config", "user.name", "Fixture")
	if _, err := Init(root, "static-site", "test-platform"); err != nil {
		t.Fatal(err)
	}
	m, _, _ := Read(root)
	m.Tools = nil
	m.Stages = map[string]json.RawMessage{
		"install":        command("true"),
		"build":          command("sh", "-c", "mkdir -p dist .artifacts; printf output > dist/index.html; printf build >> .artifacts/build-count"),
		"artifact-check": command("sh", "-c", "test -s dist/index.html"),
		"unit":           command("sh", "-c", "test -f source.txt"),
	}
	if err := writeJSON(filepath.Join(root, ManifestName), m); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "source.txt"), []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteLock(root, "test-platform"); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-qm", "fixture")
	mise := filepath.Join(t.TempDir(), "fixture-mise")
	if err := os.WriteFile(mise, []byte("#!/bin/sh\nshift 2\nexec \"$@\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	tool := func(context.Context) (string, error) { return mise, nil }
	run := func(targets ...string) (Result, error) {
		return execute(context.Background(), root, "test-platform", targets, "local", nil, nil, io.Discard, tool)
	}
	if result, err := run("check"); err != nil || !result.Completed {
		t.Fatalf("first check: %#v %v", result, err)
	}
	if _, err := run("build"); err != nil {
		t.Fatal(err)
	}
	count, _ := os.ReadFile(filepath.Join(root, ".artifacts/build-count"))
	if string(count) != "build" {
		t.Fatalf("unchanged build repeated: %s", count)
	}
	if err := os.WriteFile(filepath.Join(root, "dist/index.html"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run("build"); err != nil {
		t.Fatal(err)
	}
	count, _ = os.ReadFile(filepath.Join(root, ".artifacts/build-count"))
	if string(count) != "buildbuild" {
		t.Fatalf("tampered output reused: %s", count)
	}
	if err := os.Remove(filepath.Join(root, "source.txt")); err != nil {
		t.Fatal(err)
	}
	result, err := run("unit")
	if err == nil || result.Completed || result.ExitCode == 0 {
		t.Fatalf("failed assertion accepted: %#v %v", result, err)
	}
	b, _ := os.ReadFile(filepath.Join(root, ".artifacts/contract/failure.json"))
	if !strings.Contains(string(b), `"komizo", "run", "unit"`) {
		t.Fatalf("missing focused failure action: %s", b)
	}
}

func TestGeneratedContractNeverFollowsAnArtifactDirectoryLink(t *testing.T) {
	t.Setenv("KOMIZO_CACHE_DIR", t.TempDir())
	root := manifestFixture(t, `{"version":1,"recipe":"static-site"}`)
	if _, err := WriteLock(root, "test-platform"); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, ".artifacts")); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := prepare(root, "test-platform", nil)
	if err == nil || !strings.Contains(err.Error(), "generated directory") {
		t.Fatal("wrong refusal for generated output directory link", err)
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatal("changed external directory", err)
	}
}

func TestGoRecipeBuildsAndChecksAnActualApplication(t *testing.T) {
	t.Setenv("KOMIZO_CACHE_DIR", t.TempDir())
	root := t.TempDir()
	if _, err := Init(root, "go-service", "test-platform"); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"go.mod":       "module example.test/fixture\n\ngo 1.27.3\n",
		"main.go":      "package main\n\nimport \"fmt\"\n\nfunc greeting() string { return \"ready\" }\nfunc main() { fmt.Print(greeting()) }\n",
		"main_test.go": "package main\n\nimport \"testing\"\n\nfunc TestGreeting(t *testing.T) { if greeting() != \"ready\" { t.Fatal(\"wrong greeting\") } }\n",
	}
	for name, body := range files {
		if strings.HasSuffix(name, ".go") {
			formatted, err := format.Source([]byte(body))
			if err != nil {
				t.Fatal(err)
			}
			body = string(formatted)
		}
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	m, _, err := Read(root)
	if err != nil {
		t.Fatal(err)
	}
	m.Tools = nil
	m.Stages = map[string]json.RawMessage{"vuln": inapplicable("fixture has no external dependencies; scanner covered by caller")}
	if err := writeJSON(filepath.Join(root, ManifestName), m); err != nil {
		t.Fatal(err)
	}
	if _, err = WriteLock(root, "test-platform"); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "."}, {"-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "fixture"}} {
		c := exec.Command("git", args...)
		c.Dir = root
		if b, err := c.CombinedOutput(); err != nil {
			t.Fatal(err, string(b))
		}
	}
	mise := filepath.Join(t.TempDir(), "mise")
	if err := os.WriteFile(mise, []byte("#!/bin/sh\nshift 2\nexec \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	var progress bytes.Buffer
	result, err := execute(context.Background(), root, "test-platform", []string{"check"}, "local", nil, nil, &progress, func(context.Context) (string, error) { return mise, nil })
	if err != nil || !result.Completed {
		t.Fatal(err, progress.String())
	}
	body, err := exec.Command(filepath.Join(root, ".artifacts/build/app")).Output()
	if err != nil || string(body) != "ready" {
		t.Fatal(err, string(body))
	}
}

func TestSelectedToolsUseIsolatedConfigurationsAndCannotCertifyVerification(t *testing.T) {
	t.Setenv("KOMIZO_CACHE_DIR", t.TempDir())
	root := manifestFixture(t, `{"version":1,"recipe":"static-site","tools":{"python":"3.13.11","node":"24.18.1"},"tasks":{"publish":[["true"]]}}`)
	if _, err := WriteLock(root, "test-platform"); err != nil {
		t.Fatal(err)
	}
	_, first, _, err := prepare(root, "test-platform", []string{"python"})
	if err != nil {
		t.Fatal(err)
	}
	configPath := func(environment []string) string {
		for _, item := range environment {
			if value, ok := strings.CutPrefix(item, "KOMIZO_TOOLCHAIN="); ok {
				return value
			}
		}
		t.Fatal("no toolchain path")
		return ""
	}
	firstPath := configPath(first)
	body, err := os.ReadFile(firstPath)
	if err != nil || !bytes.Contains(body, []byte("python")) || bytes.Contains(body, []byte("node")) {
		t.Fatal(string(body), err)
	}
	_, second, _, err := prepare(root, "test-platform", []string{"node"})
	if err != nil {
		t.Fatal(err)
	}
	if configPath(second) == firstPath {
		t.Fatal("parallel subsets share a mutable configuration")
	}
	unchanged, _ := os.ReadFile(firstPath)
	if !bytes.Equal(unchanged, body) {
		t.Fatal("second selection modified first selection")
	}
	for _, selection := range [][]string{{"unknown"}, {"python", "python"}} {
		if _, _, _, err := prepare(root, "test-platform", selection); err == nil {
			t.Fatal("invalid selection accepted", selection)
		}
	}
	called := false
	result, err := execute(context.Background(), root, "test-platform", []string{"unit"}, "local", []string{"python"}, nil, io.Discard, func(context.Context) (string, error) { called = true; return "", nil })
	if err == nil || called || result.ExitCode == 0 {
		t.Fatalf("verification tool selection ran: %+v %v", result, err)
	}
}

func TestProjectDeadlineReturnsATimeoutWithoutSuccess(t *testing.T) {
	t.Setenv("KOMIZO_CACHE_DIR", t.TempDir())
	root := manifestFixture(t, `{"version":1,"recipe":"static-site","stages":{"unit":[["sh","-c","sleep 30"]]}}`)
	if _, err := WriteLock(root, "test-platform"); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "."}, {"-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "fixture"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatal(err, string(b))
		}
	}
	mise := filepath.Join(t.TempDir(), "mise")
	if err := os.WriteFile(mise, []byte("#!/bin/sh\nshift 2\nexec \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	result, err := execute(ctx, root, "test-platform", []string{"unit"}, "local", nil, nil, io.Discard, func(context.Context) (string, error) { return mise, nil })
	if !errors.Is(err, context.DeadlineExceeded) || result.Completed || result.ExitCode != 124 || time.Since(start) > 3*time.Second {
		t.Fatalf("%+v %v", result, err)
	}
}

func TestToolchainEnvironmentMakesTheVerifiedExecutableAvailableToHelpers(t *testing.T) {
	directory := t.TempDir()
	body := []byte("#!/bin/sh\nprintf '%s' verified\n")
	executable := filepath.Join(directory, "mise")
	if err := os.WriteFile(executable, body, 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", "mise")
	cmd.Env = toolchainEnvironment([]string{"PATH=/usr/bin:/bin"}, executable)
	output, err := cmd.Output()
	if err != nil || string(output) != "verified" {
		t.Fatal(err, string(output))
	}
}
