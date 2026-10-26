package project

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func selectionPolicy() VerificationPolicy {
	return VerificationPolicy{Version: 1, FullTargets: []string{"lint", "unit", "integration"}, Always: []string{"lint"}, Rules: []VerificationRule{
		{Paths: []string{"README.md", "docs/*"}, Targets: []string{"lint"}},
		{Paths: []string{"unit-tests/*"}, Targets: []string{"unit"}},
	}}
}

func TestVerificationSelectionKeepsUnknownSharedAndProductionInputsComplete(t *testing.T) {
	p := selectionPolicy()
	for _, tc := range []struct {
		paths   []string
		event   string
		mode    string
		targets []string
	}{
		{[]string{"README.md"}, "pull_request", "focused", []string{"lint"}},
		{[]string{"README.md", "unit-tests/check.go"}, "local", "focused", []string{"lint", "unit"}},
		{[]string{"docs/nested/page.md"}, "local", "focused", []string{"lint"}},
		{[]string{"code.go"}, "pull_request", "full", p.FullTargets},
		{[]string{"komizo.json"}, "local", "full", p.FullTargets},
		{[]string{"komizo.lock"}, "local", "full", p.FullTargets},
		{[]string{".github/workflows/ci.yml"}, "local", "full", p.FullTargets},
		{[]string{"app/package.json"}, "local", "full", p.FullTargets},
		{[]string{"app/go.mod"}, "local", "full", p.FullTargets},
		{[]string{"README.md"}, "push", "full", p.FullTargets},
		{[]string{"README.md"}, "workflow_dispatch", "full", p.FullTargets},
	} {
		mode, targets, _ := selectedVerification(p, tc.paths, tc.event)
		if mode != tc.mode || !slices.Equal(targets, tc.targets) {
			t.Fatalf("%v %s: %s %v", tc.paths, tc.event, mode, targets)
		}
	}
}

func selectionFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	m := Manifest{Version: 1, Recipe: "static-site", Stages: map[string]json.RawMessage{}}
	for _, name := range stageNames {
		m.Stages[name] = inapplicable("Fixture has no " + name)
	}
	m.Stages["lint"] = command("sh", "-c", "printf lint >> .artifacts/executed")
	m.Stages["unit"] = command("sh", "-c", "printf unit >> .artifacts/executed")
	m.Stages["integration"] = command("sh", "-c", "printf integration >> .artifacts/executed")
	p := selectionPolicy()
	m.Verification = &p
	if err := writeJSON(filepath.Join(root, ManifestName), m); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte(".artifacts/\n.komizo.mise*\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteLock(root, "test-platform"); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "."}, {"-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		if body, err := cmd.CombinedOutput(); err != nil {
			t.Fatal(err, string(body))
		}
	}
	body, err := verificationGit(context.Background(), root, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	return root, strings.TrimSpace(string(body))
}

func TestReadOnlyPlanIncludesDirtyUntrackedRenameAndUnavailableBase(t *testing.T) {
	t.Setenv("GITHUB_EVENT_NAME", "local")
	t.Setenv("GH_TOKEN", "credential-that-must-not-enter-a-plan")
	root, base := selectionFixture(t)
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	plan, err := Plan(context.Background(), root, "test-platform", base)
	if err != nil || plan.Mode != "focused" || !slices.Equal(plan.Targets, []string{"lint"}) {
		t.Fatal(plan, err)
	}
	if err := os.WriteFile(filepath.Join(root, "new-code.go"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	plan, err = Plan(context.Background(), root, "test-platform", base)
	if err != nil || plan.Mode != "full" {
		t.Fatal(plan, err)
	}
	if err := os.Remove(filepath.Join(root, "new-code.go")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, "README.md"), filepath.Join(root, "runtime.go")); err != nil {
		t.Fatal(err)
	}
	plan, err = Plan(context.Background(), root, "test-platform", base)
	if err != nil || plan.Mode != "full" || !slices.Equal(plan.ChangedPaths, []string{"README.md", "runtime.go"}) {
		t.Fatal(plan, err)
	}
	plan, err = Plan(context.Background(), root, "test-platform", strings.Repeat("f", 40))
	if err != nil || plan.Mode != "full" || !strings.Contains(plan.Reasons[0], "unavailable") {
		t.Fatal(plan, err)
	}
	body, _ := json.Marshal(plan)
	if strings.Contains(string(body), "credential-that-must-not-enter-a-plan") {
		t.Fatal("plan exposed inherited credentials")
	}
	if _, err := os.Stat(filepath.Join(root, ".artifacts")); !os.IsNotExist(err) {
		t.Fatal("read-only plan executed a project stage or materialized tools")
	}
}

func TestVerificationPolicyCannotOmitRequiredStagesOrInjectTargets(t *testing.T) {
	root, _ := selectionFixture(t)
	for _, mutate := range []func(*Manifest){
		func(m *Manifest) { m.Verification.FullTargets = []string{"lint"} },
		func(m *Manifest) { m.Verification.FullTargets = []string{"lint", "unit", "integration", "build;true"} },
		func(m *Manifest) { m.Verification.Rules[0].Paths = []string{"../outside"} },
		func(m *Manifest) { m.Verification.Always = []string{"missing"} },
	} {
		m, _, err := Read(root)
		if err != nil {
			t.Fatal(err)
		}
		original, _ := os.ReadFile(filepath.Join(root, ManifestName))
		mutate(&m)
		if err := writeJSON(filepath.Join(root, ManifestName), m); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Read(root); err == nil {
			t.Fatal("invalid verification policy accepted")
		}
		if err := os.WriteFile(filepath.Join(root, ManifestName), original, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFocusedVerificationDoesNotMintCompleteTestEvidence(t *testing.T) {
	t.Setenv("KOMIZO_CACHE_DIR", t.TempDir())
	root, _ := selectionFixture(t)
	mise := filepath.Join(t.TempDir(), "mise")
	if err := os.WriteFile(mise, []byte("#!/bin/sh\nshift 2\nexec \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	tool := func(context.Context) (string, error) { return mise, nil }
	run := func(targets ...string) {
		t.Helper()
		if _, err := execute(context.Background(), root, "test-platform", targets, "local", nil, nil, io.Discard, tool); err != nil {
			t.Fatal(err)
		}
	}
	run("lint", "unit")
	if _, err := os.Stat(filepath.Join(root, ".artifacts/contract/test.json")); !os.IsNotExist(err) {
		t.Fatal("partial selection created a complete test receipt")
	}
	run("lint", "unit", "integration")
	body, err := os.ReadFile(filepath.Join(root, ".artifacts/contract/test.json"))
	if err != nil || !strings.Contains(string(body), `"unit"`) || !strings.Contains(string(body), `"integration"`) {
		t.Fatal("actual complete tests did not produce bound evidence", err, string(body))
	}
}

func TestGitInventoryBoundCannotBeBypassedByCopyInterfaces(t *testing.T) {
	var output boundedGitOutput
	count, err := io.Copy(&output, strings.NewReader(strings.Repeat("a", (1<<20)+1)))
	if err != nil || count != (1<<20)+1 || output.buffer.Len() > 1<<20 || !output.truncated {
		t.Fatal("Git inventory was not drained under a finite retention bound")
	}
}

func TestIncompleteInputInventoryAlwaysRequiresCompleteVerification(t *testing.T) {
	t.Setenv("GITHUB_EVENT_NAME", "local")
	root, base := selectionFixture(t)
	folder := filepath.Join(root, "docs")
	if err := os.Mkdir(folder, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4200; i++ {
		name := filepath.Join(folder, fmt.Sprintf("page-%04d.md", i))
		if err := os.WriteFile(name, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	plan, err := Plan(context.Background(), root, "test-platform", base)
	if err != nil || plan.Mode != "full" || !plan.PathsTruncated || len(plan.ChangedPaths) > 4096 {
		t.Fatal(plan.Mode, plan.PathsTruncated, len(plan.ChangedPaths), err)
	}
	body, err := json.Marshal(plan)
	if err != nil || len(body) > 4<<20 {
		t.Fatal("plan exceeded machine output budget", len(body), err)
	}
}
