package project

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const workflowFixture = `name: Build & Test
on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]
  workflow_dispatch:
jobs:
  check:
    name: Check
    runs-on: ubuntu-24.04
    steps:
      - uses: owner/action@0123456789012345678901234567890123456789
      - run: 'true'
`

func workflowProject(t *testing.T, workflow string) string {
	t.Helper()
	root := manifestFixture(t, `{"version":1,"recipe":"static-site"}`)
	if err := os.MkdirAll(filepath.Join(root, ".github/workflows"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".github/workflows/ci.yml"), []byte(workflow), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteLock(root, "test-platform"); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestWorkflowValidationRefusesUnsafeInputs(t *testing.T) {
	for name, workflow := range map[string]string{
		"mutable action":                strings.ReplaceAll(workflowFixture, "0123456789012345678901234567890123456789", "main"),
		"duplicate key":                 strings.Replace(workflowFixture, "    name: Check", "    name: Check\n    name: Different", 1),
		"missing ready event":           strings.ReplaceAll(workflowFixture, ", ready_for_review", ""),
		"missing manual event":          strings.ReplaceAll(workflowFixture, "  workflow_dispatch:\n", ""),
		"wrong purpose":                 strings.Replace(workflowFixture, "name: Build & Test", "name: Other", 1),
		"no implementation":             strings.Replace(workflowFixture, "    steps:\n      - uses: owner/action@0123456789012345678901234567890123456789\n      - run: 'true'\n", "", 1),
		"untrusted privileged checkout": workflowFixture + "  policy:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@0123456789012345678901234567890123456789\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
	} {
		t.Run(name, func(t *testing.T) {
			if name == "untrusted privileged checkout" {
				workflow = strings.Replace(workflow, "  workflow_dispatch:", "  workflow_dispatch:\n  pull_request_target:", 1)
			}
			if _, err := Validate(workflowProject(t, workflow), "test-platform"); err == nil {
				t.Fatal("unsafe workflow accepted")
			}
		})
	}
}

func TestWorkflowValidationChecksActualRequiredGates(t *testing.T) {
	root := workflowProject(t, workflowFixture)
	if report, err := Validate(root, "test-platform"); err != nil || len(report.Workflows) != 1 {
		t.Fatalf("%#v %v", report, err)
	}
	m, _, _ := Read(root)
	m.Validation = map[string]json.RawMessage{"workflow": json.RawMessage(`{"required":["ci.yml"],"ci_gates":["Check","Build"]}`)}
	if err := writeJSON(filepath.Join(root, ManifestName), m); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteLock(root, "test-platform"); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(root, "test-platform"); err == nil {
		t.Fatal("missing required Build gate accepted")
	}
}

func TestLocalRecipeDoesNotRequireGitHub(t *testing.T) {
	root := manifestFixture(t, `{"version":1,"recipe":"static-site"}`)
	if _, err := WriteLock(root, "test-platform"); err != nil {
		t.Fatal(err)
	}
	r, err := Validate(root, "test-platform")
	if err != nil || len(r.Workflows) != 0 || len(r.Checks) != 2 {
		t.Fatalf("%#v %v", r, err)
	}
}

func TestHandoffCannotSelectProduction(t *testing.T) {
	root := workflowProject(t, workflowFixture)
	path := filepath.Join(root, ".github/workflows/ghenv.yml")
	content := "name: Local Environment\non:\n  workflow_dispatch:\njobs:\n  export:\n    runs-on: ubuntu-24.04\n    environment: Production\n    steps:\n      - run: 'true'\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(root, "test-platform"); err == nil {
		t.Fatal("production handoff accepted")
	}
	if err := os.WriteFile(path, []byte(strings.Replace(content, "Production", "Preview", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(root, "test-platform"); err != nil {
		t.Fatal(err)
	}
}

func TestReleaseWorkflowRetainsSerializationAndMainTrust(t *testing.T) {
	root := workflowProject(t, workflowFixture)
	path := filepath.Join(root, ".github/workflows/cd.yml")
	content := "name: Deploy\non:\n  push:\n    branches: [main]\n  workflow_dispatch:\nconcurrency:\n  group: deploy-production\n  cancel-in-progress: false\njobs:\n  deploy:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: 'true'\n"
	for name, bad := range map[string]string{"cancellation": strings.Replace(content, "cancel-in-progress: false", "cancel-in-progress: true", 1), "foreign branch": strings.Replace(content, "branches: [main]", "branches: [feature]", 1)} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Validate(root, "test-platform"); err == nil {
				t.Fatal("unsafe deployment accepted")
			}
		})
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(root, "test-platform"); err != nil {
		t.Fatal(err)
	}
}

func TestNamedOperationsCannotBeSuccessfulPlaceholders(t *testing.T) {
	for _, command := range []string{"true", "echo", ":"} {
		root := manifestFixture(t, `{"version":1,"recipe":"static-site","tasks":{"production-verification":[["`+command+`"]]}}`)
		if _, err := WriteLock(root, "test-platform"); err != nil {
			t.Fatal(err)
		}
		// A project without CI still validates its fixed operational tasks.
		if _, err := Validate(root, "test-platform"); err == nil {
			t.Fatal("successful operational placeholder accepted", command)
		}
	}
}
