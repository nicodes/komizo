package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func planFixture(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	key, model := filepath.Join(dir, "identity.key"), filepath.Join(dir, "model.json")
	write(t, key, 0o600, strings.Repeat("k", 32))
	write(t, model, 0o600, `{
  "services":{"api":{"image":"example/api@sha256:`+strings.Repeat("a", 64)+`","environment":{"PRIVATE":"synthetic-password"}}},
  "x-komizo":{"version":1,"services":{"api":{"mode":"request","port":8080,"ready_path":"/readyz","candidate_safe":true}}}
}`)
	return key, model
}

func TestPlanLocalAnalysis(t *testing.T) {
	key, model := planFixture(t)
	for _, before := range [][]string{{"--initial"}, {"--before", model}} {
		args := append([]string{"--after", model, "--key-file", key}, before...)
		var out, diagnostics bytes.Buffer
		if err := runPlan(args, &out, &diagnostics); err != nil {
			t.Fatal(err)
		}
		var result struct {
			AnalysisOnly bool `json:"analysis_only"`
			Services     []struct {
				Service, Change, Mode string
			} `json:"services"`
		}
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		want := "unchanged"
		if before[0] == "--initial" {
			want = "added"
		}
		if !result.AnalysisOnly || len(result.Services) != 1 || result.Services[0].Change != want || result.Services[0].Service != "api" || result.Services[0].Mode != "request" {
			t.Fatalf("unexpected analysis: %s", out.String())
		}
		for _, sensitive := range []string{"synthetic-password", "PRIVATE", strings.Repeat("k", 32), "sha256:"} {
			if strings.Contains(out.String()+diagnostics.String(), sensitive) {
				t.Fatal("analysis exposed private input")
			}
		}
	}
}

func TestPlanRefusesAmbiguousInvocation(t *testing.T) {
	key, model := planFixture(t)
	for _, args := range [][]string{
		{}, {"--after", model, "--key-file", key},
		{"--before", model, "--initial", "--after", model, "--key-file", key},
		{"--initial", "--after", model, "--key-file", key, "extra"},
	} {
		var out, diag bytes.Buffer
		if err := runPlan(args, &out, &diag); err == nil || out.Len() != 0 {
			t.Fatalf("invalid invocation produced %q, %v", out.String(), err)
		}
	}
}

func TestPlanDoesNotEchoMalformedPrivateInput(t *testing.T) {
	key, model := planFixture(t)
	write(t, model, 0o600, `{"synthetic-password":`)
	var out, diag bytes.Buffer
	err := runPlan([]string{"--initial", "--after", model, "--key-file", key}, &out, &diag)
	if err == nil || out.Len() != 0 || strings.Contains(err.Error()+diag.String(), "synthetic-password") {
		t.Fatalf("unsafe error output: %v %q %q", err, out.String(), diag.String())
	}
}

func TestPlanPrivateKeyAndRegularFileChecks(t *testing.T) {
	key, model := planFixture(t)
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPlanFile(key, 32, true); err == nil {
		t.Fatal("world-readable identity key accepted")
	}
	link := filepath.Join(filepath.Dir(model), "link")
	if err := os.Symlink(model, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, filepath.Dir(model), filepath.Join(filepath.Dir(model), "missing")} {
		if _, err := readPlanFile(path, 100, false); err == nil {
			t.Fatal("non-regular file accepted")
		}
	}
	if _, err := readPlanFile(model, 1, false); err == nil {
		t.Fatal("oversized file accepted")
	}
}

func TestPlanHelpAndFlagFailure(t *testing.T) {
	var out, diag bytes.Buffer
	if err := runPlan([]string{"--help"}, &out, &diag); err != nil || diag.Len() == 0 {
		t.Fatalf("help: %v", err)
	}
	if err := runPlan([]string{"--unknown"}, &out, &diag); !errors.Is(err, ErrSilent) {
		t.Fatalf("flag failure: %v", err)
	}
}
