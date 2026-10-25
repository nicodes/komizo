package devenv

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func projectFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ghenv.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

const fixtureProject = `{"version":1,"repository":"owner/project","default_mode":"preview","secrets":"API_KEY","variables":"PUBLIC_KEY","prefixes":{"API_KEY":"test_"},"aliases":{"PUBLIC_ALIAS":"PUBLIC_KEY"},"environment":{"BUN_OPTIONS":"--no-env-file"}}`

func TestProjectConfigurationRefusesAmbiguity(t *testing.T) {
	cases := []string{
		strings.Replace(fixtureProject, `"version":1`, `"version":2`, 1),
		strings.Replace(fixtureProject, `"default_mode":"preview"`, `"default_mode":"Production"`, 1),
		strings.Replace(fixtureProject, `"repository":"owner/project"`, `"repository":"owner/.."`, 1),
		strings.Replace(fixtureProject, `"secrets":"API_KEY"`, `"secrets":"API_KEY,API_KEY"`, 1),
		strings.Replace(fixtureProject, `"secrets":"API_KEY"`, `"secrets":"GITHUB_TOKEN"`, 1),
		strings.Replace(fixtureProject, `"API_KEY":"test_"`, `"UNKNOWN":"test_"`, 1),
		strings.Replace(fixtureProject, `"PUBLIC_ALIAS":"PUBLIC_KEY"`, `"PUBLIC_ALIAS":"UNKNOWN"`, 1),
		strings.Replace(fixtureProject, `"PUBLIC_ALIAS":"PUBLIC_KEY"`, `"API_KEY":"PUBLIC_KEY"`, 1),
		strings.Replace(fixtureProject, `"BUN_OPTIONS":"--no-env-file"`, `"PUBLIC_ALIAS":"collision"`, 1),
		strings.Replace(fixtureProject, `"BUN_OPTIONS":"--no-env-file"`, `"API_KEY":"collision"`, 1),
		strings.Replace(fixtureProject, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(fixtureProject, `"secrets"`, `"Secrets"`, 1),
		strings.Replace(fixtureProject, `"secrets"`, `"ſecrets"`, 1),
		fixtureProject + `{}`, `{}`, `null`, strings.Repeat(" ", maxBundle+1),
	}
	for i, content := range cases {
		if _, err := readProject(projectFile(t, content)); err == nil {
			t.Errorf("case %d accepted invalid project", i)
		}
	}
}

func TestProjectPreviewSelectionAndIsolation(t *testing.T) {
	p, err := readProject(projectFile(t, fixtureProject))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	fetch := func(_ context.Context, o options) (map[string]string, error) {
		calls++
		if o.Repo != "owner/project" || o.Environment != "Preview" || o.Ref != "main" || o.Secrets != "API_KEY" || o.Variables != "PUBLIC_KEY" || !o.CleanEnvironment {
			t.Fatalf("wrong request: %+v", o)
		}
		return map[string]string{"API_KEY": "test_synthetic\nquoted ' $()", "PUBLIC_KEY": "public"}, nil
	}
	env, err := projectEnvironment(context.Background(), p, "auto", []string{"PATH=/tools", "GH_TOKEN=parent-secret", "API_KEY=parent", "BUN_OPTIONS=--preload=bad", "EXPO_NO_DOTENV=0", "REMOTE_DATABASE_URL=parent"}, fetch)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, item := range env {
		name, value, _ := strings.Cut(item, "=")
		got[name] = value
	}
	if calls != 1 || got["API_KEY"] != "test_synthetic\nquoted ' $()" || got["PUBLIC_ALIAS"] != "public" || got["PUBLIC_KEY"] != "public" || got["PATH"] != "/tools" || got["BUN_OPTIONS"] != "--no-env-file" || got["EXPO_NO_DOTENV"] != "1" {
		t.Fatal("incorrect development environment")
	}
	if _, ok := got["GH_TOKEN"]; ok {
		t.Fatal("parent credential inherited")
	}
	if _, ok := got["REMOTE_DATABASE_URL"]; ok {
		t.Fatal("remote database inherited")
	}
}

func TestProjectOfflineAndEmptySelectionNeverFetch(t *testing.T) {
	p, err := readProject(projectFile(t, fixtureProject))
	if err != nil {
		t.Fatal(err)
	}
	never := func(context.Context, options) (map[string]string, error) {
		t.Fatal("offline mode contacted GitHub")
		return nil, nil
	}
	for _, mode := range []string{"local", "auto"} {
		if mode == "auto" {
			p.DefaultMode = "local"
		}
		env, err := projectEnvironment(context.Background(), p, mode, []string{"API_KEY=parent", "PUBLIC_ALIAS=parent"}, never)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range env {
			if strings.HasPrefix(item, "API_KEY=") || strings.HasPrefix(item, "PUBLIC_ALIAS=") {
				t.Fatal("offline mode inherited remote credentials")
			}
		}
	}
	p, err = readProject(projectFile(t, `{"version":1,"repository":"owner/project","default_mode":"local","environment":{"BUN_OPTIONS":"--no-env-file"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = projectEnvironment(context.Background(), p, "preview", nil, never); err != nil {
		t.Fatal(err)
	}
}

func TestProjectRefusesBadHandoffWithoutExposingValues(t *testing.T) {
	p, err := readProject(projectFile(t, fixtureProject))
	if err != nil {
		t.Fatal(err)
	}
	for _, values := range []map[string]string{
		{"API_KEY": "live_do_not_print", "PUBLIC_KEY": "public"},
		{"API_KEY": "test_synthetic"},
		{"API_KEY": "test_synthetic", "PUBLIC_KEY": "public", "OTHER": "do_not_print"},
		{"API_KEY": "test_synthetic\x00do_not_print", "PUBLIC_KEY": "public"},
	} {
		fetch := func(context.Context, options) (map[string]string, error) { return values, nil }
		if _, err = projectEnvironment(context.Background(), p, "preview", nil, fetch); err == nil || strings.Contains(err.Error(), "do_not_print") {
			t.Fatal("invalid handoff accepted or exposed its values")
		}
	}
	fetch := func(context.Context, options) (map[string]string, error) { return nil, errors.New("handoff failed") }
	if _, err = projectEnvironment(context.Background(), p, "preview", nil, fetch); err == nil {
		t.Fatal("failed handoff fell back to another mode")
	}
	never := func(context.Context, options) (map[string]string, error) {
		t.Fatal("invalid mode contacted GitHub")
		return nil, nil
	}
	if _, err = projectEnvironment(context.Background(), p, "production", nil, never); err == nil {
		t.Fatal("accepted production mode")
	}
}
