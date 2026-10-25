package devenv

import (
	"errors"
	"os"
	"os/exec"
	"slices"
	"testing"
)

func TestDevelopmentEnvironment(t *testing.T) {
	result := developmentEnvironment([]string{"PATH=/tools", "HOME=/developer", "TERM=xterm", "GH_TOKEN=parent-token", "RUNTIME_DATABASE_URL=remote", "OPENAI_API_KEY=production", "BASH_ENV=/unsafe", "NODE_OPTIONS=--require=unsafe", "MAKEFLAGS=CLERK_SECRET_KEY=old", "EXPO_PUBLIC_API_URL=https://remote", "EXPO_NO_DOTENV=0"}, map[string]string{"OPENAI_API_KEY": "preview"})
	for _, want := range []string{"PATH=/tools", "HOME=/developer", "TERM=xterm", "OPENAI_API_KEY=preview", "EXPO_NO_DOTENV=1"} {
		if !slices.Contains(result, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if len(result) != 5 {
		t.Fatal("unapproved parent settings reached child")
	}
}

func TestCleanLaunch(t *testing.T) {
	if os.Getenv("GHENV_CLEAN_CHILD") == "yes" {
		if os.Getenv("GH_TOKEN") != "" || os.Getenv("RUNTIME_DATABASE_URL") != "" || os.Getenv("EXPO_NO_DOTENV") != "1" || os.Getenv("TOKEN") != "synthetic\n'quoted'" {
			os.Exit(9)
		}
		os.Exit(23)
	}
	t.Setenv("GH_TOKEN", "parent-auth-only")
	t.Setenv("RUNTIME_DATABASE_URL", "must-not-reach-app")
	env := developmentEnvironment(os.Environ(), map[string]string{"GHENV_CLEAN_CHILD": "yes", "TOKEN": "synthetic\n'quoted'"})
	err := launchEnvironment([]string{os.Args[0], "-test.run=^TestCleanLaunch$"}, env, shutdownGrace)
	var status *exec.ExitError
	if !errors.As(err, &status) || status.ExitCode() != 23 {
		t.Fatalf("clean child failed: %v", err)
	}
	if os.Getenv("GH_TOKEN") != "parent-auth-only" {
		t.Fatal("parent authentication changed")
	}
}
