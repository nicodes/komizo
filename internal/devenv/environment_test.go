package devenv

import (
	"errors"
	"github.com/nicodes/ghenv/provider"
	"os"
	"os/exec"
	"testing"
)

func TestCleanLaunch(t *testing.T) {
	if os.Getenv("GHENV_CLEAN_CHILD") == "yes" {
		if os.Getenv("GH_TOKEN") != "" || os.Getenv("RUNTIME_DATABASE_URL") != "" || os.Getenv("EXPO_NO_DOTENV") != "1" || os.Getenv("TOKEN") != "synthetic\n'quoted'" {
			os.Exit(9)
		}
		os.Exit(23)
	}
	t.Setenv("GH_TOKEN", "parent-auth-only")
	t.Setenv("RUNTIME_DATABASE_URL", "must-not-reach-app")
	env := provider.DevelopmentEnvironment(os.Environ(), map[string]string{"GHENV_CLEAN_CHILD": "yes", "TOKEN": "synthetic\n'quoted'"})
	err := launchEnvironment([]string{os.Args[0], "-test.run=^TestCleanLaunch$"}, env, shutdownGrace)
	var status *exec.ExitError
	if !errors.As(err, &status) || status.ExitCode() != 23 {
		t.Fatalf("clean child failed: %v", err)
	}
	if os.Getenv("GH_TOKEN") != "parent-auth-only" {
		t.Fatal("parent authentication changed")
	}
}
