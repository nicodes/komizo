//go:build native_source_test

package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the current verified-source preparation and real Rust/Go compilers.
// Native CI opts into this test; the ordinary Go race suite stays bounded.
func TestVerifiedSourceBuildCarriesTheRustAPI(t *testing.T) {
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatal(err)
	}
	scratch := t.TempDir()
	archive := filepath.Join(scratch, "source.tar")
	command := exec.Command("git", "archive", "--format=tar", "--output", archive, "HEAD")
	command.Dir = strings.TrimSpace(string(root))
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("archive source: %v: %s", err, out)
	}
	source := filepath.Join(scratch, "verified")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("tar", "-xf", archive, "-C", source).CombinedOutput(); err != nil {
		t.Fatalf("unpack: %v: %s", err, out)
	}
	prepared := filepath.Join(scratch, "private-copy")
	if err := prepareNativeSource(context.Background(), source, prepared, "amd64"); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(scratch, "komizo-box")
	command = exec.Command("go", "build", "-tags", "rustapi", "-trimpath", "-o", binary, "./cmd/komizo-box")
	command.Dir = prepared
	command.Env = goBuildEnv("amd64")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build agent: %v: %s", err, out)
	}
	// No credential means the Rust monitor refuses to open a socket. Its own
	// diagnostic proves the executable was embedded and launched successfully.
	command = exec.Command(binary, "serve", "--config", filepath.Join(scratch, "missing.json"), "--socket", filepath.Join(scratch, "api.sock"))
	command.Env = append(os.Environ(), "PATH=/usr/bin:/bin", "KOMIZO_API_BINARY=")
	out, err := command.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "this box has no registry key") {
		t.Fatalf("bundled Rust monitor: %v: %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(scratch, "api.sock")); !os.IsNotExist(err) {
		t.Fatalf("unenrolled monitor created a listener: %v", err)
	}
}
