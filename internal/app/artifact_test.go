package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAgentArtifactCannotOverwriteFileOrFollowLink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent")
	if err := writeAgentArtifact(path, []byte("accepted-release")); err != nil {
		t.Fatal(err)
	}
	if err := writeAgentArtifact(path, []byte("foreign")); err == nil {
		t.Fatal("existing artifact overwritten")
	}
	link := filepath.Join(dir, "foreign-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := writeAgentArtifact(link, []byte("foreign")); err == nil {
		t.Fatal("artifact followed a link")
	}
	body, _ := os.ReadFile(path)
	if string(body) != "accepted-release" {
		t.Fatal("accepted bytes changed")
	}
}
