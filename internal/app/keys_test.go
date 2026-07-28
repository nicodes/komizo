package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratedKeysAreRealOpenSSHKeys(t *testing.T) {
	// The encoder is hand-written, so this checks it against the only opinion
	// that matters: ssh-keygen's. A key this tool cannot read is a deploy that
	// fails in CI with an authentication error and no hint as to why.
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("no ssh-keygen")
	}
	kp, err := newKeypair(keyComment("komizo-blog", "box.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(kp.private, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Errorf("private key does not look like one:\n%s", kp.private)
	}
	if !strings.HasPrefix(kp.public, "ssh-ed25519 ") {
		t.Errorf("public key does not look like one: %q", kp.public)
	}
	if !strings.HasSuffix(kp.public, "komizo:komizo-blog@box.example.com") {
		t.Errorf("the comment is what a rotation matches on: %q", kp.public)
	}

	// ssh-keygen -y derives the public key from the private one. It parses the
	// container, the padding and the key itself to do it.
	dir := t.TempDir()
	path := filepath.Join(dir, "id")
	if err := os.WriteFile(path, []byte(kp.private), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("ssh-keygen", "-y", "-f", path).Output()
	if err != nil {
		t.Fatalf("ssh-keygen could not read the private key: %v", err)
	}
	// Its output has no comment, so compare the two fields that carry the key.
	got := strings.Fields(strings.TrimSpace(string(out)))
	want := strings.Fields(kp.public)
	if len(got) < 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("the private key does not match its public half:\n got %v\nwant %v", got, want[:2])
	}

	// And two keys are two keys.
	other, _ := newKeypair("komizo:x@y")
	if other.private == kp.private {
		t.Error("every keypair should be new")
	}
}
