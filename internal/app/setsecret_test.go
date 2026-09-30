package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The remote command is assembled here, and the value is not part of it.
//
// That is the whole security property of the shape: arguments are visible in
// the host's process list to every other user on the box, so the name travels
// in argv and the bytes travel on stdin. A test that only checked the flags
// would miss the one mistake that matters.
func TestTheRemoteCommandNeverCarriesTheValue(t *testing.T) {
	cmd, err := setSecretCommand("cazper", "openai_api_key", "65534", true)
	if err != nil {
		t.Fatal(err)
	}
	want := "/usr/local/bin/set-secret-cazper --uid 65534 --file openai_api_key"
	if cmd != want {
		t.Errorf("remote command\n want %q\n got  %q", want, cmd)
	}
}

func TestTheEnvShapeBuildsThePlainCommand(t *testing.T) {
	cmd, err := setSecretCommand("blog", "CLERK_SECRET_KEY", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if cmd != "/usr/local/bin/set-secret-blog CLERK_SECRET_KEY" {
		t.Errorf("got %q", cmd)
	}
}

// Names are checked locally so a mistake is a message rather than a failed
// round trip -- and so nothing assembled into the remote command can be
// anything but a command and two safe words.
func TestSetSecretRefusesNamesThatCouldBeSomethingElse(t *testing.T) {
	for _, c := range []struct {
		name, secret, uid string
		asFile            bool
	}{
		{"env name with a dot", "recipient.pem", "", false},
		{"env name with a space", "A B", "", false},
		{"file name with a slash", "../../etc/shadow", "", true},
		{"file name that is dotdot", "..", "", true},
		{"hidden file name", ".env", "", true},
		{"file name starting with a hyphen", "-rf", "", true},
		{"file name with a space", "two words", "", true},
		{"empty name", "", "", true},
		{"non-numeric uid", "key", "nobody", true},
		{"uid without file", "KEY", "65534", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if cmd, err := setSecretCommand("blog", c.secret, c.uid, c.asFile); err == nil {
				t.Errorf("accepted, and built %q", cmd)
			}
		})
	}
}

// A name that is only wrong for the shape chosen should say which shape it
// wants. Nearly every file secret in the portfolio has a dot in it.
func TestAnEnvNameWithADotSuggestsFile(t *testing.T) {
	_, err := setSecretCommand("blog", "postgres-owner.env", "", false)
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if !strings.Contains(err.Error(), "--file") {
		t.Errorf("the refusal does not point at --file:\n%v", err)
	}
}

// Bytes, not text. A file secret may be a PEM or a binary identity and its
// trailing newline is part of it -- the env shape strips one with $(cat),
// which is exactly the difference the file shape exists for.
func TestTheValueIsReadAsBytesIncludingTheTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	const content = "-----BEGIN KEY-----\nabc\n-----END KEY-----\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readSecretValue(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != content {
		t.Errorf("value changed in transit.\nwant %q\ngot  %q", content, got)
	}
}

func TestAMissingValueFileIsReportedWithItsPath(t *testing.T) {
	_, err := readSecretValue(filepath.Join(t.TempDir(), "nope"))
	if err == nil || !strings.Contains(err.Error(), "nope") {
		t.Errorf("want an error naming the path, got %v", err)
	}
}
