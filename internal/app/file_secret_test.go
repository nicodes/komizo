package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nicodes/komizo/scripts"
)

// set-secret's file shape, run for real against a fixture directory.
//
// WHY IT EXISTS. The env shape refuses "a value that contains a newline,
// which an env file cannot represent", and every multi-line credential in
// the portfolio went round that refusal the same way: somebody wrote the file
// onto the box by hand over SSH. Ten such files across five apps -- an OpenAI
// key that has to be mounted rather than exported, an age backup identity, a
// postgres owner password the database reads before the app exists -- none of
// them delivered by anything, none rotatable without a shell. That is the
// single biggest source of hand-placed state on these servers.
//
// The script is extracted and run, not read: what matters is the bytes that
// land on disk and the mode they land with.
type setterBox struct{ dir, bin string }

func newSetterBox(t *testing.T) *setterBox {
	t.Helper()
	needs(t, "sh")
	root := t.TempDir()
	appDir := filepath.Join(root, "srv", "blog")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(appDir, "secrets.env"), 0o600, "EXISTING=keep\n")
	state := filepath.Join(root, "blog.env")
	write(t, state, 0o600, "CI_USER=komizo-blog\n")

	body := between(t, scripts.AlpineScript,
		`cat > "$SECRET_BIN.tmp" <<'KOMIZO_SECRET_EOF'`, "KOMIZO_SECRET_EOF")
	body = strings.NewReplacer("__APP_DIR__", appDir, "__STATE_FILE__", state).Replace(body)
	bin := filepath.Join(root, "set-secret-blog")
	write(t, bin, 0o755, body)
	return &setterBox{dir: appDir, bin: bin}
}

func (b *setterBox) run(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("sh", append([]string{b.bin}, args...)...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// The thing the env shape cannot do at all.
func TestFileSecretAcceptsAMultiLineValue(t *testing.T) {
	b := newSetterBox(t)
	const pem = "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADAN\n-----END PRIVATE KEY-----\n"

	if out, err := b.run(t, pem, "--file", "recipient.pem"); err != nil {
		t.Fatalf("a multi-line file secret was refused: %v\n%s", err, out)
	}
	got, err := os.ReadFile(filepath.Join(b.dir, "secrets", "recipient.pem"))
	if err != nil {
		t.Fatalf("the file was not written: %v", err)
	}
	// Byte-for-byte, INCLUDING the trailing newline. The env shape uses
	// $(cat), which strips it; a PEM without its final newline is one some
	// parsers refuse, and a base64 age identity is not a thing to be lenient
	// with either.
	if string(got) != pem {
		t.Errorf("the file is not what was piped in.\nwant %q\ngot  %q", pem, got)
	}
}

// Mode and ownership, because a secret readable by other users on the box is
// not a secret, and one the container cannot read is an outage.
func TestFileSecretIsOwnerOnlyAndItsDirectoryToo(t *testing.T) {
	b := newSetterBox(t)
	if out, err := b.run(t, "sk-xxx", "--file", "openai_api_key"); err != nil {
		t.Fatalf("run failed: %v\n%s", err, out)
	}
	for path, want := range map[string]os.FileMode{
		filepath.Join(b.dir, "secrets"):                   0o700,
		filepath.Join(b.dir, "secrets", "openai_api_key"): 0o600,
	} {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Mode().Perm(); got != want {
			t.Errorf("%s is mode %04o, want %04o", path, got, want)
		}
	}
}

// The value must never be echoed. set-secret's whole shape -- value on stdin,
// never an argument -- exists so a credential does not reach the process list
// or a CI log, and the file path must not undo that.
func TestFileSecretNeverEchoesTheValue(t *testing.T) {
	b := newSetterBox(t)
	const value = "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQ"
	out, err := b.run(t, value, "--file", "backup-age-identity")
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, out)
	}
	if strings.Contains(out, value) {
		t.Errorf("the secret value was printed:\n%s", out)
	}
	if !strings.Contains(out, "backup-age-identity") {
		t.Errorf("the run does not say which file it wrote:\n%s", out)
	}
}

// A name must not escape secrets/.
func TestFileSecretRefusesNamesThatEscapeTheDirectory(t *testing.T) {
	for _, name := range []string{"../evil", "a/b", "..", ".hidden", "-rf", ""} {
		t.Run(name, func(t *testing.T) {
			b := newSetterBox(t)
			out, err := b.run(t, "x", "--file", name)
			if err == nil {
				t.Fatalf("%q was accepted as a file secret name:\n%s", name, out)
			}
			// Nothing may be left behind by a refused write.
			if entries, _ := os.ReadDir(filepath.Join(b.dir, "secrets")); len(entries) > 0 {
				t.Errorf("a refused write left %d file(s) in secrets/", len(entries))
			}
		})
	}
}

// The two shapes must not interfere: a file write leaves secrets.env alone.
func TestFileSecretDoesNotTouchSecretsEnv(t *testing.T) {
	b := newSetterBox(t)
	if _, err := b.run(t, "x", "--file", "postgres-owner.env"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(b.dir, "secrets.env"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "EXISTING=keep\n" {
		t.Errorf("secrets.env changed during a file write: %q", got)
	}
}

// And the env shape still works exactly as before.
func TestTheEnvShapeIsUnchanged(t *testing.T) {
	b := newSetterBox(t)
	if out, err := b.run(t, "hunter2", "CLERK_SECRET_KEY"); err != nil {
		t.Fatalf("the env shape broke: %v\n%s", err, out)
	}
	got, err := os.ReadFile(filepath.Join(b.dir, "secrets.env"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "CLERK_SECRET_KEY=hunter2") || !strings.Contains(string(got), "EXISTING=keep") {
		t.Errorf("secrets.env is wrong after an env write: %q", got)
	}
	// The newline refusal is the reason the file shape exists; it must still
	// be there for the env shape.
	if out, err := b.run(t, "one\ntwo", "MULTI"); err == nil {
		t.Errorf("the env shape accepted a newline:\n%s", out)
	}
}

// --uid is only meaningful for a file, and must be numeric.
func TestUidIsValidatedAndFileOnly(t *testing.T) {
	b := newSetterBox(t)
	if out, err := b.run(t, "x", "--uid", "nobody", "--file", "k"); err == nil {
		t.Errorf("a non-numeric --uid was accepted:\n%s", out)
	}
	if out, err := b.run(t, "x", "--uid", "65534", "ENVKEY"); err == nil {
		t.Errorf("--uid was accepted for the env shape:\n%s", out)
	}
}

// The round trip: a file secret komizo writes must be one komizo can find
// and one komizo can take off again.
//
// "Delivered but not removable" is the one-way door alpine-unset-secret.sh
// was written to close for env keys. Adding a second shape that only the
// write half knows about would reopen it -- and worse than before, because a
// file secret is invisible to `--list` unless the listing knows to look.
func TestFileSecretsCanBeListedAndRemoved(t *testing.T) {
	needs(t, "sh")
	b := newSetterBox(t)
	if _, err := b.run(t, "AGE-SECRET-KEY-1TEST", "--file", "backup-age-identity"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.run(t, "pw", "--file", "postgres-owner.env"); err != nil {
		t.Fatal(err)
	}

	unset := func(t *testing.T, env ...string) (string, error) {
		t.Helper()
		cmd := exec.Command("sh", "-s")
		cmd.Stdin = strings.NewReader(scripts.AlpineUnsetSecretScript)
		cmd.Env = append(os.Environ(), append([]string{
			"APP_NAME=blog", "APP_DIR=" + b.dir,
		}, env...)...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	out, err := unset(t, "LIST=1")
	if err != nil {
		t.Fatalf("list failed: %v\n%s", err, out)
	}
	for _, want := range []string{"file:backup-age-identity", "file:postgres-owner.env", "EXISTING"} {
		if !strings.Contains(out, want) {
			t.Errorf("--list does not mention %s, so nobody can find it:\n%s", want, out)
		}
	}

	out, err = unset(t, "NAMES=file:backup-age-identity")
	if err != nil {
		t.Fatalf("removing a file secret failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(b.dir, "secrets", "backup-age-identity")); !os.IsNotExist(err) {
		t.Error("the file secret is still in place after being removed")
	}
	// Moved aside, not unlinked: the value may be the last copy of something.
	bak, _ := filepath.Glob(filepath.Join(b.dir, "secrets", "backup-age-identity.*.bak"))
	if len(bak) != 1 {
		t.Errorf("want one dated copy of the removed file secret, got %v", bak)
	}
	// The other one is untouched, and so is secrets.env -- a file-only
	// removal must not rewrite or back up a file it never changed.
	if _, err := os.Stat(filepath.Join(b.dir, "secrets", "postgres-owner.env")); err != nil {
		t.Errorf("an unrelated file secret was removed too: %v", err)
	}
	if stray, _ := filepath.Glob(filepath.Join(b.dir, "secrets.env.*.bak")); len(stray) != 0 {
		t.Errorf("a file-only removal backed up secrets.env, which it never touched: %v", stray)
	}
}

// A name that is not there must stop the run, for files as it already does
// for env keys: a tidy-up that reports success without doing anything is how
// stale secrets survive several people looking at them.
func TestRemovingAnAbsentFileSecretRefuses(t *testing.T) {
	needs(t, "sh")
	b := newSetterBox(t)
	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(scripts.AlpineUnsetSecretScript)
	cmd.Env = append(os.Environ(), "APP_NAME=blog", "APP_DIR="+b.dir, "NAMES=file:never-existed")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("removing an absent file secret reported success:\n%s", out)
	}
	if !strings.Contains(string(out), "never-existed") {
		t.Errorf("the refusal does not name the missing secret:\n%s", out)
	}
}
