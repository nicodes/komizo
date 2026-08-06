package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nicodes/komizo/scripts"
)

// /etc/doas.conf is the file that decides what a deploy account may do as root,
// and alpine.sh rewrites it on every `komizo add`.
//
// This is the gap the audit called H2. The block was deleted, re-appended and
// then validated with `doas -C` -- and if that validation failed the script
// exited leaving the invalid file in place. doas refuses to run at all against
// a config it cannot parse, so a rejected edit did not break the app being set
// up: it broke EVERY app on the box, from an operation scoped to one of them,
// with no way back except editing the file by hand over the connection komizo
// had just used.
//
// It was also the odd one out. The same script backs up sshd_config and
// restores it on any failure, and alpine-remove.sh backs up this very file. Only
// the create path skipped it.
//
// The section is run on its own rather than through the whole of alpine.sh: the
// rest of that script wants Docker, adduser, chpasswd and sshd, and stubbing all
// of them to test a file rollback would put most of this test in the stubs.
// What is extracted is the real text, so a change to it changes what runs here.

// doasBox is a fake /etc holding just the file this section edits.
type doasBox struct {
	root, conf, bin string
	section         string
}

func newDoasBox(t *testing.T, existing string) *doasBox {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	root := t.TempDir()
	b := &doasBox{
		root: root,
		conf: filepath.Join(root, "doas.conf"),
		bin:  filepath.Join(root, "bin"),
	}
	if err := os.MkdirAll(b.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, b.conf, 0o600, existing)

	// doas -C is the validator. It accepts or refuses depending on what the
	// test is modelling; nothing else about doas is exercised.
	write(t, filepath.Join(b.bin, "doas"), 0o755, `#!/bin/sh
[ "$1" = "-C" ] || exit 0
if [ -n "$STUB_DOAS_INVALID" ]; then
  echo "doas: syntax error" >&2
  exit 1
fi
exit 0
`)
	write(t, filepath.Join(b.bin, "chown"), 0o755, "#!/bin/sh\nexit 0\n")

	// The real section, lifted out of alpine.sh and pointed at the fake file.
	// Everything between granting the rules and the sshd work that follows.
	body := between(t, scripts.AlpineScript,
		`log "Granting '$CI_USER' doas access to $DEPLOY_BIN and $SECRET_BIN only"`,
		"# --- 4. sshd ---")
	b.section = strings.NewReplacer(
		"/etc/doas.conf", b.conf,
		"$PROJECT_MARKER", "komizo",
		"$CI_USER", "komizo-blog",
		"$DEPLOY_BIN", "/usr/local/bin/deploy-blog",
		"$SECRET_BIN", "/usr/local/bin/set-secret-blog",
	).Replace(body)
	// The section opens mid-script, so give it the two things it reads.
	b.section = "set -eu\nOLD_CI_USER=\"\"\nlog() { :; }\ndie() { echo \"error: $*\" >&2; exit 1; }\n" +
		b.section
	return b
}

func (b *doasBox) run(t *testing.T, invalid bool) (string, error) {
	t.Helper()
	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(b.section)
	env := append(os.Environ(), "PATH="+b.bin+":/usr/bin:/bin")
	if invalid {
		env = append(env, "STUB_DOAS_INVALID=1")
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (b *doasBox) conf_(t *testing.T) string {
	t.Helper()
	got, err := os.ReadFile(b.conf)
	if err != nil {
		t.Fatalf("doas.conf is gone entirely: %v", err)
	}
	return string(got)
}

// The rules another app depends on must survive a rejected edit.
func TestAnInvalidDoasConfIsRestored(t *testing.T) {
	// A box already hosting one app. This is the content that must come back.
	const existing = `permit nopass root

# komizo: komizo-shop BEGIN
permit nopass komizo-shop as root cmd /usr/local/bin/deploy-shop
permit nopass komizo-shop as root cmd /usr/local/bin/set-secret-shop
# komizo: komizo-shop END
`
	b := newDoasBox(t, existing)

	out, err := b.run(t, true)
	if err == nil {
		t.Fatalf("a doas.conf that does not validate should fail the run:\n%s", out)
	}

	got := b.conf_(t)
	if got != existing {
		t.Errorf("doas.conf was not restored.\nwant:\n%s\ngot:\n%s", existing, got)
	}
	// The specific consequence, stated as itself: the OTHER app's rules are the
	// thing a botched edit takes down.
	if !strings.Contains(got, "komizo-shop as root cmd /usr/local/bin/deploy-shop") {
		t.Error("the other app on this box lost its deploy rule, so nothing it " +
			"deploys can reach root any more")
	}
	if strings.Contains(got, "komizo-blog") {
		t.Error("the rejected rules were left in the file")
	}
	if !strings.Contains(out, "reverted") {
		t.Errorf("the failure does not say it reverted, so an operator cannot "+
			"tell whether the box is broken:\n%s", out)
	}
}

// The backup is not left lying in /etc afterwards, on either path.
//
// A leftover matters more than it looks: the EXIT trap restores from it, so a
// stale one from an earlier run is a file that a later, unrelated failure would
// happily copy over a working config.
func TestTheDoasBackupDoesNotSurviveTheRun(t *testing.T) {
	for _, c := range []struct {
		name    string
		invalid bool
	}{
		{"accepted", false},
		{"rejected", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := newDoasBox(t, "permit nopass root\n")
			if _, err := b.run(t, c.invalid); (err != nil) != c.invalid {
				t.Fatalf("unexpected exit state for the %s case", c.name)
			}
			// Globbed, not stat'd on one name. The backup carries a per-run
			// suffix now (komizo#58 made two runs of this section at once
			// ordinary, and a shared name loses one of them), so asking about
			// the bare ".komizo.bak" would be asking about a file that never
			// exists -- a test that passes because it looks in the wrong place.
			left, err := filepath.Glob(b.conf + ".komizo.bak*")
			if err != nil {
				t.Fatal(err)
			}
			if len(left) > 0 {
				t.Errorf("backups were left beside doas.conf: %v", left)
			}
		})
	}
}

// The happy path still does what it is for.
func TestAValidDoasConfKeepsTheNewRules(t *testing.T) {
	b := newDoasBox(t, "permit nopass root\n")
	if out, err := b.run(t, false); err != nil {
		t.Fatalf("a valid config should not fail: %v\n%s", err, out)
	}
	got := b.conf_(t)
	for _, want := range []string{
		"# komizo: komizo-blog BEGIN",
		"permit nopass komizo-blog as root cmd /usr/local/bin/deploy-blog",
		"permit nopass komizo-blog as root cmd /usr/local/bin/set-secret-blog",
		"# komizo: komizo-blog END",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q from:\n%s", want, got)
		}
	}
	// Written once, not twice: re-running setup is normal and must not leave
	// two copies of the block.
	if n := strings.Count(got, "# komizo: komizo-blog BEGIN"); n != 1 {
		t.Errorf("the rule block appears %d times, want 1", n)
	}
}

// Re-running is how a config image is changed, so it has to be idempotent.
func TestReRunningReplacesTheBlockRatherThanAppending(t *testing.T) {
	b := newDoasBox(t, "permit nopass root\n")
	if _, err := b.run(t, false); err != nil {
		t.Fatal(err)
	}
	first := b.conf_(t)
	if _, err := b.run(t, false); err != nil {
		t.Fatal(err)
	}
	if got := b.conf_(t); got != first {
		t.Errorf("a second run changed the file.\nfirst:\n%s\nsecond:\n%s", first, got)
	}
}
