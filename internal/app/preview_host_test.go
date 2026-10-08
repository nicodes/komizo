package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nicodes/komizo/scripts"
)

// The preview helpers are komizo's, installed by komizo, granted by komizo.
//
// They were hand-installed with hand-added doas rules, and those rules sat
// inside komizo's own managed block -- so `komizo update` rewrote the block
// and deleted them, and gdam's previews failed on "doas: Operation not
// permitted" in a step that had worked minutes earlier. A feature that needs
// a privilege is a feature komizo has to install.

func TestPreviewHelpersAreSplicedIntoTheShippedScript(t *testing.T) {
	for _, want := range []string{
		"komizo-preview: refused (preview up|down|resolve|ls|gc only)",
		"write-preview-stackenv: refused: bad app",
	} {
		if !strings.Contains(scripts.AlpineScript, want) {
			t.Errorf("the shipped script does not carry %q -- the splice did not happen", want)
		}
	}
	// The markers must be gone, or the box receives a comment where a script
	// should be.
	for _, marker := range []string{"__PREVIEW_RUN_BODY__", "__PREVIEW_STACKENV_BODY__"} {
		if strings.Contains(scripts.AlpineScript, marker) {
			t.Errorf("%s survived into the shipped script", marker)
		}
	}
}

// Both helpers are POSIX sh. The one this replaces was `#!/bin/bash` using
// arrays -- a dependency on a shell Alpine does not install by default, in
// the one script that has to work on every box komizo sets up.
func TestPreviewHelpersArePosixShell(t *testing.T) {
	needs(t, "sh")
	for name, body := range map[string]string{
		"preview-run.sh":      previewBody(t, "KOMIZO_PREVIEW_RUN_EOF"),
		"preview-stackenv.sh": previewBody(t, "KOMIZO_PREVIEW_STACKENV_EOF"),
	} {
		if strings.HasPrefix(body, "#!/bin/bash") {
			t.Errorf("%s is bash; every script komizo puts on a box is sh", name)
		}
		cmd := exec.Command("sh", "-n")
		cmd.Stdin = strings.NewReader(body)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s is not valid sh: %v\n%s", name, err, out)
		}
	}
}

func previewBody(t *testing.T, tag string) string {
	t.Helper()
	return between(t, scripts.AlpineScript, "<<'"+tag+"'\n", tag)
}

// Granted only when the app asked for previews, and to nothing else.
func TestPreviewGrantsAreConditional(t *testing.T) {
	needs(t, "sh")
	for _, c := range []struct {
		preview string
		want    bool
	}{{"1", true}, {"0", false}} {
		t.Run("PREVIEW="+c.preview, func(t *testing.T) {
			b := newDoasBox(t, "permit nopass root\n")
			b.section = strings.Replace(b.section, `PREVIEW=""`, `PREVIEW="`+c.preview+`"`, 1)
			out, err := b.run(t, false)
			if err != nil {
				t.Fatalf("run failed: %v\n%s", err, out)
			}
			got := b.conf_(t)
			for _, rule := range []string{
				"cmd /usr/local/bin/komizo-preview",
				"cmd /usr/local/bin/write-preview-stackenv",
			} {
				if strings.Contains(got, rule) != c.want {
					t.Errorf("with PREVIEW=%s, want %q present=%v:\n%s", c.preview, rule, c.want, got)
				}
			}
		})
	}
}

// And once komizo writes them, the adoption scan must recognise them as its
// own -- otherwise the very next update carries the rules it just wrote out
// of the block as if a human had put them there.
func TestPreviewGrantsAreNotAdoptedAsHandAdded(t *testing.T) {
	needs(t, "sh")
	b := newDoasBox(t, "permit nopass root\n")
	b.section = strings.Replace(b.section, `PREVIEW=""`, `PREVIEW="1"`, 1)
	if _, err := b.run(t, false); err != nil {
		t.Fatal(err)
	}
	first := b.conf_(t)
	out, err := b.run(t, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "Adopted") {
		t.Errorf("komizo adopted its own preview rules:\n%s", out)
	}
	if second := b.conf_(t); second != first {
		t.Errorf("a second run changed the file.\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

// A default of "off" is not a request to uninstall.
//
// --preview is new, so every app on every existing box records PREVIEW=0 the
// first time this runs -- and the first `komizo update` after the feature
// shipped therefore DELETED the two helpers that were already there,
// hand-installed and working. gdam's previews broke for the second time in
// one night, from the change written to stop exactly that happening.
//
// Same rule as the doas block adopting rules komizo did not write: an update
// must not take away a capability nobody asked it to remove.
func TestAnUpdateDoesNotUninstallPreviewHelpersItDidNotInstall(t *testing.T) {
	needs(t, "sh")
	section := between(t, scripts.AlpineScript,
		"# --- 3a2. Preview path -----------------------------------------------------\n",
		"# --- 3b. Secret path ---")

	run := func(t *testing.T, preview, previewSet string) (string, string) {
		t.Helper()
		root := t.TempDir()
		runBin := filepath.Join(root, "komizo-preview")
		stackBin := filepath.Join(root, "write-preview-stackenv")
		state := filepath.Join(root, "apps")
		if err := os.MkdirAll(state, 0o755); err != nil {
			t.Fatal(err)
		}
		// Already on the box, put there by hand before komizo knew about them.
		write(t, runBin, 0o755, "#!/bin/sh\necho hand-installed\n")
		write(t, stackBin, 0o755, "#!/bin/sh\necho hand-installed\n")

		body := "set -eu\nPREVIEW=\"" + preview + "\"\nPREVIEW_SET=\"" + previewSet + "\"\n" +
			"STATE_DIR=" + state + "\nlog() { :; }\ndie() { exit 1; }\n" +
			strings.NewReplacer(
				"PREVIEW_RUN_BIN=/usr/local/bin/komizo-preview", "PREVIEW_RUN_BIN="+runBin,
				"PREVIEW_STACKENV_BIN=/usr/local/bin/write-preview-stackenv", "PREVIEW_STACKENV_BIN="+stackBin,
			).Replace(section)
		cmd := exec.Command("sh", "-s")
		cmd.Stdin = strings.NewReader(body)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("section failed: %v\n%s", err, out)
		}
		return runBin, stackBin
	}

	t.Run("plain update with previews off leaves them alone", func(t *testing.T) {
		runBin, stackBin := run(t, "0", "0")
		for _, f := range []string{runBin, stackBin} {
			if _, err := os.Stat(f); err != nil {
				t.Errorf("an update uninstalled a helper nobody asked it to remove: %s", f)
			}
		}
	})

	t.Run("an explicit --preview=false does remove them", func(t *testing.T) {
		runBin, stackBin := run(t, "0", "1")
		for _, f := range []string{runBin, stackBin} {
			if _, err := os.Stat(f); !os.IsNotExist(err) {
				t.Errorf("an explicit revoke left %s in place", f)
			}
		}
	})
}
