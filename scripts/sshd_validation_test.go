package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// THE THREE COPIES OF THE SSHD VALIDATION ARE ONE THING.
//
// komizo#77. Every script that reloads sshd has to validate the config with the
// binary that will load it, and these scripts are embedded whole -- there is no
// splicing, so the function exists three times. Three copies of a security
// check is three chances for two of them to be right.
//
// Delimited by markers and compared byte for byte, so a fix applied to one is a
// test failure until it is applied to all.
const (
	sshdBlockBegin = "# komizo: sshd-validation BEGIN"
	sshdBlockEnd   = "# komizo: sshd-validation END"
)

// codeOnly drops comment lines, so an assertion about what the shell DOES is
// not satisfied or broken by prose. The comments here name `sshd -t` and
// `sshd.pam` precisely because they explain why neither is used directly.
func codeOnly(s string) string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "#") {
			continue
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

func sshdValidationBlock(t *testing.T, name, src string) string {
	t.Helper()
	i := strings.Index(src, sshdBlockBegin)
	if i < 0 {
		t.Fatalf("%s has no sshd-validation block, so it either does not reload sshd any more "+
			"or it went back to validating whatever `sshd` resolves to", name)
	}
	j := strings.Index(src[i:], sshdBlockEnd)
	if j < 0 {
		t.Fatalf("%s opens a sshd-validation block and never closes it", name)
	}
	return src[i : i+j+len(sshdBlockEnd)]
}

func TestEveryScriptValidatesSSHDTheSameWay(t *testing.T) {
	scripts := map[string]string{
		"alpine.sh":             AlpineScript,
		"alpine-remove.sh":      AlpineRemoveScript,
		"alpine-reload-sshd.sh": AlpineReloadSSHDScript,
	}

	var first, firstName string
	for _, name := range []string{"alpine.sh", "alpine-remove.sh", "alpine-reload-sshd.sh"} {
		block := sshdValidationBlock(t, name, scripts[name])
		if first == "" {
			first, firstName = block, name
			continue
		}
		if block != first {
			t.Errorf("%s's sshd validation differs from %s's. Three copies of this check is three\n"+
				"chances for two of them to be right; they have to be identical.\n--- %s ---\n%s\n--- %s ---\n%s",
				name, firstName, firstName, first, name, block)
		}
	}

	// AND EACH SCRIPT ACTUALLY CALLS IT. A block that is present and unused is
	// the shape this repository keeps finding: the guard is there, and the code
	// beside it does the old thing.
	for name, src := range scripts {
		body := codeOnly(strings.Replace(src, sshdValidationBlock(t, name, src), "", 1))
		if !strings.Contains(body, "komizo_sshd_config_ok") {
			t.Errorf("%s defines the validation and never calls it", name)
		}
		// `sshd -t` outside the block means a caller went back to asking the
		// wrong binary.
		if strings.Contains(body, "sshd -t") {
			t.Errorf("%s still runs `sshd -t` outside the shared block, which is the binary that "+
				"is NOT going to load the config on a box with openssh-server-pam", name)
		}
	}
}

// The selection this defers to is the init script's, so the thing worth pinning
// is that it defers rather than deciding for itself. A copy of Alpine's
// update_command() here would be vendor logic that drifts.
func TestTheValidationAsksTheInitScriptRatherThanGuessing(t *testing.T) {
	block := sshdValidationBlock(t, "alpine.sh", AlpineScript)
	for _, want := range []string{
		"rc-service sshd checkconfig", // the init script's own check
		"/etc/init.d/sshd",            // and it is asked whether that action exists
	} {
		if !strings.Contains(block, want) {
			t.Errorf("the sshd validation no longer mentions %q -- if it now picks the binary "+
				"itself, it is a copy of Alpine's update_command() and will drift from it", want)
		}
	}
	// Naming either PAM binary in the CODE would be exactly that copy. The
	// comments name them on purpose -- they are why this defers.
	code := codeOnly(block)
	for _, never := range []string{"sshd.pam", "sshd.krb5"} {
		if strings.Contains(code, never) {
			t.Errorf("the sshd validation names %q, which means it is choosing the binary itself "+
				"instead of asking the init script that will run it", never)
		}
	}
}

// AND IT BEHAVES, run against a stubbed rc-service and init script.
//
// The two paths are not the same code, and the fallback is the one that only
// runs on machines nobody here has.
func TestTheValidationPrefersCheckconfigAndFallsBackToSSHDT(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	block := sshdValidationBlock(t, "alpine.sh", AlpineScript)

	for _, tc := range []struct {
		name       string
		initScript string // contents of /etc/init.d/sshd, empty for absent
		want       string
	}{
		{
			name:       "the init script offers checkconfig",
			initScript: "#!/sbin/openrc-run\nextra_commands=\"checkconfig\"\n",
			want:       "rc-service",
		},
		{
			name:       "an init script without the action",
			initScript: "#!/sbin/openrc-run\nextra_started_commands=\"reload\"\n",
			want:       "sshd",
		},
		{
			name:       "no init script at all",
			initScript: "",
			want:       "sshd",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			// Stubs that report which one was asked.
			writeFile(t, filepath.Join(dir, "rc-service"), 0o755, "#!/bin/sh\necho rc-service \"$@\"\nexit 0\n")
			writeFile(t, filepath.Join(dir, "sshd"), 0o755, "#!/bin/sh\necho sshd \"$@\"\nexit 0\n")
			// grep is real; the init script is not.
			etc := t.TempDir()
			if tc.initScript != "" {
				writeFile(t, filepath.Join(etc, "sshd"), 0o644, tc.initScript)
			}

			script := strings.Join([]string{
				"set -eu",
				// The block, with the one absolute path it reads repointed at a
				// file this test owns. Asserted below, so a rename is fatal
				// rather than silently testing the host's real init script.
				strings.ReplaceAll(block, "/etc/init.d/sshd", etc+"/sshd"),
				"komizo_sshd_config_ok",
			}, "\n")
			if !strings.Contains(script, etc+"/sshd") {
				t.Fatalf("could not repoint the init script path -- the block no longer reads /etc/init.d/sshd")
			}

			cmd := exec.Command("sh", "-s")
			cmd.Stdin = strings.NewReader(script)
			// The stubs FIRST, then the real PATH -- the block runs `grep`, which is
			// the system's.
			cmd.Env = []string{"PATH=" + dir + ":" + os.Getenv("PATH")}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("the validation failed: %v\n%s", err, out)
			}
			got := strings.Fields(string(out))
			if len(got) == 0 || got[0] != tc.want {
				t.Errorf("asked %q, want %s -- output was %q", got, tc.want, out)
			}
		})
	}
}

func writeFile(t *testing.T, path string, mode os.FileMode, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}
