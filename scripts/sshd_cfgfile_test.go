package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// KOMIZO EDITS THE FILE THE DAEMON READS, OR IT EDITS NOTHING.
//
// nicodes/komizo-be#164. Alpine's sshd init script takes `cfgfile` from
// /etc/conf.d/sshd, so an operator can point their daemon at a config other
// than /etc/ssh/sshd_config. komizo wrote to that path unconditionally, and on
// such a box every consequence is silent:
//
//   - the deploy account's Match block is not in force, so AllowTcpForwarding no
//     and the rest never take effect, and a leaked deploy key can tunnel TCP
//     through the box to anything routable from it
//   - AuthorizedKeysFile still points wherever the real config says, so the
//     root-owned key list is not the one consulted and the account can authorise
//     a second key for itself
//   - a key rotation rewrites a file nothing loads, and the old key keeps working
//
// komizo reported success for all three. komizo#78 fixed the validator to use
// the binary that will load the config; this is the other half -- the PATH.
//
// RUN, NOT READ. The function is shell and the thing being asserted is what the
// shell decides, so these drive `sh` against a fake /etc/conf.d/sshd. A test
// that grepped the source for "cfgfile" would pass on a function that reads it
// and ignores it.

// runCfgfileCheck extracts the two functions and runs them against a fake box.
//
// The read is redirected rather than mocked: the block hardcodes
// /etc/conf.d/sshd, which is the point -- it must read the path the init script
// reads. So the whole block is rewritten to look under a temp root, and the
// rewrite itself is asserted to have changed something, or this test would be
// running against the real /etc.
func runCfgfileCheck(t *testing.T, confd string) (int, string) {
	t.Helper()
	block := sshdValidationBlock(t, "alpine", AlpineScript)

	root := t.TempDir()
	etc := filepath.Join(root, "etc", "conf.d")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	if confd != "" {
		if err := os.WriteFile(filepath.Join(etc, "sshd"), []byte(confd), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	redirected := strings.ReplaceAll(block, "/etc/conf.d/sshd", filepath.Join(etc, "sshd"))
	if redirected == block {
		t.Fatal("the block does not name /etc/conf.d/sshd, so it is not reading what the " +
			"init script reads -- and this test would be asserting against the real /etc")
	}

	script := redirected + "\nkomizo_sshd_conf_is_ours\n"
	cmd := exec.Command("sh", "-c", script)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, string(out)
}

func TestKomizoRefusesABoxThatPointsSshdSomewhereElse(t *testing.T) {
	for _, tc := range []struct {
		name  string
		confd string
		// ours is whether komizo should agree it owns this box's sshd config.
		ours bool
		// says is a phrase the refusal must carry, so the operator knows which
		// file their box uses rather than only that komizo stopped.
		says string
	}{
		{
			name:  "no conf.d file at all",
			confd: "",
			ours:  true,
		},
		{
			name:  "a conf.d that says nothing about cfgfile",
			confd: "sshd_disable_keygen=no\n",
			ours:  true,
		},
		{
			name:  "cfgfile set to the default explicitly",
			confd: "cfgfile=/etc/ssh/sshd_config\n",
			ours:  true,
		},
		{
			name:  "quoted, because /etc/conf.d is shell",
			confd: "cfgfile=\"/etc/ssh/sshd_config\"\n",
			ours:  true,
		},
		{
			name:  "pointed somewhere else",
			confd: "cfgfile=/etc/ssh/sshd_config.custom\n",
			ours:  false,
			says:  "/etc/ssh/sshd_config.custom",
		},
		{
			name:  "pointed somewhere else, quoted",
			confd: "cfgfile='/opt/ssh/sshd_config'\n",
			ours:  false,
			says:  "/opt/ssh/sshd_config",
		},
		{
			// THE LAST ASSIGNMENT WINS, which is what the shell does when the
			// init script sources this file. Reading the first would agree with
			// komizo and disagree with the daemon.
			name:  "set twice, and the daemon uses the second",
			confd: "cfgfile=/etc/ssh/sshd_config\ncfgfile=/opt/ssh/sshd_config\n",
			ours:  false,
			says:  "/opt/ssh/sshd_config",
		},
		{
			name:  "indented, which shell allows",
			confd: "  cfgfile=/opt/ssh/sshd_config\n",
			ours:  false,
			says:  "/opt/ssh/sshd_config",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out := runCfgfileCheck(t, tc.confd)

			if tc.ours {
				if code != 0 {
					t.Errorf("komizo refused a box whose sshd reads the file it manages "+
						"(exit %d):\n%s", code, out)
				}
				if strings.Contains(out, "error:") {
					t.Errorf("a box komizo does manage was told otherwise:\n%s", out)
				}
				return
			}
			if code == 0 {
				t.Fatalf("komizo agreed to edit /etc/ssh/sshd_config on a box whose daemon "+
					"reads another file -- every restriction it writes would be inert:\n%s", out)
			}
			// AND IT NAMES THE FILE. "komizo cannot manage this box" with no
			// path is a message that leaves somebody grepping /etc to find out
			// what komizo objected to.
			if !strings.Contains(out, tc.says) {
				t.Errorf("the refusal does not say which file this box uses (want %q):\n%s",
					tc.says, out)
			}
		})
	}
}

// AND EVERY SCRIPT THAT EDITS THE FILE ASKS BEFORE IT DOES.
//
// The function existing is half of it. alpine.sh takes a backup of sshd_config
// as its first write, so a refusal after that has already put a .komizo.bak
// beside a file komizo does not own; alpine-remove.sh has the same shape.
func TestEveryScriptThatEditsSshdAsksWhoseFileItIs(t *testing.T) {
	for name, src := range map[string]string{
		"alpine":             AlpineScript,
		"alpine-remove":      AlpineRemoveScript,
		"alpine-reload-sshd": AlpineReloadSSHDScript,
	} {
		// COMMENTS STRIPPED. A mention of the function in the prose explaining
		// it is not a call to it, and this file already carries three.
		code := codeOnly(src)
		if !strings.Contains(code, "komizo_sshd_conf_is_ours") {
			t.Errorf("%s edits or reloads sshd without asking whether /etc/ssh/sshd_config "+
				"is the file this box's daemon reads", name)
			continue
		}
		// CALLED, not merely defined. The definition is in the shared block, so
		// every one of these scripts has it whether it uses it or not.
		calls := strings.Count(code, "komizo_sshd_conf_is_ours")
		if calls < 2 {
			t.Errorf("%s defines the check and never calls it (%d occurrences in code)", name, calls)
		}
	}
}

// AND THE REFUSAL COMES BEFORE THE FIRST WRITE.
func TestAlpineRefusesBeforeItBacksUpAFileItDoesNotOwn(t *testing.T) {
	code := codeOnly(AlpineScript)
	call := strings.Index(code, "if ! komizo_sshd_conf_is_ours; then")
	backup := strings.Index(code, `cp "$conf" "$conf_bak"`)
	if call < 0 || backup < 0 {
		t.Fatalf("could not find both the check (%d) and the backup (%d)", call, backup)
	}
	if call > backup {
		t.Error("alpine.sh copies sshd_config before asking whether it is the file this " +
			"box's daemon reads, so a refusal leaves a .komizo.bak beside a file komizo does not own")
	}
}
