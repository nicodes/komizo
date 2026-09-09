//go:build !js && !plan9

// The capability set is signals: this test delivers SIGHUP/SIGTERM/SIGINT/
// SIGPIPE to a real sh, and SIGPIPE does not exist on js or plan9 (probed with
// `GOOS=<target> go doc syscall.SIGPIPE` under Go 1.26.5). Everywhere else --
// unix AND windows -- it compiles; it runs where sh exists, and the cross-build
// gate covers the rest.

package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nicodes/komizo/scripts"
)

// THE GUARDS ON /etc SURVIVE THE SIGNAL THAT ACTUALLY ARRIVES, AND STOP.
//
// alpine.sh backs up /etc/doas.conf and /etc/ssh/sshd_config and restores them
// from a trap. An EXIT trap does not run on HUP, TERM or PIPE, and those are
// exactly how this script dies in practice: `komizo update` is long, and
// interrupting it kills the local ssh, after which the far end takes SIGHUP
// from sshd or SIGPIPE on its next write to a closed stdout.
//
// What is left behind in each window is specific. In the doas one, this app's
// rule block has been removed and not yet re-appended, so its deploys get a
// refusal. In the sshd one, its Match block is gone -- which takes the
// root-owned AuthorizedKeysFile and every restriction in it -- and sshd has not
// been reloaded, so it bites at the next reboot instead.
//
// RUN, WITH A REAL SIGNAL, because listing the signals is not the property.
// Review 1 asked for the signals and Review 2 found that adding them was not
// enough: a handler for a non-EXIT signal RETURNS to where it was interrupted,
// so the first version restored the file and then carried on -- re-appending
// the block, finishing the run on a box whose operator had cancelled it, and
// walking into the sshd window to die there instead, where nothing was catching
// SIGPIPE at all. A string match on the trap line cannot tell those two apart.
// This sends the signal and asserts both halves: the file goes back, and the
// script stops.
//
// There is no race to lose. The lifted section is followed by a marker file and
// a sleep, so the signal is delivered at a point the test chose.
func TestTheGuardsOnEtcRestoreAndStopOnEverySignal(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed")
	}
	const original = "# untouched\n"

	// BOTH SCRIPTS THAT EDIT /etc, not just the one this test was written for.
	//
	// Review 1 on komizo#73: this ran alpine.sh's two guards only, so gutting
	// alpine-remove.sh's restore_doas() to `{ :; }` left the entire suite green.
	// The regex test below did cover the removal script -- and that is the trap
	// worth naming: it covers a DIFFERENT AXIS. It reads which signals a trap
	// line is installed for; it cannot see whether the handler restores anything
	// or stops. Extending it felt like closing this gap and was not.
	for _, guard := range []struct {
		name, src, target, pre, lift, until string
	}{
		{
			name:   "alpine.sh/doas.conf",
			src:    scripts.AlpineScript,
			target: "doas.conf",
			lift:   `doas_bak="/etc/doas.conf.komizo.bak.$$"`,
			until:  "# Delimited block,",
		},
		{
			name:   "alpine.sh/sshd_config",
			src:    scripts.AlpineScript,
			target: "sshd_config",
			lift:   "conf=/etc/ssh/sshd_config",
			until:  "# Retire the previous account's Match block",
		},
		{
			name:   "alpine-remove.sh/doas.conf",
			src:    scripts.AlpineRemoveScript,
			target: "doas.conf",
			lift:   "doas_bak=/etc/doas.conf.komizo.bak",
			until:  `sed -i -E "/^# $PROJECT_MARKER: $CI_USER BEGIN`,
		},
		{
			name:   "alpine-remove.sh/sshd_config",
			src:    scripts.AlpineRemoveScript,
			target: "sshd_config",
			// This guard opens inside `if [ -f "$conf" ]`, so the lift starts at
			// the backup -- as the others do -- and $conf is supplied here. The
			// line is the script's own, and goes through the same rewrite.
			pre:   "conf=/etc/ssh/sshd_config",
			lift:  `conf_bak="$conf.komizo.bak"`,
			until: "sed -i -E \\\n",
		},
	} {
		src := guard.src
		for _, sig := range []syscall.Signal{syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT, syscall.SIGPIPE} {
			t.Run(guard.name+"/"+sig.String(), func(t *testing.T) {
				dir := t.TempDir()
				target := filepath.Join(dir, guard.target)
				write(t, target, 0o600, original)

				// The backup-and-guard block exactly as it ships, pointed at a
				// file this test owns. Everything after it stands in for the
				// edit the guard exists to protect: the file is left in a state
				// it must not be found in, and then the signal arrives.
				block := guard.pre + "\n" + fromTo(t, src, guard.lift, guard.until)
				block = strings.NewReplacer(
					"/etc/doas.conf", target,
					"/etc/ssh/sshd_config", target,
				).Replace(block)

				script := strings.Join([]string{
					"set -eu",
					block,
					`printf 'mid-edit\n' > ` + shQuote(target),
					`printf 'ready\n' > ` + shQuote(filepath.Join(dir, "ready")),
					// A LOOP OF SHORT SUCCESSFUL COMMANDS, which is what the
					// real script is doing when the signal lands -- a sed, a
					// cat, a chmod, each returning 0.
					//
					// Not `sleep & wait`: `wait` returns 128+signal, so `set -e`
					// would end the run by itself and a handler that resumed
					// would be indistinguishable from one that exits. That is
					// the version of this test that let Review 2's blocker
					// survive. A foreground command defers the handler until it
					// finishes and then returns 0, so `set -e` has nothing to
					// act on and the script carries on -- exactly as it would
					// after the `sed -i` that opens the window.
					"i=0",
					`while [ "$i" -lt 200 ]; do sleep 0.05; i=$((i+1)); done`,
					// Reached only if the handler resumed instead of exiting.
					`printf 'RAN-ON\n' >> ` + shQuote(target),
				}, "\n")

				cmd := exec.Command("sh", "-s")
				cmd.Stdin = strings.NewReader(script)
				cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				deadline := time.Now().Add(10 * time.Second)
				for {
					if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
						break
					}
					if time.Now().After(deadline) {
						_ = cmd.Process.Kill()
						t.Fatal("the lifted guard never reached the point the signal is sent at")
					}
					time.Sleep(5 * time.Millisecond)
				}
				if err := cmd.Process.Signal(sig); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- cmd.Wait() }()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					_ = cmd.Process.Kill()
					t.Fatalf("%s did not stop the run -- a handler that returns to where it was "+
						"interrupted carries on provisioning a box whose operator has cancelled "+
						"the command, and dies in the next window instead", sig)
				}

				got, err := os.ReadFile(target)
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != original {
					t.Errorf("%s was left as %q after %s, want it restored to %q",
						guard.target, string(got), sig, original)
				}
				if strings.Contains(string(got), "RAN-ON") {
					t.Errorf("the run continued past %s", sig)
				}
				// And no backup left in /etc for a later, unrelated failure to
				// restore from.
				strays, err := filepath.Glob(target + ".komizo.bak*")
				if err != nil {
					t.Fatal(err)
				}
				if len(strays) > 0 {
					t.Errorf("backups left behind after %s: %v", sig, strays)
				}
			})
		}
	}
}
