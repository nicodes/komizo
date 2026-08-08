package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/scripts"
)

const newKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKD5vgfqmUVHAJDT5uZ6P+O/YBmR8hjj12T4jFnhrtqy rotated@web"

func rotateCmd(args map[string]string) box.Command {
	return box.Command{V: box.CommandVersion, ID: "abc123", Srv: "srv_mine",
		Exp: time.Now().Add(time.Minute).Unix(), Op: box.OpAppRotate, Args: args}
}

// boxWithApp is a machine whose record of one app is complete.
func boxWithApp(t *testing.T, record string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, box.AppsDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "web.env"), []byte(record), 0o640); err != nil {
		t.Fatal(err)
	}
	orig := lookupRoot
	lookupRoot = root
	t.Cleanup(func() { lookupRoot = orig })
	return root
}

const fullRecord = "APP_DIR=/opt/web\nCI_USER=komizo-web\nCONFIG_IMAGE=ghcr.io/you/web-config\nKNOWN_AS=web.example.com\n"

// heldProvision captures the command runProvision built, after its Env and
// Stdin are set.
func heldProvision(t *testing.T) **exec.Cmd {
	t.Helper()
	var held *exec.Cmd
	orig := execProvision
	execProvision = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		held = exec.CommandContext(ctx, "true")
		return held
	}
	t.Cleanup(func() { execProvision = orig })
	return &held
}

func envOf(t *testing.T, c *exec.Cmd) map[string]string {
	t.Helper()
	if c == nil {
		t.Fatal("nothing was run")
	}
	env := map[string]string{}
	for _, kv := range c.Env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	return env
}

// A ROTATION CHANGES THE KEY AND NOTHING ELSE.
//
// nicodes/komizo-be#112. The envelope decides which app and which key; ROOT
// decides everything else, from the record root itself wrote. That is the whole
// security property of this op: a rotation cannot re-point an app at another
// registry, move it, or change which names it answers on.
func TestARotationTakesEverySettingFromTheBoxsOwnRecord(t *testing.T) {
	boxWithApp(t, fullRecord)
	held := heldProvision(t)

	if err := perform(context.Background(), rotateCmd(map[string]string{
		"app": "web", "pubkey": newKey,
	}), testBy); err != nil {
		t.Fatalf("perform = %v", err)
	}

	env := envOf(t, *held)
	for k, want := range map[string]string{
		"APP_NAME":     "web",
		"CI_PUBKEY":    newKey,
		"CI_USER":      "komizo-web",
		"CONFIG_IMAGE": "ghcr.io/you/web-config",
		"APP_DIR":      "/opt/web",
		"KNOWN_AS":     "web.example.com",
	} {
		if env[k] != want {
			t.Errorf("%s = %q, want %q -- taken from somewhere other than this box's record", k, env[k], want)
		}
	}
	// HARDEN_SSH IS NOT INHERITED. It disables password login for EVERY user on
	// the machine, which app-only.md §7 says a deploy tool does not decide on
	// its own -- and re-asserting it on a path whose subject is one app's key is
	// a policy change nobody put in this envelope.
	if env["HARDEN_SSH"] != "0" {
		t.Errorf("HARDEN_SSH = %q, want 0 -- a key rotation changed a machine-wide policy", env["HARDEN_SSH"])
	}
}

// AND IT RUNS THE SCRIPT `komizo add --rotate-key` RUNS.
//
// app-only.md §8's condition: both triggers end in one implementation, so there
// is never a second opinion about what rotating a key means.
func TestARotationRunsTheSameScriptTheCLIRuns(t *testing.T) {
	boxWithApp(t, fullRecord)
	held := heldProvision(t)

	if err := perform(context.Background(), rotateCmd(map[string]string{
		"app": "web", "pubkey": newKey,
	}), testBy); err != nil {
		t.Fatalf("perform = %v", err)
	}
	r, ok := (*held).Stdin.(*strings.Reader)
	if !ok {
		t.Fatal("the script was not piped over stdin")
	}
	buf := make([]byte, len(scripts.AlpineScript))
	if _, err := r.ReadAt(buf, 0); err != nil {
		t.Fatal(err)
	}
	if string(buf) != scripts.AlpineScript {
		t.Error("a signed rotation runs something other than the script `komizo add` runs")
	}
}

// AN ENVELOPE THAT MENTIONS A SETTING IS REFUSED, not quietly stripped.
//
// Dropping it would let a caller believe a setting changed. Refusing says the
// op does not do that, which is the difference between a guarantee and a
// coincidence -- and it is what stops app.rotate becoming app.add with fewer
// arguments the first time somebody adds "just one more field".
func TestARotationRefusesAnEnvelopeThatWouldChangeAnythingElse(t *testing.T) {
	boxWithApp(t, fullRecord)
	heldProvision(t)

	for _, extra := range []string{"config", "app_dir", "user", "known_as", "harden_ssh"} {
		args := map[string]string{"app": "web", "pubkey": newKey, extra: "x"}
		err := perform(context.Background(), rotateCmd(args), testBy)
		if err == nil {
			t.Errorf("an envelope carrying %q was applied as an ordinary rotation", extra)
			continue
		}
		if !strings.Contains(err.Error(), extra) {
			t.Errorf("the refusal for %q does not name it: %v", extra, err)
		}
	}
}

// A KEY KOMIZO WOULD NOT ISSUE IS REFUSED, by the same rule app.add uses.
func TestARotationRefusesAKeyKomizoWouldNotIssue(t *testing.T) {
	boxWithApp(t, fullRecord)
	heldProvision(t)

	for _, bad := range []string{
		"",
		"ssh-rsa AAAAB3NzaC1yc2E deploy@web",
		"ssh-ed25519 AAAA one\nssh-ed25519 BBBB two",
	} {
		if err := perform(context.Background(), rotateCmd(map[string]string{
			"app": "web", "pubkey": bad,
		}), testBy); err == nil {
			t.Errorf("a rotation to %q was accepted", bad)
		}
	}
}

// AN APP THIS BOX HAS NO RECORD OF IS NOT PROVISIONED INTO EXISTENCE.
//
// "Rotate the key of an app that is not here" is a typo, and creating one in
// response is the worst available reading of it. app.add creates; this does not.
func TestARotationOfAnAppThatIsNotHereCreatesNothing(t *testing.T) {
	boxWithApp(t, fullRecord)
	held := heldProvision(t)

	err := perform(context.Background(), rotateCmd(map[string]string{
		"app": "other", "pubkey": newKey,
	}), testBy)
	if err == nil {
		t.Fatal("rotating an app this box has never heard of succeeded")
	}
	if *held != nil {
		t.Error("it ran the provisioning script, so a typo would have created an app")
	}
}

// AND A HALF-WRITTEN RECORD IS REFUSED RATHER THAN DEFAULTED.
//
// alpine.sh derives a deploy account from the app name and defaults APP_DIR to
// /srv/<app> -- both reasonable when SETTING UP and both wrong here: an app
// whose record is incomplete would be re-provisioned onto an account and a
// directory that may not be the ones it is using, which is a rotation that
// authorises a key somewhere else.
func TestARotationRefusesToGuessAtAnIncompleteRecord(t *testing.T) {
	for _, missing := range []string{"CI_USER", "CONFIG_IMAGE", "APP_DIR"} {
		t.Run(missing, func(t *testing.T) {
			var kept []string
			for _, ln := range strings.Split(strings.TrimSpace(fullRecord), "\n") {
				if !strings.HasPrefix(ln, missing+"=") {
					kept = append(kept, ln)
				}
			}
			boxWithApp(t, strings.Join(kept, "\n")+"\n")
			held := heldProvision(t)

			err := perform(context.Background(), rotateCmd(map[string]string{
				"app": "web", "pubkey": newKey,
			}), testBy)
			if err == nil {
				t.Fatalf("a record with no %s was rotated anyway", missing)
			}
			if !strings.Contains(err.Error(), missing) {
				t.Errorf("the refusal does not name what is missing: %v", err)
			}
			if *held != nil {
				t.Error("it ran the script despite not knowing where the app is")
			}
		})
	}
}
