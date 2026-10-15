package app

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nicodes/komizo/scripts"
)

func TestMachineSecretListingUsesNamesOnlyAndPreservesPrivateFiles(t *testing.T) {
	dir := t.TempDir()
	private := []byte("TOKEN_NAME=do-not-print-this-value\n")
	if err := os.WriteFile(filepath.Join(dir, "secrets.env"), private, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "secrets"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secrets", "signing.pem"), private, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", scripts.AlpineUnsetSecretScript)
	cmd.Env = append(os.Environ(), "APP_NAME=mailroom", "APP_DIR="+dir, "LIST=1", "MACHINE_NAMES=1", "NAMES=")
	out, err := cmd.CombinedOutput()
	if err != nil || string(out) != "TOKEN_NAME\nfile:signing.pem\n" {
		t.Fatalf("names-only protocol: %v %q", err, out)
	}
	for _, name := range []string{"secrets.env", "secrets/signing.pem"} {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(body, private) {
			t.Fatal("listing changed a private file")
		}
	}
	for _, name := range []string{"file:../key", "file:.hidden", "file:-option", "file:key\nother", "BAD.*"} {
		if validSecretName("mailroom", name) {
			t.Fatalf("unsafe secret name accepted: %q", name)
		}
	}
}

func checkManagementBinary(t *testing.T, cli string) {
	t.Helper()
	dir := t.TempDir()
	ssh := `#!/bin/sh
case "$*" in
 *' -G '*|'-G '*) printf 'port 22\n'; exit 0;;
esac
cat >/dev/null
if [ "${KOMIZO_TEST_REMOTE_FAILURE:-}" = 1 ]; then
 printf '{"code":"invalid_input","reconciliation_required":false}\n' >&2
 exit 66
fi
case "$*" in
 *MACHINE_NAMES*) printf 'TOKEN_NAME\nfile:signing.pem\n';;
 *"'platform' 'inspect'"*) printf '{"version":1,"manifest":"` + strings.Repeat("a", 64) + `","phase":"installing"}\n';;
 *"'platform' 'recover'"*) printf '{"version":1,"manifest":"` + strings.Repeat("a", 64) + `","phase":"recovered"}\n';;
 *) printf 'remote prose is not a structured acknowledgement\n';;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(ssh), 0700); err != nil {
		t.Fatal(err)
	}
	run := func(args []string, input string, failRemote bool) MachineResult {
		t.Helper()
		cmd := exec.Command(cli, append([]string{"--json"}, args...)...)
		cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "HOME="+dir)
		if failRemote {
			cmd.Env = append(cmd.Env, "KOMIZO_TEST_REMOTE_FAILURE=1")
		}
		cmd.Dir = dir
		cmd.Stdin = strings.NewReader(input)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		var result MachineResult
		if json.Unmarshal(stdout.Bytes(), &result) != nil || (err == nil) != result.OK {
			t.Fatalf("invalid envelope: %v %s %s", err, stdout.String(), stderr.String())
		}
		if strings.Contains(stdout.String(), "do-not-print-this-value") || strings.Contains(stderr.String(), "do-not-print-this-value") {
			t.Fatal("private input was printed")
		}
		return result
	}
	for _, verb := range []string{"start", "stop", "restart"} {
		r := run([]string{verb, "--host", "fixture.invalid", "--app", "mailroom"}, "", false)
		var receipt managementResult
		if !r.OK || json.Unmarshal(r.Data, &receipt) != nil || !receipt.Acknowledged || receipt.Action != verb || receipt.App != "mailroom" || receipt.Host != "root@fixture.invalid" {
			t.Fatalf("bad receipt: %+v %s", r, r.Data)
		}
	}
	r := run([]string{"set-secret", "--host", "fixture.invalid", "--app", "mailroom", "--name", "TOKEN"}, "do-not-print-this-value", false)
	if !r.OK || bytes.Contains(r.Data, []byte("text")) {
		t.Fatalf("secret write lacks structured receipt: %+v", r)
	}
	r = run([]string{"unset-secret", "--host", "fixture.invalid", "--app", "mailroom", "--list"}, "", false)
	if !r.OK || !bytes.Contains(r.Data, []byte(`"names":["TOKEN_NAME","file:signing.pem"]`)) {
		t.Fatalf("names-only listing failed: %+v", r)
	}
	for _, args := range [][]string{{"stop", "--host", "fixture.invalid"}, {"remove", "--host", "fixture.invalid", "--app", "mailroom"}, {"platform", "recover", "--host", "fixture.invalid", "--stage", "/arbitrary", "--expected-manifest", strings.Repeat("a", 64)}} {
		r = run(args, "", false)
		if r.OK || r.Error == nil || r.Error.Code != "invalid_input" || r.Error.ReconciliationRequired {
			t.Fatalf("local refusal was uncertain: %+v", r)
		}
	}
	r = run([]string{"stop", "--host", "fixture.invalid", "--app", "mailroom"}, "", true)
	if r.OK || r.Error == nil || r.Error.Code == "invalid_input" || !r.Error.ReconciliationRequired {
		t.Fatalf("remote prose forged local classification: %+v", r)
	}

	if err := os.WriteFile(filepath.Join(dir, "--help"), []byte("do-not-print-this-value"), 0600); err != nil {
		t.Fatal(err)
	}
	r = run([]string{"set-secret", "--host", "fixture.invalid", "--app", "mailroom", "--name", "TOKEN", "--from", "--help"}, "", true)
	if r.OK || r.Error == nil || !r.Error.ReconciliationRequired {
		t.Fatalf("a value spelling --help cleared mutation uncertainty: %+v", r)
	}
	for _, sub := range []string{"inspect", "recover"} {
		r = run([]string{"platform", sub, "--host", "fixture.invalid", "--stage", "/var/lib/komizo/upgrades/owned", "--expected-manifest", strings.Repeat("a", 64)}, "", false)
		if !r.OK || !bytes.Contains(r.Data, []byte(`"manifest"`)) {
			t.Fatalf("platform %s failed: %+v", sub, r)
		}
	}
}
