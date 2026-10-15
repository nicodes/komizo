package app

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const healthyPrerequisites = "os=alpine\nkernel=Linux\narch=x86_64\nuid=0\nmemory_kib=1048576\ndisk_kib=4194304\ninodes=800000\napk=yes\nopenrc=yes\ncgroup_v2=yes\ninstalled=yes\n"

func TestDoctorRefusesUnsupportedOrIncompleteBeforeSetup(t *testing.T) {
	for _, tc := range []struct {
		name, body       string
		valid, supported bool
	}{
		{"supported", healthyPrerequisites, true, true},
		{"unsupported-os", strings.ReplaceAll(healthyPrerequisites, "os=alpine", "os=debian"), true, false},
		{"non-root", strings.ReplaceAll(healthyPrerequisites, "uid=0", "uid=1000"), true, false},
		{"disk-reserve", strings.ReplaceAll(healthyPrerequisites, "disk_kib=4194304", "disk_kib=12"), true, false},
		{"missing", strings.ReplaceAll(healthyPrerequisites, "arch=x86_64\n", ""), false, false},
		{"duplicate", healthyPrerequisites + "os=alpine\n", false, false},
		{"extra", healthyPrerequisites + "credential=never-read\n", false, false},
		{"oversized", strings.Repeat("x", 4097), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := decodePrerequisites("root@host", tc.body)
			if (err == nil) != tc.valid || err == nil && r.Supported != tc.supported {
				t.Fatalf("result=%+v err=%v", r, err)
			}
		})
	}
}

func TestMachineEnvelopeSubprocessBoundary(t *testing.T) {
	// A separate process exercises the same stdout/stderr and deadline boundary
	// as a real CLI, without re-entering the test binary as a command.
	dir := t.TempDir()
	helper := filepath.Join(dir, "cli")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\ncase \"$1\" in\n version) printf '{\"version\":\"fixture\"}\\n';;\n doctor) printf '{\"checks\":[{\"ok\":false}]}\\n'; echo 'unsupported server' >&2; exit 1;;\n deploy) echo 'transport interrupted' >&2; exit 1;;\n logs) printf 'untrusted app text\\n';;\n report) while :; do :; done;;\nesac\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		ok   bool
		code string
	}{
		{[]string{"version"}, true, ""},
		{[]string{"doctor", "--host", "root@host"}, false, "command_failed"},
		{[]string{"deploy", "--host", "root@host", "--app", "mailroom"}, false, "command_failed"},
		{[]string{"logs"}, true, ""},
		{[]string{"ui"}, false, "unsupported_command"},
		{[]string{"--timeout", "1s", "report"}, false, "timeout"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			var out, progress bytes.Buffer
			status := machineWithExecutable(helper, tc.args, strings.NewReader(""), &out, &progress)
			var r MachineResult
			if err := json.Unmarshal(out.Bytes(), &r); err != nil {
				t.Fatal(err, out.String())
			}
			if r.Version != 1 || r.OK != tc.ok || (status == 0) != tc.ok {
				t.Fatalf("%+v status=%d", r, status)
			}
			if !tc.ok && (r.Error == nil || r.Error.Code != tc.code || r.Error.Retryable) {
				t.Fatalf("%+v", r)
			}
			if tc.args[0] == "doctor" && !bytes.Contains(r.Data, []byte("checks")) {
				t.Fatal("failed doctor lost its typed checks")
			}
			if tc.args[0] == "deploy" && (!r.Error.ReconciliationRequired || !strings.Contains(strings.Join(r.NextAction, " "), "operation inspect")) {
				t.Fatalf("uncertain deployment lacks inspection: %+v", r)
			}
		})
	}
}

func TestAgentCLIRealBinaryDiscoveryAndHelp(t *testing.T) {
	if testing.Short() {
		t.Skip("real CLI compilation")
	}
	cli := filepath.Join(t.TempDir(), "komizo")
	build := exec.Command("go", "build", "-o", cli, "../..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	for _, capability := range agentCommands {
		out, err := exec.Command(cli, "--json", capability.Name, "--help").Output()
		var result MachineResult
		if err != nil || json.Unmarshal(out, &result) != nil || !result.OK {
			t.Fatal("advertised command help failed", capability.Name, err, string(out))
		}
	}
	for _, args := range [][]string{{"--json", "capabilities"}, {"--json", "version"}, {"--json", "init", "--help"}, {"--json", "add", "--help"}, {"--json", "report", "--help"}, {"--json", "deploy", "--help"}, {"--json", "setup", "--help"}, {"--json", "operation", "--help"}, {"--json", "platform", "--help"}} {
		cmd := exec.Command(cli, args...)
		var out, stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatal(args, err, out.String(), stderr.String())
		}
		var result MachineResult
		if err := json.Unmarshal(out.Bytes(), &result); err != nil || !result.OK {
			t.Fatal(args, err, out.String())
		}
	}
	for _, args := range [][]string{{"--json", "unknown"}, {"--json", "add", "--definitely-not-a-flag", "--help"}, {"--json", "deploy", "--host", "host", "--app", "other", "--version", "bad"}, {"--json", "operation", "recover", "--host", "host", "--app", "other"}, {"--json", "add", "--host", "host", "--app", "other", "--config", "ghcr.io/courier/other-config"}} {
		out, err := exec.Command(cli, args...).Output()
		if err == nil {
			t.Fatal("unsafe request succeeded", args)
		}
		var result MachineResult
		if json.Unmarshal(out, &result) != nil || result.OK || result.Error == nil {
			t.Fatal(args, string(out))
		}
		if bytes.Contains(out, []byte("PRIVATE KEY")) {
			t.Fatal("private key exposed")
		}
	}
}

func TestJourneyCredentialFilesAndDefinitionBounds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("private-token"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readJourneyFile(path, 64, true); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readJourneyFile(path, 64, true); err == nil {
		t.Fatal("public credential accepted")
	}
	if _, err := readJourneyFile(path, 3, false); err == nil {
		t.Fatal("oversized input accepted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readJourneyFile(link, 64, false); err == nil {
		t.Fatal("symlink accepted")
	}
	for _, body := range []string{`{"version":2}`, `{"version":1,"unknown":"value"}`, `{"version":1} {"version":1}`} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readDefinition(path); err == nil {
			t.Fatal("invalid definition accepted", body)
		}
	}
}

func TestSetupKeyResumeIsBoundToPrivateKeyAndApp(t *testing.T) {
	for n := 0; n < 8; n++ {
		comment := "komizo-mailroom@host" + strings.Repeat("x", n)
		kp, err := newKeypair(comment)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "key")
		if err := os.WriteFile(path, []byte(kp.private), 0600); err != nil {
			t.Fatal(err)
		}
		read, err := readExistingKey(path, comment)
		if err != nil || read.public != kp.public || read.private != kp.private {
			t.Fatal("key resume failed", n, err)
		}
		if _, err := readExistingKey(path, "komizo-other@host"); err == nil {
			t.Fatal("cross-app key reuse accepted")
		}
		if err := os.WriteFile(path, []byte(kp.private[:len(kp.private)/2]), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readExistingKey(path, comment); err == nil {
			t.Fatal("truncated private key accepted")
		}
	}
}
