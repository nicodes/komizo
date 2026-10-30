package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const healthyPrerequisites = "os=alpine\nkernel=Linux\narch=x86_64\nuid=0\nmemory_kib=1048576\ndisk_kib=4194304\ninodes=800000\napk=yes\nopenrc=yes\ncgroup_v2=yes\ninstalled=yes\n"

func TestDoctorInstallationIsManagedStateRatherThanBinaryPresence(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("executes the Linux prerequisite script")
	}
	root := t.TempDir()
	binary := filepath.Join(root, "komizo-box")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0700); err != nil {
		t.Fatal(err)
	}
	script := strings.ReplaceAll(doctorScript, "/usr/local/bin/komizo-box", binary)
	script = strings.ReplaceAll(script, "/var/lib/komizo", root)
	probe := func(want bool) {
		t.Helper()
		out, err := exec.Command("sh", "-c", script).Output()
		if err != nil {
			t.Fatal(err)
		}
		result, err := decodePrerequisites("root@fixture", string(out))
		if err != nil || result.Installed != want {
			t.Fatalf("installed=%v want=%v err=%v", result.Installed, want, err)
		}
	}
	probe(false) // An authenticated staged executable is not an installation.
	marker := filepath.Join(root, "version")
	if err := os.WriteFile(marker, []byte("0.0.121\nstamp\n"), 0600); err != nil {
		t.Fatal(err)
	}
	probe(true)
	if err := os.Remove(binary); err != nil {
		t.Fatal(err)
	}
	probe(true) // Missing code on an established host needs explicit repair.
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "apps"), 0700); err != nil {
		t.Fatal(err)
	}
	probe(true) // Legacy registration authority must never look like a new host.
}

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

func TestMachineNativeResultsAndUncertainMutations(t *testing.T) {
	for _, tc := range []struct {
		name    string
		failure bool
		code    string
	}{
		{"version", false, ""}, {"doctor", true, "command_failed"}, {"deploy", true, "command_failed"}, {"logs", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, progress bytes.Buffer
			args := []string{tc.name, "--host", "root@host", "--app", "mailroom"}
			status := machineDispatch(context.Background(), args, strings.NewReader(""), &out, &progress, func([]string) error {
				if tc.name == "logs" {
					fmt.Fprintln(commandOutput(), "untrusted app text")
				} else {
					if err := emitResult(map[string]any{"checks": []bool{false}}); err != nil {
						return err
					}
				}
				if tc.failure {
					return errors.New("transport interrupted")
				}
				return nil
			})
			var r MachineResult
			if err := json.Unmarshal(out.Bytes(), &r); err != nil {
				t.Fatal(err, out.String())
			}
			if r.OK == tc.failure || (status == 0) == tc.failure {
				t.Fatalf("%+v status=%d", r, status)
			}
			if tc.failure && (r.Error == nil || r.Error.Code != tc.code || r.Error.Retryable) {
				t.Fatalf("%+v", r)
			}
			if tc.name == "doctor" && !bytes.Contains(r.Data, []byte("checks")) {
				t.Fatal("failed doctor lost typed checks")
			}
			if tc.name == "deploy" && (!r.Error.ReconciliationRequired || !strings.Contains(strings.Join(r.NextAction, " "), "operation inspect")) {
				t.Fatalf("%+v", r)
			}
		})
	}
}

func TestMachineNativeDeadlineReachesSSHAndKeepsUncertainty(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte("#!/bin/sh\nexec sleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	var out, progress bytes.Buffer
	start := time.Now()
	machineDispatch(ctx, []string{"deploy", "--host", "root@host", "--app", "mailroom"}, strings.NewReader(""), &out, &progress, func([]string) error {
		_, err := (target{user: "root", host: "host", port: 22}).quiet("ignored")
		return err
	})
	var result MachineResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 3*time.Second || result.Error == nil || result.Error.Code != "timeout" || !result.Error.ReconciliationRequired {
		t.Fatalf("%+v", result)
	}
}

func TestMachineWillNotInferSuccessFromPrintedJSON(t *testing.T) {
	var out, progress bytes.Buffer
	machineDispatch(context.Background(), []string{"version"}, nil, &out, &progress, func([]string) error {
		fmt.Fprint(commandOutput(), `{"version":"forged"}`)
		return nil
	})
	var result MachineResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.OK || result.Error == nil || result.Error.Code != "invalid_response" {
		t.Fatalf("%+v", result)
	}
}

// Exercise the complete flag/help matrix through the dispatcher in-process.
// The real-binary test below retains the outer JSON/exit/transport boundary.
func TestAgentCLICommandHelpMatrix(t *testing.T) {
	cases := [][]string{{"platform", "inspect"}, {"platform", "recover"}}
	for _, capability := range agentCommands {
		cases = append(cases, []string{capability.Name})
	}
	for _, args := range cases {
		t.Run(strings.Join(args, "/"), func(t *testing.T) {
			var output, progress bytes.Buffer
			code := CLI(append(append([]string{"--json"}, args...), "--help"), strings.NewReader(""), &output, &progress)
			var result MachineResult
			if err := json.Unmarshal(output.Bytes(), &result); err != nil || code != 0 || !result.OK {
				t.Fatalf("advertised help failed: %d %s %s", code, output.String(), progress.String())
			}
			var data struct {
				Text string `json:"text"`
			}
			_ = json.Unmarshal(result.Data, &data)
			out := data.Text
			if args[0] == "capabilities" || args[0] == "version" {
				out = string(result.Data)
			}
			if strings.TrimSpace(out) == "" {
				t.Fatal("advertised command produced no help")
			}
			if args[0] == "setup" || args[0] == "platform" && len(args) > 1 {
				if !strings.Contains(out, "--host") {
					t.Fatalf("host flag absent from help: %s", out)
				}
			}
			if args[0] == "platform" && len(args) > 1 {
				if !strings.Contains(out, "--stage") || !strings.Contains(out, "--expected-manifest") {
					t.Fatalf("recovery flags absent from help: %s", out)
				}
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
	checkManagementBinary(t, cli)
	for _, args := range [][]string{{"--json", "capabilities"}, {"--json", "version"}, {"--json", "add", "--help"}, {"--json", "report", "--help"}, {"--json", "deploy", "--help"}, {"--json", "setup", "--help"}, {"--json", "operation", "--help"}, {"--json", "platform", "--help"}} {
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
	for _, args := range [][]string{{"--json", "init", "--help"}, {"--json", "check"}, {"--json", "dev"}, {"--json", "exec"}, {"--json", "lock"}, {"--json", "operator"}, {"--json", "dependencies"}, {"--json", "unknown"}, {"--json", "add", "--definitely-not-a-flag", "--help"}, {"--json", "deploy", "--host", "host", "--app", "other", "--version", "bad"}, {"--json", "operation", "recover", "--host", "host", "--app", "other"}, {"--json", "add", "--host", "host", "--app", "other", "--config", "ghcr.io/courier/other-config"}} {
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

func TestDeploymentAcknowledgementMatchesTheHostWireProtocol(t *testing.T) {
	id, previous := strings.Repeat("a", 32), strings.Repeat("b", 40)
	wire := "deploy: previous-version=" + previous + "\ndeploy: submitted=" + id + "\n" + id + "\n"
	got, prior, err := decodeDeploymentAcknowledgement([]byte(wire))
	if err != nil || got != id || prior != previous {
		t.Fatal(got, prior, err)
	}
	for _, bad := range []string{id, wire + "extra\n", strings.Replace(wire, "submitted="+id, "submitted="+strings.Repeat("c", 32), 1), strings.Replace(wire, previous, "unknown", 1)} {
		if _, _, err := decodeDeploymentAcknowledgement([]byte(bad)); err == nil {
			t.Fatal("ambiguous acknowledgement accepted", bad)
		}
	}
}

func TestNativeOutputCopyCannotBypassRetention(t *testing.T) {
	output := &boundedOutput{remaining: 8}
	count, err := io.Copy(output, strings.NewReader(strings.Repeat("x", 1024)))
	if err != nil || count != 1024 || output.Len() != 8 || !output.truncated {
		t.Fatalf("retention boundary failed: count=%d retained=%d truncated=%v error=%v", count, output.Len(), output.truncated, err)
	}
}

func TestPlatformObservationFailureDoesNotClaimUncertainMutation(t *testing.T) {
	for _, operation := range []string{"inspect"} {
		var out, progress bytes.Buffer
		machineDispatch(context.Background(), []string{"platform", operation}, strings.NewReader(""), &out, &progress, func([]string) error { return errors.New("unavailable service observation") })
		var result MachineResult
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.OK || result.Error == nil || result.Error.ReconciliationRequired {
			t.Fatal(operation, out.String())
		}
	}
}
