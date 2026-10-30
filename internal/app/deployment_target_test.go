package app

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateTargetIsBoundToRepositoryAndCannotMoveImplicitly(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	repo := t.TempDir()
	path := filepath.Join(repo, "komizo.json")
	body := []byte(`{"version":1,"repository":"example/site"}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := deploymentBinding(repo); err == nil {
		t.Fatal("unconfigured repository acquired authority")
	}
	target := target{user: "root", host: "host.example", port: 2222}
	if err := bindDeploymentTarget("example/site", target, "site"); err != nil {
		t.Fatal(err)
	}
	if err := bindDeploymentTarget("example/site", target, "site"); err != nil {
		t.Fatal("idempotent setup failed", err)
	}
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	configuredPort := 22
	fs.IntVar(&configuredPort, "port", 22, "port")
	configuredHost, configuredApp := "", ""
	if _, err := defaultDeploymentTarget(repo, &configuredHost, &configuredPort, &configuredApp, fs); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveTarget(fs, configuredHost, configuredPort)
	if err != nil || resolved.port != 2222 || !resolved.portExplicit {
		t.Fatalf("private port lost to SSH defaults: %+v %v", resolved, err)
	}
	_, binding, err := deploymentBinding(repo)
	if err != nil || binding.Host != target.addr() || binding.Port != 2222 {
		t.Fatal(binding, err)
	}
	target.host = "other.example"
	if err := bindDeploymentTarget("example/site", target, "site"); err == nil {
		t.Fatal("setup silently moved a project target")
	}
	host, port, app := "", 22, "different"
	if _, err := defaultDeploymentTarget(repo, &host, &port, &app, nil); err == nil {
		t.Fatal("project changed its private application scope")
	}
	if err := os.WriteFile(path, bytes.ReplaceAll(body, []byte("example/site"), []byte("example/foreign")), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := deploymentBinding(repo); err == nil {
		t.Fatal("foreign repository acquired target")
	}
	targetFile, _ := targetPath()
	if err := os.Chmod(targetFile, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readTargets(); err == nil {
		t.Fatal("public target file accepted")
	}
}

func TestProjectRevisionNeverSelectsUncommittedWork(t *testing.T) {
	root := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		if body, err := cmd.CombinedOutput(); err != nil {
			t.Fatal(err, string(body))
		}
	}
	git("init", "-q")
	git("config", "user.email", "fixture@example.test")
	git("config", "user.name", "Fixture")
	file := filepath.Join(root, "source.txt")
	if err := os.WriteFile(file, []byte("one"), 0600); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-qm", "fixture")
	if revision, err := deploymentRevision(root); err != nil || len(revision) != 40 {
		t.Fatal(revision, err)
	}
	if err := os.WriteFile(file, []byte("two"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := deploymentRevision(root); err == nil {
		t.Fatal("uncommitted source selected for deployment")
	}
}

func TestGlobalProjectFlagsDoNotReachHostBootstrap(t *testing.T) {
	dir := t.TempDir()
	var output, progress bytes.Buffer
	status := CLI([]string{"--json", "--timeout", "1s", "init", "--host", "fixture.invalid", "--directory", dir}, strings.NewReader(""), &output, &progress)
	var result MachineResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || status == 0 || result.OK {
		t.Fatalf("%s %s", output.String(), progress.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "komizo.json")); !os.IsNotExist(err) {
		t.Fatal("invalid init changed project")
	}
}

func TestDeploymentTargetDoesNotReadSDKPinsOrRuntimeLocks(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "komizo.json"), []byte(`{"version":1,"repository":"unrelated/application","images":["registry.example/unrelated/app:{revision}"]}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := bindDeploymentTarget("unrelated/application", target{user: "root", host: "host.example", port: 2222}, "application"); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"mise.toml", "komizo.lock"} {
		if err := os.WriteFile(filepath.Join(root, file), []byte("deliberately invalid development input"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	config, binding, err := deploymentBinding(root)
	if err != nil || config.Repository != "unrelated/application" || binding.App != "application" {
		t.Fatal(config, binding, err)
	}
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	port := fs.Int("port", 22, "port")
	if err := fs.Parse([]string{"--port", "3333"}); err != nil {
		t.Fatal(err)
	}
	host, app := "", ""
	if _, err := defaultDeploymentTarget(root, &host, port, &app, fs); err == nil || host != "" || app != "" {
		t.Fatal("conflicting private target changed scope", host, app, err)
	}
}

func TestDeploymentConfigurationRejectsDevelopmentFieldsAndAmbiguousIdentity(t *testing.T) {
	root := t.TempDir()
	for _, body := range []string{
		`{"version":1,"repository":"example/app","recipe":"go-service"}`,
		`{"version":1,"repository":"example/app","tools":{"go":"1.27.3"}}`,
		`{"version":1,"repository":"example/app","repository":"other/app"}`,
		`{"version":2,"repository":"example/app"}`,
		`{"version":1,"repository":"example/app","images":["registry.example/app:{sdk}"]}`,
		`{"version":1,"repository":"example/app","images":["registry.example/app:source","registry.example/app:source"]}`,
	} {
		if err := os.WriteFile(filepath.Join(root, "komizo.json"), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := readDeploymentConfiguration(root); err == nil {
			t.Fatal("accepted ambiguous or development configuration", body)
		}
	}
	host, port, app := "root@explicit.example", 2222, "explicit"
	if _, err := defaultDeploymentTarget(t.TempDir(), &host, &port, &app, nil); err != nil || host != "root@explicit.example" || app != "explicit" || port != 2222 {
		t.Fatal("explicit SSH selection depends on a repository configuration", host, port, app, err)
	}
}
