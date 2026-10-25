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

	"github.com/nicodes/komizo/internal/project"
)

func TestPrivateTargetIsBoundToRepositoryAndCannotMoveImplicitly(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	repo := t.TempDir()
	if _, err := project.Init(repo, "static-site", versionText()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repo, "komizo.json")
	body := []byte(`{"version":1,"recipe":"static-site","repository":"example/site"}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := project.WriteLock(repo, versionText()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := projectBinding(repo); err == nil {
		t.Fatal("unconfigured repository acquired authority")
	}
	target := target{user: "root", host: "host.example", port: 2222}
	if err := bindProjectTarget("example/site", target, "site"); err != nil {
		t.Fatal(err)
	}
	if err := bindProjectTarget("example/site", target, "site"); err != nil {
		t.Fatal("idempotent setup failed", err)
	}
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	configuredPort := 22
	fs.IntVar(&configuredPort, "port", 22, "port")
	configuredHost, configuredApp := "", ""
	if _, err := defaultProjectTarget(repo, &configuredHost, &configuredPort, &configuredApp, fs); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveTarget(fs, configuredHost, configuredPort)
	if err != nil || resolved.port != 2222 || !resolved.portExplicit {
		t.Fatalf("private port lost to SSH defaults: %+v %v", resolved, err)
	}
	_, binding, err := projectBinding(repo)
	if err != nil || binding.Host != target.addr() || binding.Port != 2222 {
		t.Fatal(binding, err)
	}
	target.host = "other.example"
	if err := bindProjectTarget("example/site", target, "site"); err == nil {
		t.Fatal("setup silently moved a project target")
	}
	host, port, app := "", 22, "different"
	if _, err := defaultProjectTarget(repo, &host, &port, &app, nil); err == nil {
		t.Fatal("project changed its private application scope")
	}
	if err := os.WriteFile(path, bytes.ReplaceAll(body, []byte("example/site"), []byte("example/foreign")), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := project.WriteLock(repo, versionText()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := projectBinding(repo); err == nil {
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
	if revision, err := projectRevision(root); err != nil || len(revision) != 40 {
		t.Fatal(revision, err)
	}
	if err := os.WriteFile(file, []byte("two"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := projectRevision(root); err == nil {
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
