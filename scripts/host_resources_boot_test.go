package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostResourceBootFailurePreventsDockerStart(t *testing.T) {
	_, block, ok := strings.Cut(AlpineInitScript, "# BEGIN host resources boot policy\n")
	if !ok {
		t.Fatal("missing boot policy")
	}
	block, _, ok = strings.Cut(block, "# END host resources boot policy")
	if !ok {
		t.Fatal("missing boot policy end")
	}
	_, service, ok := strings.Cut(block, "<<'KOMIZO_RESOURCES_EOF'\n")
	if !ok {
		t.Fatal("missing service")
	}
	service, _, ok = strings.Cut(service, "\nKOMIZO_RESOURCES_EOF")
	if !ok {
		t.Fatal("missing service end")
	}
	dir := t.TempDir()
	policy := filepath.Join(dir, "resources.json")
	helper := filepath.Join(dir, "komizo-box")
	for _, failure := range []bool{false, true} {
		status := "0"
		if failure {
			status = "23"
		}
		if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit "+status+"\n"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(policy, []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
		script := strings.ReplaceAll(service, "/etc/komizo/resources.json", policy)
		script = strings.ReplaceAll(script, "/usr/local/bin/komizo-box", helper)
		cmd := exec.Command("sh", "-c", script+"\nstart\n")
		out, err := cmd.CombinedOutput()
		if (err != nil) != failure {
			t.Fatalf("failed=%v, got %v %s", failure, err, out)
		}
	}
	if !strings.Contains(block, `rc_need="${rc_need} komizo-resources"`) || !strings.Contains(service, "need cgroups") || !strings.Contains(service, "before docker") {
		t.Fatal("Docker lacks a hard resource dependency")
	}
	if strings.Index(AlpineInitScript, "# END host resources boot policy") > strings.Index(AlpineInitScript, "rc-service docker start") {
		t.Fatal("Docker starts before policy applies")
	}
}
