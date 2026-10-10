package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBoxSSHDoesNotInheritAgentForwarding(t *testing.T) {
	config := filepath.Join(t.TempDir(), "ssh_config")
	if err := os.WriteFile(config, []byte("Host *\n ForwardAgent yes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	target := target{user: "root", host: "fixture.invalid", port: 22}
	args := append([]string{"-G", "-F", config}, target.sshArgs()...)
	output, err := exec.Command("ssh", args...).Output()
	if err != nil {
		t.Fatalf("resolve effective SSH configuration: %v", err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "forwardagent ") {
			if line != "forwardagent no" {
				t.Fatal("box connection inherited signing-agent forwarding")
			}
			return
		}
	}
	t.Fatal("effective SSH configuration omitted forwarding policy")
}
