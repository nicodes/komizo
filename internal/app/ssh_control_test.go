package app

import (
	"os/exec"
	"strings"
	"testing"
)

func TestLongHomesUseDirectSSHWithTheSameTrustPolicy(t *testing.T) {
	if multiplexSocketPath("/home/example/.ssh") == "" {
		t.Fatal("ordinary home lost connection reuse")
	}
	if multiplexSocketPath("/home/"+strings.Repeat("long", 20)+"/.ssh") != "" {
		t.Fatal("unusable Unix socket path selected")
	}
	if multiplexSocketPath("/home/"+strings.Repeat("é", 32)+"/.ssh") != "" {
		t.Fatal("Unicode path counted as characters rather than bytes")
	}
	previous := controlPath
	controlPath = func() string { return "" }
	defer func() { controlPath = previous }()
	args := append([]string{"-G", "-F", "/dev/null"}, (target{user: "root", host: "example.test", port: 22}).sshArgs()...)
	if !strings.Contains(strings.Join(args, " "), "ControlPath=none") {
		t.Fatal("long home inherited a configured socket")
	}
	output, err := exec.Command("ssh", args...).Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"controlmaster false", "stricthostkeychecking true", "forwardagent no"} {
		if !strings.Contains(strings.ToLower(string(output)), want) {
			t.Fatal("direct SSH changed connection security", want, string(output))
		}
	}
}
