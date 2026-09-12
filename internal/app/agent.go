package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os/exec"
	"strings"

	"github.com/nicodes/komizo/internal/agent"
	"github.com/nicodes/komizo/scripts"
)

// Putting the agent on a box.
//
// Two connections rather than one. The binary is several megabytes of ELF and
// the installer is shell, and the obvious way to send both at once -- base64 in
// a heredoc -- costs a third more bytes, needs a base64 on the far end that
// Alpine's busybox spells differently, and turns a transfer failure into a
// syntax error in the middle of a script running as root.

// installAgent stages komizo-box on the box and runs the installer.
func installAgent(t target) error {
	arch, err := boxArch(t)
	if err != nil {
		return err
	}
	// EMBEDDED IF THIS KOMIZO CARRIES ONE, BUILT IF IT DOES NOT.
	//
	// A release archive carries the agents, so this needs no toolchain and no
	// network. A `go install`/`go run` build carries none -- the agents are
	// gitignored build artifacts, absent from the module the proxy serves -- and
	// for that case agent.Get compiles one from the same module at the same
	// version. See internal/agent/build.go for why building beats fetching.
	//
	// The stamp comes back with the bytes because the two paths record
	// different KINDS of stamp, and only agent.Get knows which one it took.
	path, version := moduleRef()
	bin, stamp, err := agent.Get(context.Background(), path, version, arch)
	if err != nil {
		return err
	}
	if err := stageAgent(t, bin); err != nil {
		return fmt.Errorf("could not copy the agent to %s: %w", t.host, err)
	}
	return t.runScript(scripts.AgentInstall(stamp, versionText()), nil)
}

// boxArch asks the box what it is.
//
// Asked, never assumed. komizo is pointed at other people's servers and a
// laptop's architecture says nothing about theirs -- and an amd64 binary on an
// arm64 box fails with the kernel reporting "not found" about a file that
// plainly exists, which is the single most confusing thing an exec can say.
func boxArch(t target) (string, error) {
	out, err := t.quiet("uname -m")
	if err != nil {
		return "", fmt.Errorf("could not ask %s what architecture it is: %w", t.host, err)
	}
	uname := strings.TrimSpace(out)
	arch, ok := agent.ArchFor(uname)
	if !ok {
		return "", fmt.Errorf("%s reports architecture %q, which komizo has no agent for.\n"+
			"    komizo ships linux/amd64 and linux/arm64.", t.host, uname)
	}
	return arch, nil
}

// stageAgent writes the binary to a temporary path on the box.
//
// `cat` rather than scp: it needs no second tool on either end, it reuses the
// connection settings target already knows about -- port, key, known_hosts --
// and scp would need every one of them restated in scp's own spelling.
//
// Written to a staging path and moved into place by the installer, because
// overwriting a running executable is ETXTBSY at best and a half-written binary
// at worst.
func stageAgent(t target, bin []byte) error {
	c := exec.Command("ssh", t.sshArgs("cat > "+scripts.ShQuote(scripts.StagedAgent))...)
	return runAgentTransfer(c, bin)
}

func stageAgentAt(t target, bin []byte, destination string) error {
	command := "set -euC; umask 077; cat > " + scripts.ShQuote(destination)
	c := exec.Command("ssh", t.sshArgs(command)...)
	return runAgentTransfer(c, bin)
}

func runAgentTransfer(c *exec.Cmd, bin []byte) error {
	c.Stdin = bytes.NewReader(bin)
	var errb bytes.Buffer
	c.Stderr = &errb
	if err := c.Run(); err != nil {
		if s := strings.TrimSpace(errb.String()); s != "" {
			return fmt.Errorf("%w: %s", err, s)
		}
		return err
	}
	return nil
}

func rolloutRuntimePath(app string) string {
	return "/usr/local/libexec/komizo/rollouts/" + app + "/komizo-box"
}

// installRolloutRuntime carries the agent embedded in this verified CLI to one
// application's private broker path. It never replaces the host-wide agent.
func installRolloutRuntime(t target, app string) (string, error) {
	arch, err := boxArch(t)
	if err != nil {
		return "", err
	}
	path, version := moduleRef()
	bin, _, err := agent.Get(context.Background(), path, version, arch)
	if err != nil {
		return "", err
	}
	staged := "/tmp/.komizo-rollout-" + app + "-" + rand.Text()
	if err := stageAgentAt(t, bin, staged); err != nil {
		return "", fmt.Errorf("could not stage app-scoped rollout runtime: %w", err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(bin))
	destination := rolloutRuntimePath(app)
	if err := t.runScript(scripts.RolloutRuntimeInstall(staged, destination, digest), nil); err != nil {
		return "", fmt.Errorf("could not install app-scoped rollout runtime: %w", err)
	}
	return destination, nil
}
