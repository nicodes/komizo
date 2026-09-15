//go:build linux

package rollout

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func recoveryVerifierCommand(ctx context.Context, file *os.File, a RecoveryAuthorization) (io.WriteCloser, io.ReadCloser, *exec.Cmd, error) {
	command := exec.CommandContext(ctx, "/proc/self/fd/3", a.VerifierArgs...)
	command.Args = append([]string{filepath.Base(a.VerifierPath)}, a.VerifierArgs...)
	command.ExtraFiles = []*os.File{file}
	command.Env = []string{"HOME=/nonexistent", "LANG=C", "PATH=/usr/bin:/bin"}
	command.Dir = "/"
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Credential: &syscall.Credential{Uid: a.UID, Gid: a.GID, NoSetGroups: true}}
	command.Stderr = io.Discard
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, nil, nil, errors.New("cannot open recovery verifier input")
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, nil, nil, errors.New("cannot open recovery verifier output")
	}
	return stdin, stdout, command, nil
}

func killRecoveryVerifier(command *exec.Cmd) {
	if command.Process != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
}
