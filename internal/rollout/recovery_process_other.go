//go:build !linux

package rollout

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
)

func recoveryVerifierCommand(context.Context, *os.File, RecoveryAuthorization) (io.WriteCloser, io.ReadCloser, *exec.Cmd, error) {
	return nil, nil, nil, errors.New("verified recovery execution is available only on the Linux box runtime")
}

func killRecoveryVerifier(command *exec.Cmd) {
	if command != nil && command.Process != nil {
		_ = command.Process.Kill()
	}
}
