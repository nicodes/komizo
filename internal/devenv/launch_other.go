//go:build !linux && !darwin

package devenv

import (
	"context"
	"errors"
	"os/exec"
	"time"
)

const shutdownGrace = 5 * time.Second

func launchEnvironment([]string, []string, time.Duration) error {
	return errors.New("ghenv currently supports process supervision on Linux and macOS only")
}

func launch([]string, map[string]string) error {
	return errors.New("ghenv currently supports process supervision on Linux and macOS only")
}

func RunCommand(context.Context, *exec.Cmd, time.Duration) error {
	return errors.New("local process supervision requires Linux or macOS")
}
