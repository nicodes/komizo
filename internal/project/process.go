package project

import (
	"context"
	"github.com/nicodes/komizo/internal/devenv"
	"os/exec"
	"time"
)

func runCommand(ctx context.Context, cmd *exec.Cmd) error {
	err := devenv.RunCommand(ctx, cmd, 2*time.Second)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
