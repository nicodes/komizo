package app

import (
	"context"
	"errors"
	"github.com/nicodes/komizo/scripts"
	"os"
	"os/exec"
	"time"
)

// Preparation authenticates released bytes and emits a reviewable finite plan.
// Execution requires the operator's exact prepared manifest, not an implicit yes.
func RunPlatform(args []string) error {
	if len(args) == 0 || (args[0] != "plan" && args[0] != "apply") {
		return errors.New("platform requires plan or apply; installed recovery uses komizo-box platform recover")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/python3", append([]string{"-I", "-c", scripts.PlatformPrepare}, args...)...)
	command.WaitDelay = 2 * time.Second
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	command.Stdin = nil
	return command.Run()
}
