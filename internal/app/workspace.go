package app

import (
	"context"
	"errors"
	"github.com/nicodes/komizo/scripts"
	"os"
	"os/exec"
	"time"
)

// Workspace operations inspect disk space or remove an exact reviewed set of
// caller-owned generated files. They never prune shared caches or evidence.
func RunWorkspace(args []string) error {
	if len(args) == 0 {
		return errors.New("workspace requires check, plan or clean")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c := exec.CommandContext(ctx, "/usr/bin/python3", append([]string{"-I", "-c", scripts.WorkspaceStorage}, args...)...)
	c.WaitDelay = 2 * time.Second
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	c.Stdin = nil
	return c.Run()
}
