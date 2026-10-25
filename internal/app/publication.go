package app

import (
	"context"
	"errors"
	"os/exec"
	"time"

	"github.com/nicodes/komizo/scripts"
)

// RunPublication prepares tested image bytes without registry credentials.
func RunPublication(args []string) error {
	if len(args) == 0 || args[0] != "prepare" {
		return errors.New("publication requires prepare --image SOURCE_TAG --output NEW_DIRECTORY")
	}
	ctx, cancel := context.WithTimeout(commandContext(), 17*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/python3", append([]string{"-I", "-c", scripts.PublicationPrepare}, args...)...)
	command.WaitDelay = 2 * time.Second
	command.Stdout, command.Stderr = commandOutput(), commandProgress()
	return runProtocolCommand(command, args)
}
