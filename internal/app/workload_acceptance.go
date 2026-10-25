package app

import (
	"context"
	"errors"
	"github.com/nicodes/komizo/scripts"
	"os/exec"
	"strconv"
	"time"
)

func RunWorkloadAcceptance(args []string) error {
	if len(args) == 0 || args[0] != "acceptance" {
		return errors.New("workload requires acceptance --profile PATH --host root@HOST --output PATH")
	}
	ctx, cancel := context.WithTimeout(commandContext(), 35*time.Minute)
	defer cancel()
	source := "_SOURCE=" + strconv.Quote(scripts.WorkloadAcceptance) + "\n" + scripts.WorkloadAcceptance
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", append([]string{"-I", "-c", source}, args[1:]...)...)
	cmd.WaitDelay = 2 * time.Second
	cmd.Stdout, cmd.Stderr = commandOutput(), commandProgress()
	cmd.Stdin = nil
	return runProtocolCommand(cmd, args)
}
