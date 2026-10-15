package main

import (
	"context"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	"github.com/nicodes/komizo/scripts"
)

func applySmallHostCompressedSwap(total int64) error {
	if runtime.GOOS != "linux" || total > 2<<30 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-c", scripts.CompressedSwap, strconv.FormatInt(total, 10))
	command.Env = []string{"PATH=/usr/sbin:/sbin:/usr/bin:/bin", "LC_ALL=C"}
	command.Dir = "/"
	command.WaitDelay = 2 * time.Second
	return command.Run()
}
