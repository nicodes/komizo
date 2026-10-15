package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/scripts"
)

func runPreviewDatabase() error {
	if os.Geteuid() != 0 {
		return errors.New("preview database requires the root operator")
	}
	if err := enterReadBudget(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	unlock, err := box.LockPreviewInfrastructure(ctx, "")
	if err != nil {
		return err
	}
	defer unlock()
	records, err := box.ListPreviews("")
	if err != nil || len(records) > 0 {
		return errors.New("preview database provisioning requires no active or retained preview records")
	}
	if _, err := previewHostResources("/etc/komizo/resources.json"); err != nil {
		return err
	}
	body, err := protectedActivationBytes("/etc/komizo/resources.json")
	if err != nil {
		return err
	}
	program := "import types\n_shared = types.ModuleType('komizo_platform')\nexec(" + strconv.Quote(scripts.Platform) + ", _shared.__dict__)\nPlatform = _shared.Platform\n" + scripts.PreviewDatabase
	command := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-c", program, deploymentHash(body))
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/root", "LC_ALL=C"}
	command.Dir = "/"
	command.WaitDelay = 2 * time.Second
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	return command.Run()
}
