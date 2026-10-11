package main

import (
	"errors"
	"os"
	"os/exec"

	"github.com/nicodes/komizo/scripts"
)

func runPlatform(args []string) error {
	if os.Geteuid() != 0 || len(args) != 3 || (args[0] != "apply" && args[0] != "recover" && args[0] != "inspect") {
		return errors.New("platform requires the root operator, apply/recover/inspect, protected stage and exact manifest digest")
	}
	command := exec.Command("/usr/bin/python3", "-I", "-c", scripts.Platform, args[0], args[1], args[2])
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/root", "LC_ALL=C"}
	command.Dir = "/"
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	return command.Run()
}
