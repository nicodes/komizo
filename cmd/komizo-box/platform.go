package main

import (
	"errors"
	"os"
	"os/exec"
	"strconv"

	"github.com/nicodes/komizo/scripts"
)

func runPlatform(args []string) error {
	if len(args) > 0 && args[0] == "maintenance" {
		program := "import types\n_shared = types.ModuleType('komizo_platform')\nexec(" + strconv.Quote(scripts.Platform) + ", _shared.__dict__)\nPlatform = _shared.Platform\n" + scripts.Maintenance
		command := exec.Command("/usr/bin/python3", append([]string{"-I", "-c", program}, args[1:]...)...)
		command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/root", "LC_ALL=C"}
		command.Dir = "/"
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		return command.Run()
	}
	if os.Geteuid() != 0 || len(args) != 3 || (args[0] != "apply" && args[0] != "recover" && args[0] != "inspect") {
		return errors.New("platform requires the root operator, apply/recover/inspect, protected stage and exact manifest digest")
	}
	command := exec.Command("/usr/bin/python3", "-I", "-c", scripts.Platform, args[0], args[1], args[2])
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/root", "LC_ALL=C"}
	command.Dir = "/"
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	return command.Run()
}
