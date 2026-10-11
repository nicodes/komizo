package app

import (
	"context"
	"errors"
	"github.com/nicodes/komizo/scripts"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// Preparation authenticates released bytes and emits a reviewable finite plan.
// Execution requires the operator's exact prepared manifest, not an implicit yes.
func RunPlatform(args []string) error {
	proxy := len(args) > 0 && args[0] == "proxy"
	if proxy {
		args = args[1:]
	}
	if len(args) == 0 || (args[0] != "plan" && args[0] != "apply") {
		return errors.New("platform requires plan or apply; installed recovery uses komizo-box platform recover")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	program := scripts.PlatformPrepare
	if proxy {
		program = "import types\n_shared = types.ModuleType('komizo_platform_prepare')\nexec(" + strconv.Quote(scripts.PlatformPrepare) + ", _shared.__dict__)\nrun, digest, protected_directory, HOST = _shared.run, _shared.digest, _shared.protected_directory, _shared.HOST\n" + scripts.ProxyPrepare
	}
	command := exec.CommandContext(ctx, "/usr/bin/python3", append([]string{"-I", "-c", program}, args...)...)
	command.WaitDelay = 2 * time.Second
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	command.Stdin = nil
	return command.Run()
}
