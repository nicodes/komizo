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
	if len(args) > 0 && args[0] == "maintenance" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		command := exec.CommandContext(ctx, "/usr/bin/python3", append([]string{"-I", "-c", scripts.MaintenancePrepare}, args[1:]...)...)
		command.WaitDelay = 2 * time.Second
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		return command.Run()
	}
	proxy := len(args) > 0 && args[0] == "proxy"
	controls := len(args) > 0 && args[0] == "controls"
	if proxy || controls {
		args = args[1:]
	}
	if len(args) == 0 || (args[0] != "plan" && args[0] != "apply") {
		return errors.New("platform requires plan or apply; installed recovery uses komizo-box platform recover")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	program := scripts.PlatformPrepare
	if proxy {
		program = "import types\n_shared = types.ModuleType('komizo_platform_prepare')\nexec(" + strconv.Quote(scripts.PlatformPrepare) + ", _shared.__dict__)\nrun, digest, protected_directory, HOST = _shared.run, _shared.digest, _shared.protected_directory, _shared.HOST\n" + "\n_runtime = types.ModuleType('komizo_proxy_runtime')\nexec(" + strconv.Quote(scripts.Platform) + ", _runtime.__dict__)\nproxy_runtime_environment = _runtime.proxy_runtime_environment\n" + scripts.ProxyPrepare
	}
	if controls {
		program = "import types\n_shared = types.ModuleType('komizo_platform_prepare')\nexec(" + strconv.Quote(scripts.PlatformPrepare) + ", _shared.__dict__)\nprepare, run, protected_directory, HOST = _shared.prepare, _shared.run, _shared.protected_directory, _shared.HOST\n_platform = types.ModuleType('komizo_platform')\nexec(" + strconv.Quote(scripts.Platform) + ", _platform.__dict__)\ncontrol_configuration, CONTROL_SERVICES = _platform.control_configuration, _platform.CONTROL_SERVICES\n" + scripts.ControlsPrepare
	}
	command := exec.CommandContext(ctx, "/usr/bin/python3", append([]string{"-I", "-c", program}, args...)...)
	command.WaitDelay = 2 * time.Second
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	command.Stdin = nil
	return command.Run()
}
