package app

import (
	"context"
	"errors"
	"github.com/nicodes/komizo/scripts"
	"os/exec"
	"strconv"
	"time"
)

// Preparation authenticates released bytes and emits a reviewable finite plan.
// Execution requires the operator's exact prepared manifest, not an implicit yes.
func RunPlatform(args []string) error {
	if len(args) > 0 && (args[0] == "inspect" || args[0] == "recover") {
		return runPlatformOperation(args)
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		usageJourney("platform", "komizo platform plan|apply --host HOST --release VERSION --source COMMIT --release-dir DIR --stage DIR", "Use inspect|recover --help for exact-stage recovery, plan --help for upgrade options, maintenance --help for packages, or proxy/controls plan --help. Application recovery is available through komizo operation inspect|recover.")
		return nil
	}
	if len(args) > 0 && args[0] == "maintenance" {
		ctx, cancel := context.WithTimeout(commandContext(), 20*time.Minute)
		defer cancel()
		command := exec.CommandContext(ctx, "/usr/bin/python3", append([]string{"-I", "-c", scripts.MaintenancePrepare}, args[1:]...)...)
		command.WaitDelay = 2 * time.Second
		command.Stdout, command.Stderr = commandOutput(), commandProgress()
		return runProtocolCommand(command, args)
	}
	proxy := len(args) > 0 && args[0] == "proxy"
	controls := len(args) > 0 && args[0] == "controls"
	if proxy || controls {
		args = args[1:]
	}
	if len(args) == 0 || (args[0] != "plan" && args[0] != "apply") {
		return errors.New("platform requires plan or apply; installed recovery uses komizo-box platform recover")
	}
	ctx, cancel := context.WithTimeout(commandContext(), 15*time.Minute)
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
	command.Stdout, command.Stderr = commandOutput(), commandProgress()
	command.Stdin = nil
	return runProtocolCommand(command, args)
}
