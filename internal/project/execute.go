package project

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/nicodes/komizo/internal/devenv"
)

// Result is shared by the human and machine presentation layers.
type Result struct {
	Recipe     string   `json:"recipe"`
	Targets    []string `json:"targets,omitempty"`
	Completed  bool     `json:"completed"`
	ExitCode   int      `json:"exit_code"`
	Receipt    string   `json:"receipt,omitempty"`
	NextAction []string `json:"next_action,omitempty"`
}

func setEnv(base []string, values map[string]string) []string {
	var result []string
	for _, item := range base {
		name, _, _ := strings.Cut(item, "=")
		if _, replaced := values[name]; !replaced && name != "GOROOT" {
			result = append(result, item)
		}
	}
	for name, value := range values {
		result = append(result, name+"="+value)
	}
	return result
}

func prepare(root, platform string, selected []string) (Manifest, []string, string, error) {
	m, data, err := Read(root)
	if err != nil {
		return m, nil, "", err
	}
	if err = CheckLock(root, platform, data, m); err != nil {
		return m, nil, "", err
	}
	runtimeRoot, err := Runtime()
	if err != nil {
		return m, nil, "", err
	}
	output := filepath.Join(root, ".artifacts", "komizo")
	if err = projectDirectory(root, ".artifacts", "komizo"); err != nil {
		return m, nil, "", err
	}
	contract, err := m.Contract()
	if err != nil {
		return m, nil, "", err
	}
	contractPath := filepath.Join(output, "contract.json")
	if err = writeJSON(contractPath, contract); err != nil {
		return m, nil, "", err
	}
	resolvedTools := m.ToolsForRecipe()
	config, err := toolConfig(resolvedTools)
	if err != nil {
		return m, nil, "", err
	}
	misePath := filepath.Join(root, ".komizo.mise.toml")
	if err = atomicFile(misePath, []byte(config), 0o600); err != nil {
		return m, nil, "", err
	}
	if len(selected) > 0 {
		tools := map[string]json.RawMessage{}
		for _, name := range selected {
			value, exists := resolvedTools[name]
			if !exists || tools[name] != nil {
				return m, nil, "", fmt.Errorf("select unique declared tools; invalid selection %q", name)
			}
			tools[name] = value
		}
		config, err = toolConfig(tools)
		if err != nil {
			return m, nil, "", err
		}
		misePath = filepath.Join(root, ".komizo.mise-"+digest([]byte(config))[:16]+".toml")
		if err = atomicFile(misePath, []byte(config), 0600); err != nil {
			return m, nil, "", err
		}
	}
	values := map[string]string{"CICD_ENGINEERING": runtimeRoot, "KOMIZO_CONTRACT": contractPath,
		"KOMIZO_PROJECT": filepath.Join(root, ManifestName), "KOMIZO_TOOLCHAIN": misePath,
		"PYTHONDONTWRITEBYTECODE": "1", "GOTOOLCHAIN": "local",
		"MISE_OVERRIDE_CONFIG_FILENAMES": filepath.Base(misePath), "MISE_TRUSTED_CONFIG_PATHS": root}
	executable, err := os.Executable()
	if err != nil {
		return m, nil, "", err
	}
	values["KOMIZO_EXECUTABLE"] = executable
	values["KOMIZO_DEV_PROJECT"] = "komizo-" + digest([]byte(filepath.Clean(root)))[:16]
	values["PATH"] = filepath.Dir(executable) + string(os.PathListSeparator) + os.Getenv("PATH")
	if app := m.Release["project"]; app != "" {
		slugs, _ := json.Marshal([]string{app})
		values["BACKUP_ALLOWED_SLUGS"] = string(slugs)
	}
	for name, value := range m.Validation {
		if name != "workflow" && name != "operations" {
			return m, nil, "", fmt.Errorf("unknown validation declaration %q", name)
		}
		path := filepath.Join(output, name+".json")
		if err = atomicFile(path, value, 0o600); err != nil {
			return m, nil, "", err
		}
		switch name {
		case "workflow":
			values["KOMIZO_WORKFLOW_POLICY"] = path
		case "operations":
			values["KOMIZO_WORKFLOW_OPERATIONS"] = path
		default:
			return m, nil, "", fmt.Errorf("unknown validation declaration %q", name)
		}
	}
	return m, setEnv(os.Environ(), values), runtimeRoot, nil
}

// Exec runs an explicit command with the project's locked tools and runtime.
func Exec(ctx context.Context, root, platform string, arguments, selected []string, in io.Reader, out, progress io.Writer) (result Result, err error) {
	result = Result{Targets: []string{"exec"}}
	defer func() { result.failed(err) }()
	if len(arguments) == 0 {
		return result, errors.New("specify a command after --")
	}
	m, environment, _, err := prepare(root, platform, selected)
	result.Recipe = m.Recipe
	if err != nil {
		return result, err
	}
	mise, err := ensureMise(ctx)
	if err != nil {
		return result, err
	}
	cmd := exec.Command(mise, append([]string{"exec", "--"}, arguments...)...)
	environment = toolchainEnvironment(environment, mise)
	cmd.Dir, cmd.Env, cmd.Stdin, cmd.Stdout, cmd.Stderr = root, environment, in, out, progress
	err = runCommand(ctx, cmd)
	result.Completed = err == nil
	if err != nil {
		result.ExitCode = 1
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() > 0 {
			result.ExitCode = exit.ExitCode()
		}
	}
	return result, err
}

// Execute uses the same resolved recipe, inputs and toolchain locally and in CI.
func Execute(ctx context.Context, root, platform string, targets []string, mode string, selected []string, in io.Reader, progress io.Writer) (Result, error) {
	return execute(ctx, root, platform, targets, mode, selected, in, progress, ensureMise)
}

func execute(ctx context.Context, root, platform string, targets []string, mode string, selected []string, in io.Reader, progress io.Writer, toolchain func(context.Context) (string, error)) (result Result, err error) {
	result = Result{Targets: targets}
	defer func() { result.failed(err) }()
	m, environment, runtimeRoot, err := prepare(root, platform, selected)
	result.Recipe = m.Recipe
	if err != nil {
		result.ExitCode = 1
		return result, err
	}
	if len(selected) > 0 {
		for _, target := range targets {
			if m.Tasks[target] == nil {
				return result, errors.New("tool selection is available only for named tasks; verification stages require the complete declared toolchain")
			}
		}
	}
	for _, target := range targets {
		if target == "check" || target == "lint" {
			if _, err = Validate(root, platform); err != nil {
				result.ExitCode = 1
				return result, err
			}
			break
		}
	}
	for _, target := range targets {
		if !knownStage(target) && target != "test" && target != "check" && target != "validate" && m.Tasks[target] == nil {
			return result, fmt.Errorf("unknown project target %q", target)
		}
	}
	if len(targets) == 1 && targets[0] == "dev" {
		profile := map[string]any{"version": 1, "repository": m.Repository, "default_mode": "local"}
		for k, v := range m.Development {
			profile[k] = v
		}
		// Credential-free recipes need no GitHub identity or handoff.
		if m.Repository == "" {
			profile["repository"] = "local/project"
		}
		path := filepath.Join(root, ".artifacts", "komizo", "development.json")
		if err = writeJSON(path, profile); err != nil {
			return result, err
		}
		environment, err = devenv.Prepare(ctx, path, mode, environment)
		if err != nil {
			return result, err
		}
		// Reapply only the verified runtime bindings after dropping inherited credentials.
		trusted := map[string]string{}
		for _, entry := range environmentForRuntime(root, runtimeRoot) {
			k, v, _ := strings.Cut(entry, "=")
			trusted[k] = v
		}
		environment = setEnv(environment, trusted)
	}
	actualTargets := append([]string{}, targets...)
	if len(targets) == 1 && targets[0] == "check" {
		actualTargets = []string{"install", "check"}
	}
	args := append([]string{"exec", "--", "python3", filepath.Join(runtimeRoot, "helpers", "contract.py"), "--manifest", filepath.Join(root, ".artifacts", "komizo", "contract.json")}, actualTargets...)
	mise, err := toolchain(ctx)
	if err != nil {
		return result, err
	}
	cmd := exec.Command(mise, args...)
	environment = toolchainEnvironment(environment, mise)
	cmd.Dir, cmd.Env, cmd.Stdin, cmd.Stdout, cmd.Stderr = root, environment, in, progress, progress
	err = runCommand(ctx, cmd)
	result.Completed = err == nil
	if err != nil {
		result.ExitCode = 1
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() > 0 {
			result.ExitCode = exit.ExitCode()
		}
		result.NextAction = append([]string{"komizo", "run", "--directory", root}, targets...)
		result.Receipt = ".artifacts/contract/failure.json"
	} else {
		result.Receipt = ".artifacts/contract"
	}
	return result, err
}

func environmentForRuntime(root, runtimeRoot string) []string {
	executable, _ := os.Executable()
	return []string{"KOMIZO_EXECUTABLE=" + executable, "KOMIZO_DEV_PROJECT=komizo-" + digest([]byte(filepath.Clean(root)))[:16], "CICD_ENGINEERING=" + runtimeRoot, "KOMIZO_PROJECT=" + filepath.Join(root, ManifestName),
		"KOMIZO_CONTRACT=" + filepath.Join(root, ".artifacts", "komizo", "contract.json"),
		"KOMIZO_TOOLCHAIN=" + filepath.Join(root, ".komizo.mise.toml"), "PYTHONDONTWRITEBYTECODE=1", "GOTOOLCHAIN=local",
		"MISE_OVERRIDE_CONFIG_FILENAMES=.komizo.mise.toml", "MISE_TRUSTED_CONFIG_PATHS=" + root}
}

func toolchainEnvironment(environment []string, mise string) []string {
	for _, entry := range environment {
		if value, ok := strings.CutPrefix(entry, "PATH="); ok {
			return setEnv(environment, map[string]string{"PATH": filepath.Dir(mise) + string(os.PathListSeparator) + value})
		}
	}
	return setEnv(environment, map[string]string{"PATH": filepath.Dir(mise)})
}

func (result *Result) failed(err error) {
	if err == nil {
		return
	}
	result.Completed = false
	if result.ExitCode <= 0 {
		result.ExitCode = 1
	}
	if errors.Is(err, context.DeadlineExceeded) {
		result.ExitCode = 124
	}
	if errors.Is(err, context.Canceled) {
		result.ExitCode = 130
	}
}
