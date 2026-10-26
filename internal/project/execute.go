package project

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/nicodes/komizo/internal/devenv"
)

// Result is shared by the human and machine presentation layers.
type Result struct {
	Recipe                 string            `json:"recipe"`
	Targets                []string          `json:"targets,omitempty"`
	Completed              bool              `json:"completed"`
	ReconciliationRequired bool              `json:"reconciliation_required"`
	ExitCode               int               `json:"exit_code"`
	Receipt                string            `json:"receipt,omitempty"`
	NextAction             []string          `json:"next_action,omitempty"`
	Selection              *VerificationPlan `json:"selection,omitempty"`
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
	contractBytes, _ := json.Marshal(contract)
	contractPath := filepath.Join(output, "contract-"+digest(contractBytes)[:16]+".json")
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
	}
	misePath = filepath.Join(root, ".komizo.mise-"+digest([]byte(config))[:16]+".toml")
	if err = atomicFile(misePath, []byte(config), 0600); err != nil {
		return m, nil, "", err
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
	if os.Getenv("MISE_GITHUB_TOKEN") == "" && os.Getenv("GITHUB_API_TOKEN") == "" && os.Getenv("GITHUB_TOKEN") == "" && os.Getenv("GH_TOKEN") != "" {
		values["MISE_GITHUB_TOKEN"] = os.Getenv("GH_TOKEN")
	}
	values["KOMIZO_DEV_PROJECT"] = "komizo-" + digest([]byte(filepath.Clean(root)))[:16]
	values["PATH"] = filepath.Dir(executable) + string(os.PathListSeparator) + os.Getenv("PATH")
	if app := m.Release["project"]; app != "" {
		slugs, _ := json.Marshal([]string{app})
		values["BACKUP_ALLOWED_SLUGS"] = string(slugs)
	}
	for name, value := range m.Validation {
		if name != "workflow" {
			return m, nil, "", fmt.Errorf("unknown validation declaration %q", name)
		}
		path := filepath.Join(output, name+".json")
		if err = atomicFile(path, value, 0o600); err != nil {
			return m, nil, "", err
		}
		switch name {
		case "workflow":
			values["KOMIZO_WORKFLOW_POLICY"] = path
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
	result.ReconciliationRequired = err != nil
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
	if slices.Contains(targets, "dev") && (len(targets) != 1) {
		return result, errors.New("development must run as its own foreground session")
	}
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
	contractPath := environmentValue(environment, "KOMIZO_CONTRACT")
	misePath := environmentValue(environment, "KOMIZO_TOOLCHAIN")
	development := len(targets) == 1 && targets[0] == "dev"
	if slices.Contains(targets, "clean") {
		release, leaseErr := developmentLease(root)
		if leaseErr != nil {
			return result, leaseErr
		}
		defer release()
	}
	var session, marker, mise string
	if development {
		contract, _ := m.Contract()
		var commands [][]string
		if json.Unmarshal(contract["stages"].(map[string]json.RawMessage)["dev"], &commands) != nil {
			return result, errors.New("this project declares no standalone development process")
		}
		release, leaseErr := developmentLease(root)
		if leaseErr != nil {
			return result, leaseErr
		}
		defer release()
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
		// Install dependencies before obtaining Preview credentials. Tool downloads
		// can use the caller's GitHub identity; application credentials and hooks
		// from the parent environment never reach this setup process.
		installation, installErr := devenv.Prepare(ctx, path, "local", environment)
		if installErr != nil {
			return result, installErr
		}
		trustedInstall := map[string]string{}
		for _, entry := range environmentForRuntime(root, runtimeRoot, contractPath, misePath) {
			key, value, _ := strings.Cut(entry, "=")
			trustedInstall[key] = value
		}
		for _, key := range []string{"GH_TOKEN", "GITHUB_TOKEN", "GITHUB_API_TOKEN", "MISE_GITHUB_TOKEN"} {
			if value := environmentValue(environment, key); value != "" {
				trustedInstall[key] = value
			}
		}
		installation = setEnv(installation, trustedInstall)
		mise, err = toolchain(ctx)
		if err != nil {
			return result, err
		}
		setup := exec.Command(mise, "exec", "--", "python3", filepath.Join(runtimeRoot, "helpers", "contract.py"), "--manifest", contractPath, "install")
		setup.Dir, setup.Env, setup.Stdin, setup.Stdout, setup.Stderr = root, toolchainEnvironment(installation, mise), in, progress, progress
		if err = runCommand(ctx, setup); err != nil {
			result.ReconciliationRequired = true
			result.Receipt = ".artifacts/contract/failure.json"
			var exit *exec.ExitError
			if errors.As(err, &exit) && exit.ExitCode() > 0 {
				result.ExitCode = exit.ExitCode()
			}
			return result, err
		}
		// Revalidate source and regenerate trusted runtime files after package
		// hooks. They cannot silently widen the authorized credential selection.
		current, freshEnvironment, _, prepareErr := prepare(root, platform, selected)
		if prepareErr != nil {
			return result, prepareErr
		}
		originalPolicy, _ := json.Marshal(m)
		currentPolicy, _ := json.Marshal(current)
		if string(originalPolicy) != string(currentPolicy) {
			return result, errors.New("project configuration changed during installation; review it before starting development")
		}
		environment = freshEnvironment
		if err = writeJSON(path, profile); err != nil {
			return result, err
		}
		environment, err = devenv.Prepare(ctx, path, mode, environment)
		if err != nil {
			return result, err
		}
		// Reapply only the verified runtime bindings after dropping inherited credentials.
		trusted := map[string]string{}
		for _, entry := range environmentForRuntime(root, runtimeRoot, contractPath, misePath) {
			k, v, _ := strings.Cut(entry, "=")
			trusted[k] = v
		}
		environment = setEnv(environment, trusted)
	}
	if development {
		nonce := make([]byte, 16)
		if _, err = rand.Read(nonce); err != nil {
			return result, err
		}
		session = hex.EncodeToString(nonce)
		marker = filepath.Join(root, ".artifacts", "komizo", "dev-session-"+session+".json")
		environment = setEnv(environment, map[string]string{"KOMIZO_DEV_SESSION": session, "KOMIZO_DEV_SESSION_FILE": marker})
		defer os.Remove(marker)
	}
	actualTargets := append([]string{}, targets...)
	if len(targets) == 1 && targets[0] == "check" {
		actualTargets = []string{"install", "check"}
	}
	args := append([]string{"exec", "--", "python3", filepath.Join(runtimeRoot, "helpers", "contract.py"), "--manifest", contractPath}, actualTargets...)
	if mise == "" {
		mise, err = toolchain(ctx)
		if err != nil {
			return result, err
		}
	}
	cmd := exec.Command(mise, args...)
	environment = toolchainEnvironment(environment, mise)
	cmd.Dir, cmd.Env, cmd.Stdin, cmd.Stdout, cmd.Stderr = root, environment, in, progress, progress
	if development {
		err = devenv.RunCommand(ctx, cmd, 15*time.Second)
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if cleanupErr := cleanupDevelopment(root, m, environment, mise, session, marker, progress); cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
	} else {
		err = runCommand(ctx, cmd)
	}
	result.Completed = err == nil
	if err != nil {
		result.ExitCode = 1
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() > 0 {
			result.ExitCode = exit.ExitCode()
		}
		result.NextAction = append([]string{"komizo", "run", "--directory", root}, targets...)
		for _, target := range targets {
			if m.Tasks[target] != nil {
				result.ReconciliationRequired = true
				result.NextAction = nil
				break
			}
		}
		result.Receipt = ".artifacts/contract/failure.json"
	} else {
		result.Receipt = ".artifacts/contract"
	}
	return result, err
}

func environmentForRuntime(root, runtimeRoot, contractPath, misePath string) []string {
	executable, _ := os.Executable()
	return []string{"KOMIZO_EXECUTABLE=" + executable, "KOMIZO_DEV_PROJECT=komizo-" + digest([]byte(filepath.Clean(root)))[:16], "CICD_ENGINEERING=" + runtimeRoot, "KOMIZO_PROJECT=" + filepath.Join(root, ManifestName),
		"KOMIZO_CONTRACT=" + contractPath,
		"KOMIZO_TOOLCHAIN=" + misePath, "PYTHONDONTWRITEBYTECODE=1", "GOTOOLCHAIN=local",
		"MISE_OVERRIDE_CONFIG_FILENAMES=" + filepath.Base(misePath), "MISE_TRUSTED_CONFIG_PATHS=" + root}
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

func environmentValue(environment []string, name string) string {
	for _, entry := range environment {
		if value, ok := strings.CutPrefix(entry, name+"="); ok {
			return value
		}
	}
	return ""
}
func cleanupDevelopment(root string, m Manifest, environment []string, mise, session, marker string, progress io.Writer) error {
	info, err := os.Lstat(marker)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1024 {
		return errors.New("cannot establish ownership of the development cleanup")
	}
	body, err := os.ReadFile(marker)
	if err != nil {
		return err
	}
	var receipt struct {
		Version int    `json:"version"`
		Session string `json:"session"`
	}
	if json.Unmarshal(body, &receipt) != nil || receipt.Version != 1 || receipt.Session != session {
		return errors.New("development cleanup ownership changed")
	}
	contract, err := m.Contract()
	if err != nil {
		return err
	}
	raw := contract["stages"].(map[string]json.RawMessage)["stop"]
	var commands [][]string
	if json.Unmarshal(raw, &commands) != nil {
		return nil
	} // Explicitly inapplicable.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, arguments := range commands {
		cmd := exec.Command(mise, append([]string{"exec", "--"}, arguments...)...)
		cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = root, environment, progress, progress
		if err := runCommand(ctx, cmd); err != nil {
			return fmt.Errorf("development cleanup failed: %w", err)
		}
	}
	return nil
}
