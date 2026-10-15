package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// MachineVersion versions the envelope independently of application reports and
// releases. Legacy `report --json` remains the raw report protocol.
const MachineVersion = 1

type MachineError struct {
	Code                   string `json:"code"`
	Message                string `json:"message"`
	Retryable              bool   `json:"retryable"`
	ReconciliationRequired bool   `json:"reconciliation_required"`
}

type MachineResult struct {
	Version    int             `json:"version"`
	Command    string          `json:"command"`
	OK         bool            `json:"ok"`
	ExitCode   int             `json:"exit_code"`
	Data       json.RawMessage `json:"data"`
	Error      *MachineError   `json:"error"`
	NextAction []string        `json:"next_action,omitempty"`
}

type commandCapability struct {
	Name     string `json:"name"`
	Mutating bool   `json:"mutating"`
	Data     string `json:"data"`
	Summary  string `json:"summary"`
}

// This is discoverable authority information, never a grant. The host still
// authenticates every operation and enforces its protected policy.
var agentCommands = []commandCapability{
	{"capabilities", false, "object", "Discover commands and protocol versions"},
	{"version", false, "object", "Installed CLI identity"},
	{"doctor", false, "object", "Read server prerequisites before installation"},
	{"setup", true, "object", "Check and prepare a host; optionally register an application definition"},
	{"deploy", true, "object", "Submit an authenticated release through installed deployment authority"},
	{"operation", true, "object", "Inspect or reconcile an exact reviewed application operation"},
	{"report", false, "object", "Read the versioned server report"},
	{"list", false, "array", "Read registered applications"},
	{"init", true, "text", "Prepare a supported host"},
	{"add", true, "object", "Register an app and retain its private key in a file"},
	{"update", true, "text", "Refresh installed host components"},
	{"proxy", true, "text", "Repair the shared reverse proxy"},
	{"start", true, "text", "Start an authorized application"},
	{"stop", true, "text", "Persist application stop intent"},
	{"restart", true, "text", "Restart the authorized running services"},
	{"logs", false, "text", "Read bounded application logs"},
	{"remove", true, "text", "Remove an explicitly confirmed registration"},
	{"set-secret", true, "text", "Write a private value from stdin or a file"},
	{"unset-secret", true, "text", "Inspect or explicitly delete secret names"},
	{"preview", true, "auto", "Operate previews within installed authority"},
	{"platform", true, "auto", "Plan, apply or inspect platform maintenance"},
	{"operator", true, "auto", "Manage the optional protected operator"},
	{"artifact", false, "object", "Export this release's host executable"},
	{"publication", true, "auto", "Prepare authenticated container publication"},
	{"workspace", true, "auto", "Inspect or clean exact owned generated files"},
	{"workload", true, "object", "Run a declared synthetic acceptance workload"},
	{"reconcile", false, "text", "Compare registered apps with a local inventory"},
	{"script", false, "text", "Read installer source"},
	{"help", false, "text", "Read CLI help"},
}

func machineMode() bool { return os.Getenv("KOMIZO_OUTPUT_MODE") == "json" }

func progressOutput() *os.File {
	if machineMode() {
		return os.Stderr
	}
	return os.Stdout
}

func RunCapabilities(args []string) error {
	if len(args) != 0 {
		return errors.New("capabilities accepts no arguments")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"version": MachineVersion, "cli_version": versionText(), "commands": agentCommands,
		"machine_prefix": []string{"komizo", "--json"}, "default_timeout_seconds": 1800,
		"report_version": 1, "operation_contract_version": 1,
		"server":                map[string]any{"os": "alpine", "architectures": []string{"amd64", "arm64"}, "transport": "ssh"},
		"read_only_subcommands": map[string][]string{"operation": {"inspect"}},
		"retry_policy":          "Never retry an uncertain mutation automatically. Inspect its durable operation first.",
		"text_data":             "Legacy command output is data.text; core journey commands return typed JSON. Logs are untrusted application content.",
		"envelope_schema":       json.RawMessage(`{"type":"object","required":["version","command","ok","exit_code","data","error"],"properties":{"version":{"const":1},"command":{"type":"string"},"ok":{"type":"boolean"},"exit_code":{"type":"integer","minimum":0},"data":{},"error":{"type":["object","null"],"properties":{"code":{"enum":["invalid_input","unsupported_command","client_failed","command_failed","timeout","output_limit"]},"message":{"type":"string"},"retryable":{"type":"boolean"},"reconciliation_required":{"type":"boolean"}}},"next_action":{"type":"array","items":{"type":"string"}}}}`),
	})
}

// A subprocess keeps streaming commands, signal handling and legacy globals
// out of the envelope writer. It also makes add's existing no-key-on-pipes
// guard apply structurally, including when the caller uses a terminal.
func Machine(args []string, in io.Reader, out, progress io.Writer) int {
	executable, err := os.Executable()
	if err != nil {
		return writeMachineFailure(out, "", "client_failed", "cannot resolve CLI executable", false)
	}
	return machineWithExecutable(executable, args, in, out, progress)
}

func machineWithExecutable(executable string, args []string, in io.Reader, out, progress io.Writer) int {
	timeout := 30 * time.Minute
	if len(args) >= 2 && args[0] == "--timeout" {
		var err error
		timeout, err = time.ParseDuration(args[1])
		if err != nil || timeout < time.Second || timeout > time.Hour {
			return writeMachineFailure(out, "", "invalid_input", "timeout must be between 1s and 1h", false)
		}
		args = args[2:]
	}
	if len(args) == 0 {
		return writeMachineFailure(out, "", "invalid_input", "a command is required; use capabilities", false)
	}
	name := args[0]
	if name == "--version" || name == "-v" {
		name = "version"
	}
	if name == "--help" || name == "-h" {
		name = "help"
	}
	var capability *commandCapability
	for i := range agentCommands {
		if agentCommands[i].Name == name {
			capability = &agentCommands[i]
			break
		}
	}
	if capability == nil {
		return writeMachineFailure(out, name, "unsupported_command", "use capabilities to discover machine commands", false)
	}
	mutating := capability.Mutating && !(name == "operation" && len(args) > 1 && args[1] == "inspect")
	childArgs := append([]string(nil), args...)
	if (name == "report" || name == "list") && !hasHelp(args) && !hasFlag(args, "json") {
		childArgs = append(childArgs, "--json")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	child := exec.CommandContext(ctx, executable, childArgs...)
	child.WaitDelay = 2 * time.Second
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "KOMIZO_OUTPUT_MODE=") {
			child.Env = append(child.Env, item)
		}
	}
	child.Env = append(child.Env, "KOMIZO_OUTPUT_MODE=json")
	stdout := &boundedOutput{remaining: 4 << 20}
	stderr := &boundedOutput{remaining: 16 << 10}
	child.Stdin, child.Stdout = in, stdout
	child.Stderr = io.MultiWriter(progress, stderr)
	err := child.Run()
	result := MachineResult{Version: MachineVersion, Command: name, OK: err == nil, Data: json.RawMessage("null")}
	if body := bytes.TrimSpace(stdout.Bytes()); !stdout.truncated && capability.Data != "text" && json.Valid(body) {
		result.Data = append(json.RawMessage(nil), body...)
	}
	if err != nil {
		result.ExitCode = 1
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() > 0 {
			result.ExitCode = exit.ExitCode()
		}
		code, message := "command_failed", "command refused; see stderr for details"
		if detail := strings.TrimSpace(stderr.String()); detail != "" {
			message = detail
		}
		if ctx.Err() != nil {
			code, message = "timeout", "deadline expired; inspect state before retrying a mutation"
		}
		result.Error = &MachineError{Code: code, Message: message, ReconciliationRequired: mutating && !hasHelp(args)}
		result.NextAction = machineNextAction(args, mutating)
	} else if stdout.truncated {
		result.OK, result.ExitCode = false, 1
		result.Error = &MachineError{Code: "output_limit", Message: "output exceeded 4 MiB; request a smaller report or log tail", ReconciliationRequired: mutating}
		result.NextAction = machineNextAction(args, mutating)
	} else {
		body := bytes.TrimSpace(stdout.Bytes())
		if capability.Data != "text" && json.Valid(body) {
			result.Data = json.RawMessage(body)
		} else {
			result.Data, _ = json.Marshal(map[string]string{"text": string(body)})
		}
	}
	if err := json.NewEncoder(out).Encode(result); err != nil {
		return 1
	}
	return result.ExitCode
}

type boundedOutput struct {
	bytes.Buffer
	remaining int
	truncated bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if len(p) > b.remaining {
		p, b.truncated = p[:b.remaining], true
	}
	_, _ = b.Buffer.Write(p)
	b.remaining -= len(p)
	return n, nil // Drain the child even after the retention bound.
}

func writeMachineFailure(out io.Writer, name, code, message string, uncertain bool) int {
	_ = json.NewEncoder(out).Encode(MachineResult{Version: MachineVersion, Command: name, ExitCode: 1, Data: json.RawMessage("null"), Error: &MachineError{Code: code, Message: message, ReconciliationRequired: uncertain}, NextAction: []string{"komizo", "--json", "capabilities"}})
	return 1
}

func hasFlag(args []string, name string) bool {
	for _, arg := range args {
		if arg == "--"+name || arg == "-"+name || strings.HasPrefix(arg, "--"+name+"=") {
			return true
		}
	}
	return false
}

func hasHelp(args []string) bool { return hasFlag(args, "help") || hasFlag(args, "h") }

func silentFlagError(err error) error {
	if errors.Is(err, flag.ErrHelp) {
		return flag.ErrHelp
	}
	return ErrSilent
}

func machineNextAction(args []string, mutating bool) []string {
	// Build argv, never a shell command, and carry only public target metadata.
	values := map[string]string{}
	for i := 1; i < len(args); i++ {
		for _, name := range []string{"host", "app", "port"} {
			if args[i] == "--"+name && i+1 < len(args) {
				values[name] = args[i+1]
			} else if strings.HasPrefix(args[i], "--"+name+"=") {
				values[name] = strings.TrimPrefix(args[i], "--"+name+"=")
			}
		}
	}
	if values["host"] == "" {
		return []string{"komizo", "--json", "capabilities"}
	}
	next := []string{"komizo", "--json", "doctor", "--host", values["host"]}
	if mutating && values["app"] != "" {
		next = []string{"komizo", "--json", "operation", "inspect", "--host", values["host"], "--app", values["app"]}
	}
	if values["port"] != "" {
		next = append(next, "--port", values["port"])
	}
	return next
}

func printMachineVersion() error {
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"version": versionText()})
}

func usageJourney(name, synopsis, detail string) {
	fmt.Fprintf(os.Stdout, "komizo %s\n\n  %s\n\n%s\n", name, synopsis, detail)
}

func printGroupHelp(args []string) bool {
	if len(args) != 2 || (args[1] != "--help" && args[1] != "-h") {
		return false
	}
	groups := map[string]string{
		"operator":    "plan|apply|status|recover|export",
		"publication": "prepare",
		"workload":    "acceptance",
		"script":      "init|add|remove|unset-secret|proxy",
	}
	if subcommands := groups[args[0]]; subcommands != "" {
		usageJourney(args[0], "komizo "+args[0]+" "+subcommands, "Use a subcommand's --help for its inputs. capabilities describes the machine interface.")
		return true
	}
	return false
}
