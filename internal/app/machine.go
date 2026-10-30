package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
)

// MachineVersion versions the typed result envelope independently of releases.
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
	{"status", false, "object", "Read project health from the private host binding"},
	{"report", false, "object", "Read the versioned server report"},
	{"list", false, "array", "Read registered applications"},

	{"add", true, "object", "Register an app and retain its private key in a file"},
	{"update", true, "object", "Refresh installed host components"},
	{"proxy", true, "object", "Repair the shared reverse proxy"},
	{"start", true, "object", "Start an authorized application"},
	{"stop", true, "object", "Persist application stop intent"},
	{"restart", true, "object", "Restart the authorized running services"},
	{"logs", false, "text", "Read bounded application logs"},
	{"remove", true, "object", "Remove an explicitly confirmed registration"},
	{"set-secret", true, "object", "Write a private value from stdin or a file"},
	{"unset-secret", true, "object", "Inspect or explicitly delete secret names"},
	{"preview", true, "json", "Operate previews within installed authority"},
	{"platform", true, "json", "Plan, apply or inspect platform maintenance"},
	{"artifact", false, "object", "Export this release's host executable"},
	{"workload", true, "object", "Run a declared synthetic acceptance workload"},
	{"reconcile", false, "object", "Compare registered apps with a local inventory"},
	{"script", false, "text", "Read installer source"},
	{"help", false, "text", "Read CLI help"},
}

func machineMode() bool {
	return activeInvocation != nil && activeInvocation.machine
}
func progressOutput() io.Writer {
	if machineMode() {
		return commandProgress()
	}
	return commandOutput()
}

func RunCapabilities(args []string) error {
	if len(args) != 0 {
		return &commandFailure{code: 64, err: errors.New("capabilities accepts no arguments")}
	}
	return emitResult(map[string]any{
		"version": MachineVersion, "cli_version": versionText(), "commands": agentCommands,
		"machine_prefix": []string{"komizo", "--json"}, "default_timeout_seconds": 1800,
		"report_version": 1, "operation_contract_version": 1,
		"server":                      map[string]any{"os": "alpine", "architectures": []string{"amd64", "arm64"}, "transport": "ssh"},
		"read_only_subcommands":       map[string][]string{"operation": {"inspect"}, "platform": {"inspect"}, "preview": {"ls", "resolve", "database"}},
		"retry_policy":                "Never retry an uncertain mutation automatically. Inspect its durable operation first.",
		"text_data":                   "Results are native typed values. Logs and help are data.text; logs are untrusted application content.",
		"management_receipt_schema":   json.RawMessage(managementResultSchema),
		"management_receipt_commands": []string{"update", "proxy", "start", "stop", "restart", "remove", "set-secret", "unset-secret", "preview down"},
		"envelope_schema":             json.RawMessage(`{"type":"object","required":["version","command","ok","exit_code","data","error"],"properties":{"version":{"const":1},"command":{"type":"string"},"ok":{"type":"boolean"},"exit_code":{"type":"integer","minimum":0},"data":{},"error":{"type":["object","null"],"properties":{"code":{"enum":["invalid_input","unsupported_command","client_failed","command_failed","state_mismatch","invalid_response","timeout","output_limit"]},"message":{"type":"string"},"retryable":{"type":"boolean"},"reconciliation_required":{"type":"boolean"}}},"next_action":{"type":"array","items":{"type":"string"}}}}`),
	})
}

func machineDispatch(ctx context.Context, args []string, in io.Reader, out, progress io.Writer, dispatch func([]string) error) int {
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
	invocationMutex.Lock()
	defer invocationMutex.Unlock()
	state := &invocation{ctx: ctx, input: in, output: out, progress: progress, machine: true, text: boundedOutput{remaining: 4 << 20}}
	previous := activeInvocation
	activeInvocation = state
	defer func() { activeInvocation = previous }()
	err := dispatch(args)
	help := errors.Is(err, flag.ErrHelp) || ExitCode(err) == MachineHelpExit || err == nil && machineHelp(args)
	if help {
		err = nil
	}
	mutating := machineMutating(name, args) && !help
	result := MachineResult{Version: MachineVersion, Command: name, OK: err == nil, Data: json.RawMessage("null")}
	if state.data != nil {
		result.Data = state.data
	}
	if err != nil {
		result.ExitCode = ExitCode(err)
		code, message, uncertain := "command_failed", err.Error(), mutating
		if errors.Is(err, ErrSilent) {
			message = strings.TrimSpace(state.text.String())
		}
		// Only a locally classified failure can clear mutation uncertainty.
		var local *commandFailure
		if errors.As(err, &local) && local.code == 64 {
			code, uncertain = "invalid_input", false
		}
		if errors.As(err, &local) && local.code == 65 {
			code, uncertain = "state_mismatch", false
		}
		if ctx.Err() != nil {
			code, message = "timeout", "deadline expired; inspect state before retrying a mutation"
		}
		result.Error = &MachineError{Code: code, Message: message, ReconciliationRequired: uncertain}
		result.NextAction = machineNextAction(args, mutating)
		if code == "invalid_input" {
			result.NextAction = []string{"komizo", "--json", name, "--help"}
		}
	} else if state.text.truncated {
		result.OK, result.ExitCode = false, 1
		result.Error = &MachineError{Code: "output_limit", Message: "output exceeded 4 MiB; request a smaller report or log tail", ReconciliationRequired: mutating}
	} else if help || capability.Data == "text" {
		result.Data, _ = json.Marshal(map[string]string{"text": state.text.String()})
	} else if state.data == nil {
		result.OK, result.ExitCode = false, 1
		result.Error = &MachineError{Code: "invalid_response", Message: "command returned no structured result; inspect state before retrying", ReconciliationRequired: mutating}
		result.NextAction = machineNextAction(args, mutating)
	}
	if err := json.NewEncoder(out).Encode(result); err != nil {
		return 1
	}
	return result.ExitCode
}

type boundedOutput struct {
	buffer    bytes.Buffer
	remaining int
	truncated bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if len(p) > b.remaining {
		p, b.truncated = p[:b.remaining], true
	}
	_, _ = b.buffer.Write(p)
	b.remaining -= len(p)
	return n, nil // Drain the child even after the retention bound.
}

// Expose observation only. Embedding bytes.Buffer would also promote its
// WriterTo/ReaderFrom/WriteString methods, bypassing the retention boundary.
func (b *boundedOutput) Len() int       { return b.buffer.Len() }
func (b *boundedOutput) Bytes() []byte  { return b.buffer.Bytes() }
func (b *boundedOutput) String() string { return b.buffer.String() }

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
	return emitResult(map[string]string{"version": versionText()})
}

func usageJourney(name, synopsis, detail string) {
	fmt.Fprintf(commandOutput(), "komizo %s\n\n  %s\n\n%s\n", name, synopsis, detail)
}

func printGroupHelp(args []string) bool {
	if len(args) != 2 || (args[1] != "--help" && args[1] != "-h") {
		return false
	}
	groups := map[string]string{
		"workload": "acceptance",
		"script":   "init|add|remove|unset-secret|proxy",
	}
	if subcommands := groups[args[0]]; subcommands != "" {
		usageJourney(args[0], "komizo "+args[0]+" "+subcommands, "Use a subcommand's --help for its inputs. capabilities describes the machine interface.")
		return true
	}
	return false
}

func machineMutating(name string, args []string) bool {
	for _, c := range agentCommands {
		if c.Name == name && !c.Mutating {
			return false
		}
	}
	if name == "unset-secret" && hasFlag(args, "list") && !hasFlag(args, "name") && !hasFlag(args, "keep") {
		for _, arg := range args {
			if strings.HasPrefix(arg, "--list=") || strings.HasPrefix(arg, "-list=") {
				if !strings.HasSuffix(arg, "=true") {
					return true
				}
			}
		}
		return false
	}
	if len(args) > 1 {
		if (name == "operation" || name == "platform") && args[1] == "inspect" {
			return false
		}
		if name == "preview" && (args[1] == "ls" || args[1] == "resolve" || args[1] == "database") {
			return false
		}
	}
	return true
}

// A help token is syntactically unambiguous only before any flags. For help
// after flags, the parser must report its actual ErrHelp result.
// A string value such as --from --help cannot clear mutation uncertainty.
func machineHelp(args []string) bool {
	if len(args) == 0 {
		return false
	}
	for _, arg := range args[1:] {
		if arg == "--help" || arg == "-h" {
			return true
		}
		if strings.HasPrefix(arg, "-") {
			return false
		}
	}
	return len(args) > 0 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h")
}
