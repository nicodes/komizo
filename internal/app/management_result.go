package app

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
)

// A receipt acknowledges successful command completion. It does not claim
// application readiness, a data restore, or an independently observed state.
type managementResult struct {
	Version      int            `json:"version"`
	Action       string         `json:"action"`
	Host         string         `json:"host"`
	App          string         `json:"app,omitempty"`
	Details      map[string]any `json:"details"`
	Acknowledged bool           `json:"acknowledged"`
}

func managementReceipt(action string, tgt target, app string, details map[string]any) error {
	if !machineMode() {
		return nil
	}
	if details == nil {
		details = map[string]any{}
	}
	return json.NewEncoder(os.Stdout).Encode(managementResult{Version: 1, Action: action, Host: tgt.addr(), App: app, Details: details, Acknowledged: true})
}

const MachineHelpExit = 66

type commandFailure struct {
	code int
	err  error
}

func (e *commandFailure) Error() string { return e.err.Error() }
func (e *commandFailure) Unwrap() error { return e.err }

// ExitCode carries only locally classified failures across the subprocess
// boundary. Remote output cannot forge validation success or clear uncertainty.
func ExitCode(err error) int {
	var failure *commandFailure
	if errors.As(err, &failure) {
		return failure.code
	}
	return 1
}

type inputBoundary struct {
	err      *error
	complete bool
}

func localInput(err *error) *inputBoundary { return &inputBoundary{err: err} }
func (b *inputBoundary) finish() {
	if !b.complete && *b.err != nil && !errors.Is(*b.err, flag.ErrHelp) {
		*b.err = &commandFailure{code: 64, err: *b.err}
	}
}

const managementResultSchema = `{"type":"object","required":["version","action","host","acknowledged","details"],"properties":{"version":{"const":1},"action":{"type":"string"},"host":{"type":"string"},"app":{"type":"string"},"acknowledged":{"const":true},"details":{"type":"object"}},"additionalProperties":false}`
