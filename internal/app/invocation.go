package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// A CLI invocation is serial. Handlers emit typed values and use explicit
// streams; no handler replaces or reads back process-global stdout/stderr.
// Direct library calls retain their ordinary terminal streams.
type invocation struct {
	ctx              context.Context
	input            io.Reader
	output, progress io.Writer
	machine          bool
	data             json.RawMessage
	text             boundedOutput
}

var invocationMutex sync.Mutex
var activeInvocation *invocation

func commandContext() context.Context {
	if activeInvocation != nil {
		return activeInvocation.ctx
	}
	return context.Background()
}
func commandInput() io.Reader {
	if activeInvocation != nil {
		return activeInvocation.input
	}
	return os.Stdin
}
func commandOutput() io.Writer {
	if activeInvocation != nil {
		if activeInvocation.machine {
			return &activeInvocation.text
		}
		return activeInvocation.output
	}
	return os.Stdout
}
func commandProgress() io.Writer {
	if activeInvocation != nil {
		return activeInvocation.progress
	}
	return os.Stderr
}
func commandFlags() io.Writer {
	if activeInvocation != nil && activeInvocation.machine {
		return commandOutput()
	}
	return commandProgress()
}
func commandExec(name string, args ...string) *exec.Cmd {
	c := exec.CommandContext(commandContext(), name, args...)
	c.WaitDelay = 2 * time.Second
	return c
}
func emitResult(value any) error {
	if activeInvocation == nil || !activeInvocation.machine {
		return json.NewEncoder(commandOutput()).Encode(value)
	}
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(body) > 4<<20 {
		return errors.New("structured result exceeds 4 MiB")
	}
	if activeInvocation.data != nil {
		return errors.New("command emitted more than one structured result")
	}
	activeInvocation.data = body
	return nil
}
func emitProtocol(body []byte) error {
	if len(body) > 4<<20 {
		return errors.New("protocol response exceeds 4 MiB")
	}
	if err := rejectDuplicateMembers(body); err != nil {
		return err
	}
	var value any
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	if err := d.Decode(&value); err != nil {
		return errors.New("invalid structured protocol response")
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("multiple structured protocol responses")
	}
	return emitResult(value)
}

// External bundled programs have a JSON protocol. Decode once at that process
// boundary, without executing or parsing a second instance of this CLI.
func runProtocolCommand(c *exec.Cmd, args []string) error {
	if !machineMode() {
		c.Stdout, c.Stderr = commandOutput(), commandProgress()
		return c.Run()
	}
	var output boundedOutput
	output.remaining = 4 << 20
	c.Stdout, c.Stderr = &output, commandProgress()
	err := c.Run()
	if output.truncated {
		return errors.New("helper response exceeds 4 MiB")
	}
	if machineHelp(args) && err == nil {
		_, _ = commandOutput().Write(output.Bytes())
		return flag.ErrHelp
	}
	if len(bytes.TrimSpace(output.Bytes())) > 0 {
		if decodeErr := emitProtocol(output.Bytes()); decodeErr != nil && err == nil {
			return decodeErr
		}
	}
	return err
}
