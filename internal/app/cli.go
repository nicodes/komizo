package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// CLI is the single process entry point for deployment and host commands.
func CLI(args []string, in io.Reader, out, progress io.Writer) int {
	machine := false
	timeout := 30 * time.Minute
	for len(args) > 0 {
		switch args[0] {
		case "--json":
			machine = true
			args = args[1:]
		case "--timeout":
			var err error
			if len(args) < 2 {
				err = errors.New("--timeout requires a duration")
			} else {
				timeout, err = time.ParseDuration(args[1])
			}
			if err != nil || timeout < time.Second || timeout > time.Hour {
				if machine {
					return writeMachineFailure(out, "", "invalid_input", "timeout must be between 1s and 1h", false)
				}
				fmt.Fprintln(progress, "error: timeout must be between 1s and 1h")
				return 1
			}
			args = args[2:]
		default:
			goto parsed
		}
	}
parsed:
	baseCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(baseCtx, timeout)
	defer cancel()
	if machine {
		return machineDispatch(ctx, args, in, out, progress, Main)
	}
	invocationMutex.Lock()
	defer invocationMutex.Unlock()
	previous := activeInvocation
	activeInvocation = &invocation{ctx: ctx, input: in, output: out, progress: progress}
	defer func() { activeInvocation = previous }()
	if err := Main(args); err != nil {
		if !errors.Is(err, ErrSilent) {
			fmt.Fprintln(progress, "error:", err)
		}
		return ExitCode(err)
	}
	return 0
}
