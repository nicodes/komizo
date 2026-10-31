package nativeapi

import (
	"context"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

// Run starts the native API directly. The API owns every HTTP handler and its
// state; this launcher only supervises the executable and forwards termination.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	path, cleanup, err := Prepare()
	if err != nil {
		return err
	}
	defer cleanup()
	argv := append([]string{}, args...)
	argv = append(argv, "--parent-pid", strconv.Itoa(os.Getpid()))
	command := exec.Command(path, argv...)
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = stderr
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	if err := command.Start(); err != nil {
		return err
	}
	cleanup()
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	cancelled := ctx.Done()
	var deadline <-chan time.Time
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		select {
		case err := <-done:
			return err
		case received := <-signals:
			_ = command.Process.Signal(received)
			if timer == nil {
				timer = time.NewTimer(10 * time.Second)
				deadline = timer.C
			}
		case <-cancelled:
			cancelled = nil
			_ = command.Process.Signal(syscall.SIGTERM)
			if timer == nil {
				timer = time.NewTimer(10 * time.Second)
				deadline = timer.C
			}
		case <-deadline:
			_ = command.Process.Kill()
			return <-done
		}
	}
}
