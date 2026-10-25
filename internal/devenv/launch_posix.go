//go:build linux || darwin

package devenv

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
	"unsafe"
)

const shutdownGrace = 5 * time.Second

func launch(args []string, values map[string]string) error {
	return launchWithGrace(args, values, shutdownGrace)
}

func launchWithGrace(args []string, values map[string]string, grace time.Duration) error {
	return launchEnvironment(args, commandEnvironment(os.Environ(), values), grace)
}

func launchEnvironment(args []string, environment []string, grace time.Duration) error {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = environment
	return RunCommand(context.Background(), cmd, grace)
}

// RunCommand owns the terminal and descendants for one local command.
func RunCommand(ctx context.Context, cmd *exec.Cmd, grace time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if cmd.Stdin == nil {
		cmd.Stdin = os.Stdin
	}
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}
	cmd.WaitDelay = grace
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Give an interactive child the foreground terminal, then restore it before
	// returning. Otherwise its new process group would stop on terminal input.
	fd := os.Stdin.Fd()
	if f, ok := cmd.Stdin.(*os.File); ok {
		fd = f.Fd()
	}
	foreground, terminalErr := terminalGroup(fd, syscall.TIOCGPGRP, 0)
	if terminalErr == nil {
		cmd.SysProcAttr.Foreground = true
		cmd.SysProcAttr.Ctty = int(fd)
		signal.Ignore(syscall.SIGTTOU)
		defer signal.Reset(syscall.SIGTTOU)
		defer func() { _, _ = terminalGroup(fd, syscall.TIOCSPGRP, foreground) }()
	}
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	if err := cmd.Start(); err != nil {
		return err
	}
	group := cmd.Process.Pid
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	var deadline time.Time
	var timer *time.Timer
	var expired <-chan time.Time
	ctxDone := ctx.Done()
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		select {
		case err := <-wait:
			if deadline.IsZero() {
				deadline = time.Now().Add(grace)
			}
			cleanupGroup(group, deadline, signals)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		case <-ctxDone:
			_ = syscall.Kill(-group, syscall.SIGTERM)
			deadline = time.Now().Add(grace)
			timer = time.NewTimer(grace)
			expired = timer.C
			ctxDone = nil
		case sig := <-signals:
			if deadline.IsZero() {
				_ = syscall.Kill(-group, sig.(syscall.Signal))
				deadline = time.Now().Add(grace)
				timer = time.NewTimer(grace)
				expired = timer.C
			} else {
				_ = syscall.Kill(-group, syscall.SIGKILL)
				deadline = time.Now()
			}
		case <-expired:
			_ = syscall.Kill(-group, syscall.SIGKILL)
			expired = nil
		}
	}
}

func cleanupGroup(group int, deadline time.Time, signals <-chan os.Signal) {
	_ = syscall.Kill(-group, syscall.SIGTERM)
	for {
		if errors.Is(syscall.Kill(-group, 0), syscall.ESRCH) {
			return
		}
		if !time.Now().Before(deadline) {
			_ = syscall.Kill(-group, syscall.SIGKILL)
			return
		}
		select {
		case <-signals:
			_ = syscall.Kill(-group, syscall.SIGKILL)
			return
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func terminalGroup(fd uintptr, operation uintptr, group int32) (int32, error) {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, operation, uintptr(unsafe.Pointer(&group)))
	if errno != 0 {
		return 0, errno
	}
	return group, nil
}
