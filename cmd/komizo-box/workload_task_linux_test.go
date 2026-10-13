//go:build linux

package main

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestNamedTaskCancellationTerminatesItsChild(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	command := exec.CommandContext(ctx, "/bin/sh", "-c", "sleep 60 & echo $!; wait")
	if err := workloadTaskProcessGroup(command); err != nil {
		t.Fatal(err)
	}
	command.WaitDelay = 2 * time.Second
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = command.Wait() }()
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(output).ReadString('\n'); ready <- line }()
	var child string
	select {
	case line := <-ready:
		pid, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil || pid <= 1 {
			t.Fatal("task did not report its own child")
		}
		child = strconv.Itoa(pid)
	case <-time.After(3 * time.Second):
		t.Fatal("task did not start within its fixture deadline")
	}
	cancel()
	if err := command.Wait(); err == nil {
		t.Fatal("cancelled task succeeded")
	}
	// An orphan may briefly remain as a zombie until PID 1 reaps it. It must
	// never remain a running child after its executor has returned.
	deadline := time.Now().Add(time.Second)
	for {
		body, err := os.ReadFile(filepath.Join("/proc", child, "stat"))
		// procfs can return ESRCH when the task disappears after lookup but
		// before read. Both outcomes prove this owned child has exited.
		if os.IsNotExist(err) || errors.Is(err, syscall.ESRCH) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		end := strings.LastIndex(string(body), ")")
		if end >= 0 && strings.HasPrefix(string(body[end+1:]), " Z ") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("owned child remained running after cancellation")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
