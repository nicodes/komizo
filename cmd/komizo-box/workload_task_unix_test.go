//go:build unix

package main

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"testing"
	"time"
)

func TestNamedTaskDeadlineKillsItsOwnedProcessGroup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	command := exec.CommandContext(ctx, "/bin/sh", "-c", "sleep 60 & wait")
	if err := workloadTaskProcessGroup(command); err != nil {
		t.Fatal(err)
	}
	command.WaitDelay = 2 * time.Second
	began := time.Now()
	if err := command.Run(); err == nil {
		t.Fatal("stalled task passed")
	}
	if time.Since(began) > 3*time.Second {
		t.Fatal("owned task process group exceeded deadline")
	}
}

func TestNamedTaskStalledProofHasAnIndependentDeadline(t *testing.T) {
	read, write := io.Pipe()
	defer read.Close()
	defer write.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	began := time.Now()
	if _, err := readTaskProof(ctx, bufio.NewReaderSize(read, (128<<10)+2)); err == nil {
		t.Fatal("stalled proof accepted")
	}
	if time.Since(began) > time.Second {
		t.Fatal("proof framing exceeded its deadline")
	}
}
