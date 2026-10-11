package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestPrivilegedPayloadDeadlineDoesNotWaitForEOF(t *testing.T) {
	read, write := io.Pipe()
	defer read.Close()
	defer write.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	began := time.Now()
	body, err := readWorkloadInput(ctx, read, 128<<10)
	if body != nil || !errors.Is(err, context.DeadlineExceeded) || time.Since(began) > time.Second {
		t.Fatal("stalled privileged payload exceeded its inherited deadline")
	}
}

func TestPrivilegedPayloadRetainsAnOversizeSentinel(t *testing.T) {
	body, err := readWorkloadInput(context.Background(), strings.NewReader(strings.Repeat("x", 1024)), 64)
	if err != nil || len(body) != 65 {
		t.Fatal("payload size bound lost its refusal sentinel")
	}
}
