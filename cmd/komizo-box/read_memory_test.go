package main

import (
	"runtime/debug"
	"testing"
)

func TestReadMemoryDefaultPreservesOperatorOverride(t *testing.T) {
	before := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(before) })
	t.Setenv("GOMEMLIMIT", "")
	setReadMemoryDefault()
	if got := debug.SetMemoryLimit(-1); got != 64<<20 {
		t.Fatalf("default limit: %d", got)
	}
	debug.SetMemoryLimit(32 << 20)
	t.Setenv("GOMEMLIMIT", "33554432")
	setReadMemoryDefault()
	if got := debug.SetMemoryLimit(-1); got != 32<<20 {
		t.Fatalf("operator override replaced: %d", got)
	}
}
