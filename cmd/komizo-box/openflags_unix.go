//go:build unix

package main

import "syscall"

// The flags readBounded opens the inbox with. Split by platform because the
// constants do not exist everywhere this module compiles -- see
// openflags_other.go.
const (
	oNoFollow = syscall.O_NOFOLLOW
	oNonBlock = syscall.O_NONBLOCK
)
