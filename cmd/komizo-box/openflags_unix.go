//go:build unix

// The unix tag is the exact capability set for these constants: every gc unix
// target carries O_NOFOLLOW and O_NONBLOCK (probed per target with
// `GOOS=<target> go doc syscall.<sym>` under Go 1.26.5, and compiled per
// family by the cross-build gate). See reconcile_open_unix.go for the probe
// details and the other-platform fallback.

package main

import "syscall"

// The flags readBounded opens the inbox with. Split by platform because the
// constants do not exist everywhere this module compiles -- see
// openflags_other.go.
const (
	oNoFollow = syscall.O_NOFOLLOW
	oNonBlock = syscall.O_NONBLOCK
)
