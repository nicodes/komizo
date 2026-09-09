//go:build unix

// The unix tag is the exact capability set for these constants: every gc unix
// target carries O_NOFOLLOW and O_NONBLOCK (probed per target with
// `GOOS=<target> go doc syscall.<sym>` under Go 1.26.5, and compiled per
// family by the cross-build gate). See reconcile_open_unix.go for the probe
// details and the other-platform fallback.

package app

import "syscall"

// oNoFollow is O_NOFOLLOW where the platform has it: a private key or an
// inventory opened through a symlink is a file the caller did not name.
// See openflags_other.go for the platforms without it.
const oNoFollow = syscall.O_NOFOLLOW
