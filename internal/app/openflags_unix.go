//go:build unix

package app

import "syscall"

// oNoFollow is O_NOFOLLOW where the platform has it: a private key or an
// inventory opened through a symlink is a file the caller did not name.
// See openflags_other.go for the platforms without it.
const oNoFollow = syscall.O_NOFOLLOW
