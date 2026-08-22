//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly || illumos || android || ios

package box

import "syscall"

// flockExclusiveNB takes an exclusive lock on an open file without blocking,
// and answers whether it got it. Split out of stopped.go because syscall.Flock
// does not exist on every platform this module compiles for.
//
// The build tag is the EXACT set of Go 1.26 targets whose syscall package
// carries Flock, probed with `GOOS=<target> go doc syscall.Flock`: every unix
// except aix and solaris, which is why this is a list rather than the unix
// tag. The cross-build step in `make check` (and CI) compiles for aix,
// solaris/illumos and wasip1 among others, so a port gaining or losing the
// API fails the gate rather than surprising somebody. See
// flock_unsupported.go for the complement.
func flockExclusiveNB(fd uintptr) bool {
	return syscall.Flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB) == nil
}

func flockUnlock(fd uintptr) { _ = syscall.Flock(int(fd), syscall.LOCK_UN) }
