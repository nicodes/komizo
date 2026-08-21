//go:build unix

package box

import "syscall"

// flockExclusiveNB takes an exclusive lock on an open file without blocking,
// and answers whether it got it. Split out of stopped.go because syscall.Flock
// does not exist on every platform this module compiles for -- see
// flock_other.go.
func flockExclusiveNB(fd uintptr) bool {
	return syscall.Flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB) == nil
}

func flockUnlock(fd uintptr) { _ = syscall.Flock(int(fd), syscall.LOCK_UN) }
