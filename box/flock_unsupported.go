//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly && !illumos && !android && !ios

package box

// No flock on this platform (aix, solaris, windows, wasip1, js, plan9, and any
// port added later -- the complement of flock_supported.go's list, so a new
// port degrades safely rather than failing to compile). lockRecord's contract
// already covers "locking is impossible" -- every failure there is a no-op
// release and the caller's work stays correct, just unserialised -- and a
// platform without flock is that case at compile time. komizo-box runs on
// Alpine; this file exists so the shared package compiles for the CLI's
// portable build targets, and never runs.
func flockExclusiveNB(fd uintptr) bool { return false }

func flockUnlock(fd uintptr) {}
