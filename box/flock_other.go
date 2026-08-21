//go:build !unix

package box

// No flock on this platform. lockRecord's contract already covers "locking is
// impossible" -- every failure there is a no-op release and the caller's work
// stays correct, just unserialised -- and a platform without flock is that
// case at compile time. komizo-box runs on Alpine; this file exists so the
// shared package compiles for the CLI's portable build targets, and never
// runs.
func flockExclusiveNB(fd uintptr) bool { return false }

func flockUnlock(fd uintptr) {}
