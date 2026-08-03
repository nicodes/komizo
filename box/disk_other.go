//go:build !linux

package box

// The probes read /proc and /sys, so they only mean anything on Linux. This
// exists so the package still BUILDS elsewhere -- the CLI imports it for the
// report types, and an operator's laptop is frequently a Mac.
//
// Reporting absent rather than guessing: a disk figure invented on a platform
// the rest of the probe cannot read would be the one number on the page with no
// measurement behind it.
func statfs(string) (Disk, bool) { return Disk{}, false }
