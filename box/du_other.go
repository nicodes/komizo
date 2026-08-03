//go:build !linux

package box

// See disk_other.go. The probes only mean anything on Linux; this keeps the
// package building where the CLI needs nothing but the report types.
func dirBytes(string) (uint64, bool) { return 0, false }
