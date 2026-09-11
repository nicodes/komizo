//go:build !linux

package gateway

// The production gateway runs beside Docker on Linux. Other targets compile
// for CLI portability but conservatively refuse stale-socket replacement when
// their platform-specific error cannot be established.
func connectionRefused(error) bool { return false }
