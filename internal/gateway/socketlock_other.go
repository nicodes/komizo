//go:build !linux && !darwin

package gateway

import (
	"errors"
	"os"
)

func connectionRefused(error) bool { return false }

func socketLock(string) (*os.File, error) {
	return nil, errors.New("gateway socket locking is unsupported on this platform")
}
