//go:build !linux && !darwin

package gateway

import (
	"errors"
	"os"
)

func socketLock(string) (*os.File, error) {
	return nil, errors.New("gateway socket locking is unsupported on this platform")
}
