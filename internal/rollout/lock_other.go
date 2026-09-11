//go:build !linux && !darwin

package rollout

import (
	"context"
	"errors"
	"os"
	"time"
)

func lockFile(context.Context, *os.File, time.Duration) error {
	return errors.New("rollout journal locking is unsupported on this platform")
}

func ownedByCurrent(os.FileInfo) bool { return false }
