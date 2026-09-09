//go:build linux || darwin

package rollout

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"
)

func lockFile(ctx context.Context, file *os.File, poll time.Duration) error {
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return errors.New("cancelled while acquiring rollout lock")
		}
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return errors.New("cannot acquire rollout lock")
		}
		select {
		case <-ctx.Done():
			return errors.New("cancelled while acquiring rollout lock")
		case <-ticker.C:
		}
	}
}

func ownedByCurrent(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}
