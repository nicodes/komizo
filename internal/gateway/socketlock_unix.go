//go:build linux || darwin

package gateway

import (
	"errors"
	"os"
	"syscall"
)

func connectionRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }

func socketLock(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, errors.New("cannot open gateway ownership lock")
	}
	info, statErr := file.Stat()
	link, linkErr := os.Lstat(path)
	if statErr != nil || linkErr != nil || !info.Mode().IsRegular() || !link.Mode().IsRegular() || !os.SameFile(info, link) || info.Mode().Perm()&0o077 != 0 {
		file.Close()
		return nil, errors.New("gateway ownership lock must be a private regular file")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("another gateway owns this admin socket")
	}
	return file, nil
}
