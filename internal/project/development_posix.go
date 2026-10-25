//go:build linux || darwin

package project

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// The CLI owns this lease through cleanup, beyond the nested supervisor's
// lifetime. A replacement cannot start while old checkout resources stop.
func developmentLease(root string) (func(), error) {
	command := exec.Command("git", "rev-parse", "--git-path", "komizo-dev.lock")
	command.Dir = root
	body, err := command.Output()
	if err != nil {
		return nil, err
	}
	path := strings.TrimSpace(string(body))
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("this checkout already owns a development session or its cleanup")
	}
	return func() { file.Close() }, nil
}
