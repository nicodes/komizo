//go:build unix

// The unix tag is the EXACT capability set here, not an approximation: the
// gc toolchain's unix targets are aix, android, darwin, dragonfly, freebsd,
// illumos, ios, linux, netbsd, openbsd and solaris (hurd has no gc port), and
// every one of them carries O_NOFOLLOW, O_NONBLOCK, O_CLOEXEC and
// syscall.Open -- probed per target with `GOOS=<target> go doc syscall.<sym>`
// under Go 1.26.5, and compiled per family by the cross-build step in
// `make check` and CI. The platforms WITHOUT those constants (windows,
// wasip1, js, plan9) take reconcile_open_other.go.

package app

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// openInventory opens the inventory without following a final-component link
// or hanging on a FIFO.
//
// The naive sequence -- Lstat to check, then os.Open -- has a window between
// the two in which a writable directory can swap the checked regular file for
// a FIFO or a symlink to one, and os.Open on a FIFO blocks until a writer
// appears. So the checks happen on the OPENED descriptor, and the open itself
// is made safe:
//
//   - O_NOFOLLOW refuses a symlink as the FINAL component (ELOOP) -- exactly
//     that, and no more. Intermediate directories MAY still be symlinks
//     ($HOME itself sometimes is one), and an attacker who can WRITE the
//     parent directory can rename a different regular file over the path
//     outright; the descriptor check then correctly validates the replacement.
//     No open flag prevents that, and none is claimed to: the inventory and
//     its parent directories must be owned and writable only by the operator,
//     like every other file a check's answer depends on.
//   - O_NONBLOCK means that even if the descriptor somehow names a FIFO, the
//     open and any read return immediately instead of waiting on a writer
//     that may never come. It is ignored for regular files, so it costs a
//     real inventory nothing.
//   - The regular-file check on the descriptor rules out FIFOs and devices:
//     it is the answer about the thing actually held, where a pre-open Lstat
//     answers about a path that can change the moment it returns.
func openInventory(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("the inventory must be a real file, not a symlink (%s).\n"+
				"    Intermediate directories may be links; the file itself may not.", path)
		}
		return nil, fmt.Errorf("could not read the inventory: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("could not read the inventory: %w", err)
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("the inventory must be a regular file, not %s (%s)", st.Mode().Type(), path)
	}
	return f, nil
}
