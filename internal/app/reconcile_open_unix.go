//go:build unix

package app

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// openInventory opens the inventory the way a replacement cannot hurt us.
//
// The naive sequence -- Lstat to check, then os.Open -- has a window between
// the two in which a writable directory can swap the checked regular file for
// a FIFO or a symlink to one, and os.Open on a FIFO blocks until a writer
// appears. So the checks happen on the OPENED descriptor, and the open itself
// is made safe:
//
//   - O_NOFOLLOW refuses a symlink as the FINAL component (ELOOP). The
//     inventory is an operator's committed file, and silently following a
//     link would let a writable directory point the check at another file.
//     Intermediate directories MAY still be symlinks -- $HOME itself
//     sometimes is one.
//   - O_NONBLOCK means that even if the descriptor somehow names a FIFO, the
//     open and any read return immediately instead of waiting on a writer
//     that may never come. It is ignored for regular files, so it costs a
//     real inventory nothing.
//   - The regular-file check on the descriptor is the answer about the thing
//     actually held. A pre-open Lstat answers about a path that can change
//     the moment it returns; this one cannot.
func openInventory(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("the inventory must be a real file, not a symlink (%s);\n"+
				"    a link would let a writable directory point the check at another file.\n"+
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
