//go:build !unix

package app

import (
	"fmt"
	"os"
)

// openInventory for platforms without O_NOFOLLOW/O_NONBLOCK (Windows): the
// plain open, then the same regular-file check on the descriptor.
//
// The replacement race the unix half closes -- a checked regular file swapped
// for a FIFO or symlink between check and open -- exists here, and symlinks
// are followed rather than refused. komizo's servers and the operators running
// this command are unix; the CLI compiles for Windows so the tree stays
// portable, not because reconcile is expected to run there. The difference is
// stated here rather than hidden in a shared implementation.
func openInventory(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not read the inventory: %w", err)
	}
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
