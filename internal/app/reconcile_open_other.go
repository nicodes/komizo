//go:build !unix

package app

import (
	"fmt"
	"os"
)

// openInventory for platforms without O_NOFOLLOW/O_NONBLOCK (windows, wasip1,
// js, plan9): the plain open, then the same regular-file check on the
// descriptor.
//
// Two differences from the unix half, stated rather than hidden:
//
//   - The replacement race the unix half closes -- a checked regular file
//     swapped for a FIFO or symlink between check and open -- exists here.
//   - A SYMLINK AS THE FINAL COMPONENT IS FOLLOWED, not refused: the stdlib
//     offers no no-follow open on Windows, and maintaining a raw CreateFile
//     path for a platform komizo's operators do not run is the worse trade.
//     The user-facing docs (README, reconcile --help) carry this
//     qualification, so the published policy matches the compiled behavior on
//     every supported platform.
//
// komizo's servers and the operators running this command are unix; the CLI
// compiles for these targets so the tree stays portable, not because
// reconcile is expected to run there.
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
