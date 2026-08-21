//go:build unix

package main

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/nicodes/komizo/box"
)

// A FIFO IN THE INBOX MUST NOT HANG ROOTD.
//
// The inbox is owned by the account that talks to the internet, so it can
// mkfifo there. A plain Open on a FIFO blocks in the kernel until somebody
// writes, and this ran inside rootd's loop -- so one command-shaped pipe stopped
// commands AND the report, forever. A box that stops reporting is
// indistinguishable from a box that is down.
func TestAFifoInTheInboxDoesNotHang(t *testing.T) {
	captureCompose(t)
	inbox, results := t.TempDir(), t.TempDir()
	fifo := filepath.Join(inbox, "looks-like-a-command")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot make a fifo here: %v", err)
	}
	pub, _ := device(t)
	conf := box.AgentConf{ServerID: "srv_mine", OperatorKeys: []string{box.FormatDeviceKey(pub)}}

	done := make(chan struct{})
	go func() {
		applyPending(context.Background(), conf, inbox, results)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("applyPending blocked on a fifo -- rootd would stop reporting")
	}
	if _, err := os.Stat(fifo); !os.IsNotExist(err) {
		t.Error("the fifo was left behind to block the next pass too")
	}
}
