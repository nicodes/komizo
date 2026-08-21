//go:build unix

package app

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Unix-only, because the facilities under test are: syscall.Mkfifo does not
// exist in Go's Windows syscall package (compilation, not a runtime check, is
// where that fails), and the O_NOFOLLOW symlink policy is enforced by the
// unix openInventory. The shared tests stay in reconcile_test.go and compile
// everywhere.

// A FIFO IS NOT AN INVENTORY. os.Open on a FIFO blocks until a writer appears
// and a slow writer stalls the read indefinitely -- the 1 MiB cap bounds
// bytes, not time -- so the path must be a regular file, checked on the opened
// descriptor. The timeout is not decoration: if the non-blocking open is ever
// lost, this test fails by CLOCK rather than hanging the suite.
func TestTheInventoryMustBeARegularFile(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "expected-apps.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := loadInventory(fifo)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("a FIFO inventory was not refused as a non-regular file: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("loadInventory blocked on a FIFO -- the non-blocking open is gone")
	}
}

// A SYMLINK IS NOT AN INVENTORY EITHER. The file is an operator's committed
// answer to "what should be on this box", and following a final-component link
// would let a writable directory point the check at another file -- including
// at a FIFO, which is the blocking case above arriving by a second door.
// Refusing the link is deterministic (O_NOFOLLOW fails the open with ELOOP),
// unlike the mid-open replacement race it stands in for.
func TestAnInventorySymlinkIsRefused(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	if err := os.WriteFile(real, []byte(`{"apps":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "expected-apps.json")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	_, err := loadInventory(link)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("an inventory symlink to a regular file was not refused: %v", err)
	}
}

func TestAnInventorySymlinkToAFifoIsRefusedWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "expected-apps.json")
	if err := os.Symlink(fifo, link); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := loadInventory(link)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("an inventory symlink to a FIFO was not refused: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("loadInventory blocked on a symlink to a FIFO -- O_NOFOLLOW is gone")
	}
}
