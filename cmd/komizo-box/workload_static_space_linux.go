//go:build linux

package main

import (
	"errors"
	"github.com/nicodes/komizo/internal/workload"
	"syscall"
)

func staticSpace(public string, limits workload.StaticLimits) error {
	maxBytes, _, err := workload.StaticBounds(limits)
	if err != nil {
		return err
	}
	var space syscall.Statfs_t
	if err := syscall.Statfs(public, &space); err != nil || uint64(space.Bavail)*uint64(space.Bsize) < uint64((2<<30)+2*maxBytes) || space.Ffree < 1024+2*workload.StaticMaxEntries {
		return errors.New("public extraction would consume the host recovery floor")
	}
	return nil
}
