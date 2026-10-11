//go:build linux

package main

import (
	"github.com/nicodes/komizo/box"
	"os"
	"syscall"
)

func imageConfigSpace(path string) bool {
	floor := int64(2 << 30)
	_, statErr := os.Lstat(box.DeployFloorsPath)
	if os.IsNotExist(statErr) {
		var fs syscall.Statfs_t
		return syscall.Statfs(path, &fs) == nil && uint64(fs.Bavail)*uint64(fs.Bsize) > uint64(floor)+512 && fs.Ffree > 1025
	}
	body, err := protectedActivationBytes(box.DeployFloorsPath)
	if err == nil {
		floors, _, parseErr := box.ParsePreviewFloors(string(body))
		if parseErr != nil {
			return false
		}
		if floors.DiskBytes > floor {
			floor = floors.DiskBytes
		}
	} else if !os.IsNotExist(err) {
		return false
	}
	var fs syscall.Statfs_t
	return syscall.Statfs(path, &fs) == nil && uint64(fs.Bavail)*uint64(fs.Bsize) > uint64(floor)+512 && fs.Ffree > 1025
}
