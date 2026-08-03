package box

import (
	"fmt"
	"syscall"
)

// statfs measures one filesystem.
//
// Used and available rather than the raw size, because df computes its own
// percentage that way -- excluding the blocks reserved for root -- and a disk
// figure that disagrees with df on the very same box is one nobody will
// believe, however defensible the arithmetic behind it. So: used is what is
// spent, size is used plus what an ordinary process may still have.
//
// Dev is the filesystem ID rather than a device NAME, which is what the shell
// this replaces read out of df's first column. The id is the better answer for
// the only thing Dev is for -- deciding whether two mount points are one
// filesystem. A bind mount of /var/lib/docker onto itself gives one filesystem
// two names in /proc/mounts and the same id here, and the id needs no parsing
// of a file whose format is not promised.
func statfs(path string) (Disk, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return Disk{}, false
	}
	bs := uint64(st.Bsize)
	if bs == 0 {
		return Disk{}, false
	}
	used := (st.Blocks - st.Bfree) * bs
	avail := st.Bavail * bs
	return Disk{
		Dev:  fmt.Sprintf("%x-%x", uint32(st.Fsid.X__val[0]), uint32(st.Fsid.X__val[1])),
		Used: used,
		Size: used + avail,
	}, true
}
