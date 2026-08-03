package box

import (
	"io/fs"
	"path/filepath"
	"syscall"
)

// dirBytes is du -sx: the disk actually occupied by a tree, staying on one
// filesystem.
//
// BLOCKS, not apparent size -- st_blocks times 512, which is what du reports
// and what the disk bar it sits beside is measured in. A sparse file or a
// compressed filesystem makes the two differ by a lot, and a volume that reads
// as larger than the disk holding it is the kind of number that makes somebody
// stop trusting the whole page.
//
// Hard links are counted once, the way du does. A tree of linked backups would
// otherwise report several times the space it costs.
//
// One filesystem only. Following a mount out of the volume would measure
// whatever is mounted there, which belongs to something else.
func dirBytes(root string) (uint64, bool) {
	var st syscall.Stat_t
	if err := syscall.Lstat(root, &st); err != nil {
		return 0, false
	}
	dev := st.Dev
	seen := map[uint64]bool{}
	var total uint64
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// A directory that vanished mid-walk, or one this cannot read.
			// Skipped rather than abandoning the measurement: a volume is live
			// data and files move under a walk all the time.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		sys, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		if sys.Dev != dev {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if sys.Nlink > 1 {
			if seen[sys.Ino] {
				return nil
			}
			seen[sys.Ino] = true
		}
		total += uint64(sys.Blocks) * 512
		return nil
	})
	if err != nil {
		return 0, false
	}
	return total, true
}
