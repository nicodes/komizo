package box

// diskAccounting turns statfs block counts into the bytes df reports.
//
// used is (Blocks-Bfree)*Bsize -- including space reserved for root.
// available is Bavail*Bsize -- what an ordinary process may still write.
// size is used+available, NOT Blocks*Bsize, so the percentage matches df.
func diskAccounting(bsize, blocks, bfree, bavail uint64) (used, size, available uint64) {
	if bsize == 0 {
		return 0, 0, 0
	}
	used = (blocks - bfree) * bsize
	available = bavail * bsize
	return used, used + available, available
}

// inodeAccounting turns statfs inode counts into used and free.
//
// ok is false when the filesystem reports no inode table (Files == 0), so a
// zero is not presented as a measurement.
func inodeAccounting(files, ffree uint64) (used, free uint64, ok bool) {
	if files == 0 {
		return 0, 0, false
	}
	return saturatingSub(files, ffree), ffree, true
}
