//go:build !windows && !plan9

package main

import (
	"os"
	"syscall"
)

func workloadRootOwner(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0
}
