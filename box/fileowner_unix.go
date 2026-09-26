//go:build !windows && !plan9

package box

import (
	"os"
	"syscall"
)

func fileUID(info os.FileInfo) (int, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}
