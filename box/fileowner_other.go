//go:build windows || plan9

package box

import "os"

func fileUID(info os.FileInfo) (int, bool) {
	return 0, false
}
