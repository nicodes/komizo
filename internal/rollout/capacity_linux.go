//go:build linux

package rollout

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func availableCapacity(path string) (uint64, uint64, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil || len(data) > 1<<20 {
		return 0, 0, errors.New("memory capacity unavailable")
	}
	var memory uint64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "MemAvailable:" && fields[2] == "kB" {
			kb, parseErr := strconv.ParseUint(fields[1], 10, 64)
			if parseErr != nil || kb > ^uint64(0)/1024 {
				return 0, 0, errors.New("invalid memory capacity")
			}
			memory = kb * 1024
			break
		}
	}
	if memory == 0 {
		return 0, 0, errors.New("memory capacity unavailable")
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0, err
	}
	return memory, stat.Bavail * uint64(stat.Bsize), nil
}
