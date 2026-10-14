//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Fresh operator probes share the worker's declared envelope instead of
// allocating an additional unconstrained process in the SSH service group.
func enterReadBudget() error {
	if os.Geteuid() != 0 {
		return nil
	}
	return enterReadBudgetAt("/etc/komizo/resources.json", "/sys/fs/cgroup", os.Getpid(), 0)
}

func enterReadBudgetAt(policyPath, cgroupRoot string, pid int, owner uint32) error {
	info, err := os.Lstat(policyPath)
	if os.IsNotExist(err) {
		return nil
	} // Unconfigured installations have no envelope.
	if err != nil || !protectedReadFile(info, owner) || info.Mode().Perm()&0077 != 0 || info.Size() > 65536 {
		return errors.New("read resource authority unavailable")
	}
	body, err := os.ReadFile(policyPath)
	if err != nil {
		return err
	}
	var policy struct {
		Controls map[string]struct {
			MemoryBytes int64 `json:"memory_bytes"`
		} `json:"controls"`
	}
	if err = json.Unmarshal(body, &policy); err != nil {
		return errors.New("read resource authority invalid")
	}
	if len(policy.Controls) == 0 {
		return nil
	}
	group, ok := policy.Controls["openrc.komizo-rootd"]
	if !ok || group.MemoryBytes < 4<<20 || pid <= 0 {
		return errors.New("declared read envelope unavailable")
	}
	dir := filepath.Join(cgroupRoot, "openrc.komizo-rootd")
	for _, path := range []string{cgroupRoot, dir} {
		i, e := os.Lstat(path)
		if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 || i.Mode().Perm()&0022 != 0 || i.Sys().(*syscall.Stat_t).Uid != owner {
			return errors.New("protected read control group unavailable")
		}
	}
	for _, name := range []string{"memory.max", "cgroup.procs"} {
		i, e := os.Lstat(filepath.Join(dir, name))
		if e != nil || !protectedReadFile(i, owner) {
			return errors.New("read control interface unavailable")
		}
	}
	limit, err := os.ReadFile(filepath.Join(dir, "memory.max"))
	if err != nil || strings.TrimSpace(string(limit)) != strconv.FormatInt(group.MemoryBytes, 10) {
		return errors.New("read control limit differs from authority")
	}
	return os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0600)
}

func protectedReadFile(info os.FileInfo, owner uint32) bool {
	return info.Mode().IsRegular() && info.Mode().Perm()&0022 == 0 && info.Sys().(*syscall.Stat_t).Uid == owner
}
