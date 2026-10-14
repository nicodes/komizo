//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Small hosts keep sparse Go heaps on ordinary pages. Resource application is
// also the native boot dependency before Docker, so the default survives boot.
func applySmallHostKernelMemory(root string, total int64) error {
	return applySmallHostKernelMemoryAt(root, total, 0)
}
func applySmallHostKernelMemoryAt(root string, total int64, owner uint32) error {
	if total > 2<<30 {
		return nil
	}
	base := filepath.Join(root, "sys/kernel/mm/transparent_hugepage")
	info, err := os.Lstat(filepath.Join(base, "enabled"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !protectedReadFile(info, owner) {
		return errors.New("kernel memory control unavailable")
	}
	enabled, err := os.ReadFile(filepath.Join(base, "enabled"))
	if err != nil {
		return err
	}
	if strings.Contains(string(enabled), "[never]") {
		return nil
	}
	if !strings.Contains(string(enabled), "[always]") && !strings.Contains(string(enabled), "[madvise]") {
		return errors.New("unknown kernel memory mode")
	}
	for p := base; p != filepath.Clean(root) && p != "/"; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || info.Sys().(*syscall.Stat_t).Uid != owner {
			return errors.New("protected kernel memory ancestry unavailable")
		}
	}
	knobs := []struct{ name, value string }{{"enabled", "madvise"}, {"defrag", "defer+madvise"}, {"khugepaged/max_ptes_none", "0"}}
	for _, knob := range knobs {
		p := filepath.Join(base, knob.name)
		i, e := os.Lstat(p)
		if e != nil || !protectedReadFile(i, owner) {
			return errors.New("protected kernel memory control unavailable")
		}
	}
	defrag, err := os.ReadFile(filepath.Join(base, "defrag"))
	if err != nil {
		return err
	}
	if !strings.Contains(string(defrag), "defer+madvise") {
		return errors.New("deferred kernel memory control unavailable")
	}
	for _, knob := range knobs {
		if err := os.WriteFile(filepath.Join(base, knob.name), []byte(knob.value), 0600); err != nil {
			return err
		}
	}
	return nil
}
