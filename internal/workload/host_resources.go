package workload

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// HostResources reserves the OS first, then divides finite physical RAM among
// production, the proxy, preview services and the shared preview database.
// Per-service maxima still apply inside each parent. This is a hard aggregate
// ceiling, not a claim that all services can use their individual maxima at once.
type HostResources struct {
	Version             int       `json:"version"`
	PhysicalMemoryBytes int64     `json:"physical_memory_bytes"`
	OSReserveBytes      int64     `json:"os_reserve_bytes"`
	PhysicalMilliCPUs   int64     `json:"physical_milli_cpus"`
	OSReserveMilliCPUs  int64     `json:"os_reserve_milli_cpus"`
	Production          HostGroup `json:"production"`
	Proxy               HostGroup `json:"proxy"`
	Previews            HostGroup `json:"previews"`
	PreviewDatabase     HostGroup `json:"preview_database"`
}
type HostGroup struct {
	MemoryBytes int64 `json:"memory_bytes"`
	SwapBytes   int64 `json:"swap_bytes"` // additional swap, unlike Compose's total
	MilliCPUs   int64 `json:"milli_cpus"`
	PIDs        int64 `json:"pids"`
}

func (p HostResources) groups() map[string]HostGroup {
	return map[string]HostGroup{"komizo-production": p.Production, "komizo-proxy": p.Proxy, "komizo-previews": p.Previews, "komizo-preview-database": p.PreviewDatabase}
}
func (p HostResources) Check(measuredMemory, measuredCPU int64) error {
	if p.Version != 1 || p.PhysicalMemoryBytes <= 0 || p.PhysicalMemoryBytes > measuredMemory || p.OSReserveBytes < 64<<20 || p.OSReserveBytes > p.PhysicalMemoryBytes {
		return errors.New("host resources require measured RAM and an OS reserve")
	}
	if p.PhysicalMilliCPUs <= 0 || p.PhysicalMilliCPUs > measuredCPU || p.OSReserveMilliCPUs < 100 || p.OSReserveMilliCPUs > p.PhysicalMilliCPUs {
		return errors.New("host resources require measured CPU and an OS CPU reserve")
	}
	reservedCPU := p.OSReserveMilliCPUs
	reserved := p.OSReserveBytes
	for _, group := range p.groups() {
		if group.MemoryBytes < 4<<20 || group.MemoryBytes > p.PhysicalMemoryBytes || group.SwapBytes < 0 || group.SwapBytes > p.PhysicalMemoryBytes || group.MilliCPUs < 1 || group.MilliCPUs > 64000 || group.PIDs < 16 || group.PIDs > 8192 {
			return errors.New("host group requires finite memory, swap, CPU and PID limits")
		}
		reserved += group.MemoryBytes
		reservedCPU += group.MilliCPUs
	}
	if reserved > p.PhysicalMemoryBytes || reservedCPU > p.PhysicalMilliCPUs {
		return errors.New("aggregate host ceilings consume the OS reserve")
	}
	if p.Previews.SwapBytes != 0 || p.PreviewDatabase.SwapBytes != 0 {
		return errors.New("preview groups may not grow swap")
	}
	return nil
}

func (p HostResources) Apply(root string, measuredMemory, measuredCPU int64) error {
	if err := p.Check(measuredMemory, measuredCPU); err != nil {
		return err
	}
	controllers, err := os.ReadFile(filepath.Join(root, "cgroup.controllers"))
	if err != nil {
		return errors.New("cgroup v2 controller inventory unavailable")
	}
	for _, name := range []string{"cpu", "memory", "pids"} {
		if !strings.Contains(" "+strings.TrimSpace(string(controllers))+" ", " "+name+" ") {
			return errors.New("required cgroup v2 controller unavailable")
		}
	}

	for name, group := range p.groups() {
		dir := filepath.Join(root, name)
		if info, err := os.Lstat(dir); err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
			return errors.New("host cgroup path is not a real directory")
		}
		if body, err := os.ReadFile(filepath.Join(dir, "memory.current")); err == nil {
			current, e := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64)
			if e != nil || current > group.MemoryBytes {
				return errors.New("host resource change would reduce memory below current usage; measure and drain first")
			}
		}
	}

	if err := os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), []byte("+cpu +memory +pids"), 0600); err != nil {
		return err
	}
	for name, group := range p.groups() {
		dir := filepath.Join(root, name)
		if info, err := os.Lstat(dir); err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
			return errors.New("host cgroup path is not a real directory")
		}
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
		settings := map[string]string{"memory.max": fmt.Sprint(group.MemoryBytes), "memory.swap.max": fmt.Sprint(group.SwapBytes), "cpu.max": fmt.Sprintf("%d 100000", group.MilliCPUs*100), "pids.max": fmt.Sprint(group.PIDs), "cgroup.subtree_control": "+cpu +memory +pids"}
		for file, value := range settings {
			if err := os.WriteFile(filepath.Join(dir, file), []byte(value), 0600); err != nil {
				return fmt.Errorf("apply %s/%s: %w", name, file, err)
			}
		}
	}
	return nil
}
