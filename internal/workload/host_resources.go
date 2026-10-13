package workload

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// HostResources reserves the OS first, then divides finite physical RAM among
// production, the proxy, preview services and the shared preview database.
// Per-service maxima still apply inside each parent. This is a hard aggregate
// ceiling, not a claim that all services can use their individual maxima at once.
type HostResources struct {
	Version             int                         `json:"version"`
	PhysicalMemoryBytes int64                       `json:"physical_memory_bytes"`
	OSReserveBytes      int64                       `json:"os_reserve_bytes"`
	PhysicalMilliCPUs   int64                       `json:"physical_milli_cpus"`
	OSReserveMilliCPUs  int64                       `json:"os_reserve_milli_cpus"`
	Production          HostGroup                   `json:"production"`
	Proxy               HostGroup                   `json:"proxy"`
	Previews            HostGroup                   `json:"previews"`
	PreviewDatabase     HostGroup                   `json:"preview_database"`
	Apps                map[string]ApplicationGroup `json:"apps,omitempty"`
}

// ApplicationGroup retains a measured serving footprint under pressure. Each
// app's hard ceiling leaves room for every other app's declared reserve.
type ApplicationGroup struct {
	HostGroup
	BaselineMemoryBytes int64 `json:"baseline_memory_bytes"`
	MemoryLowBytes      int64 `json:"memory_low_bytes"`
	MemoryHighBytes     int64 `json:"memory_high_bytes"`
	CPUWeight           int64 `json:"cpu_weight"`
	// Zero uses explicit device rate limits without assuming a proportional
	// I/O scheduler. Positive weights require the io.weight interface.
	IOWeight int64            `json:"io_weight,omitempty"`
	IOMax    []DeviceIOBudget `json:"io_max,omitempty"`
}

// Rate limits enforce disk admission independently of the device scheduler.
// Devices and rates belong to the installed operator policy, never Compose.
type DeviceIOBudget struct {
	Device              string `json:"device"`
	ReadBytesPerSecond  int64  `json:"read_bytes_per_second"`
	WriteBytesPerSecond int64  `json:"write_bytes_per_second"`
}

var blockDeviceID = regexp.MustCompile(`^(0|[1-9][0-9]{0,6}):(0|[1-9][0-9]{0,6})$`)

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
	if err := p.checkApps(); err != nil {
		return err
	}
	return nil
}

func (p HostResources) checkApps() error {
	if len(p.Apps) > 32 {
		return errors.New("host application inventory exceeds its bound")
	}
	var reserved int64
	for name, group := range p.Apps {
		if len(group.IOMax) > 16 {
			return errors.New("application disk device inventory exceeds its bound")
		}
		seen := map[string]bool{}
		for _, limit := range group.IOMax {
			if !blockDeviceID.MatchString(limit.Device) || seen[limit.Device] || limit.ReadBytesPerSecond < 4096 || limit.ReadBytesPerSecond > 1<<30 || limit.WriteBytesPerSecond < 4096 || limit.WriteBytesPerSecond > 1<<30 {
				return errors.New("disk limits require unique block devices and finite read/write rates")
			}
			seen[limit.Device] = true
		}
		if !identifier.MatchString(name) || group.BaselineMemoryBytes < 4<<20 ||
			group.MemoryLowBytes < group.BaselineMemoryBytes || group.MemoryHighBytes < group.MemoryLowBytes ||
			group.MemoryBytes < group.MemoryHighBytes || group.MemoryBytes > p.Production.MemoryBytes ||
			group.SwapBytes < 0 || group.SwapBytes > p.Production.SwapBytes || group.MilliCPUs < 1 || group.MilliCPUs > p.Production.MilliCPUs ||
			group.PIDs < 16 || group.PIDs > p.Production.PIDs || group.CPUWeight < 1 || group.CPUWeight > 10000 || group.IOWeight < 0 || group.IOWeight > 10000 || (group.IOWeight == 0 && len(group.IOMax) == 0) {
			return errors.New("application group requires measured baseline, pressure threshold and finite host-owned limits")
		}
		reserved += group.MemoryLowBytes
	}
	for _, group := range p.Apps {
		if reserved-group.MemoryLowBytes+group.MemoryBytes > p.Production.MemoryBytes {
			return errors.New("one app's hard memory ceiling consumes another app's serving reserve")
		}
	}
	return nil
}

// Preflight validates capacity, available controllers and current usage without
// creating a cgroup or writing a controller. The platform journal uses it before
// replacing the protected policy; Apply repeats it immediately before effects.
func (p HostResources) Preflight(root string, measuredMemory, measuredCPU int64) error {
	if err := p.Check(measuredMemory, measuredCPU); err != nil {
		return err
	}
	controllers, err := os.ReadFile(filepath.Join(root, "cgroup.controllers"))
	if err != nil {
		return errors.New("cgroup v2 controller inventory unavailable")
	}
	needed := []string{"cpu", "memory", "pids"}
	if len(p.Apps) > 0 {
		needed = append(needed, "io")
	}
	for _, name := range needed {
		if !strings.Contains(" "+strings.TrimSpace(string(controllers))+" ", " "+name+" ") {
			return errors.New("required cgroup v2 controller unavailable")
		}
	}
	// Preflight every new subgroup before changing any controller or limit.
	for name, group := range p.Apps {
		if group.IOWeight > 0 {
			if info, err := os.Stat(filepath.Join(root, "komizo-production", "io.weight")); err != nil || !info.Mode().IsRegular() {
				return errors.New("requested I/O weighting controller unavailable; select explicit device rate limits or a supported weighting backend")
			}
		}
		if root == "/sys/fs/cgroup" {
			for _, limit := range group.IOMax {
				if _, err := os.Stat(filepath.Join("/sys/dev/block", limit.Device)); err != nil {
					return errors.New("reviewed disk device is unavailable")
				}
			}
		}
		dir := filepath.Join(root, "komizo-production", name)
		info, err := os.Lstat(dir)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("application cgroup path is not a real directory")
		}
		if _, err := currentIOLimitDevices(filepath.Join(dir, "io.max")); err != nil {
			return err
		}
		for file, limit := range map[string]int64{"memory.current": group.MemoryBytes, "memory.swap.current": group.SwapBytes, "pids.current": group.PIDs} {
			body, err := os.ReadFile(filepath.Join(dir, file))
			if err != nil {
				return errors.New("application usage is unavailable")
			}
			current, err := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64)
			if err != nil || current < 0 || current > limit {
				return errors.New("application resource reduction requires measurement and drain")
			}
		}
	}

	for name, group := range p.groups() {
		dir := filepath.Join(root, name)
		if info, err := os.Lstat(dir); err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
			return errors.New("host cgroup path is not a real directory")
		}
		if _, err := os.Lstat(dir); os.IsNotExist(err) {
			continue
		}
		for file, ceiling := range map[string]int64{
			"memory.current":      group.MemoryBytes,
			"memory.swap.current": group.SwapBytes,
			"pids.current":        group.PIDs,
		} {
			body, err := os.ReadFile(filepath.Join(dir, file))
			if err != nil {
				return fmt.Errorf("host usage unavailable for %s/%s: %w", name, file, err)
			}
			current, err := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64)
			if err != nil || current < 0 || current > ceiling {
				return fmt.Errorf("host resource change would reduce %s/%s below current usage; measure and drain first", name, file)
			}
		}
	}

	return nil
}

func (p HostResources) Apply(root string, measuredMemory, measuredCPU int64) error {
	if err := p.Preflight(root, measuredMemory, measuredCPU); err != nil {
		return err
	}
	control := "+cpu +memory +pids"
	if len(p.Apps) > 0 {
		control += " +io"
	}
	if err := os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), []byte(control), 0600); err != nil {
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
		if name == "komizo-proxy" {
			// Every app's core route depends on this shared serving group.
			// Protect its existing finite allocation from ancestor reclaim;
			// this changes neither the hard ceiling nor the physical envelope.
			settings["memory.low"] = fmt.Sprint(group.MemoryBytes)
		}
		for file, value := range settings {
			if err := os.WriteFile(filepath.Join(dir, file), []byte(value), 0600); err != nil {
				return fmt.Errorf("apply %s/%s: %w", name, file, err)
			}
		}
	}
	var reserve int64
	if len(p.Apps) > 0 {
		production := filepath.Join(root, "komizo-production")
		if err := os.WriteFile(filepath.Join(production, "cgroup.subtree_control"), []byte(control), 0600); err != nil {
			return err
		}
		for name, group := range p.Apps {
			reserve += group.MemoryLowBytes
			dir := filepath.Join(production, name)
			if err := os.MkdirAll(dir, 0755); err != nil {
				return err
			}
			settings := map[string]string{"memory.low": fmt.Sprint(group.MemoryLowBytes), "memory.high": fmt.Sprint(group.MemoryHighBytes),
				"memory.max": fmt.Sprint(group.MemoryBytes), "memory.swap.max": fmt.Sprint(group.SwapBytes),
				"cpu.max": fmt.Sprintf("%d 100000", group.MilliCPUs*100), "cpu.weight": fmt.Sprint(group.CPUWeight),
				"pids.max": fmt.Sprint(group.PIDs), "cgroup.subtree_control": control}
			if group.IOWeight > 0 {
				settings["io.weight"] = fmt.Sprintf("default %d", group.IOWeight)
			}
			for file, value := range settings {
				if err := os.WriteFile(filepath.Join(dir, file), []byte(value), 0600); err != nil {
					return fmt.Errorf("apply application group %s/%s: %w", name, file, err)
				}
			}
			// This operator-owned group is an exact policy replacement. Clearing
			// prior device limits also lets recovery restore a previous empty set.
			devices, err := currentIOLimitDevices(filepath.Join(dir, "io.max"))
			if err != nil {
				return err
			}
			for _, device := range devices {
				if err := os.WriteFile(filepath.Join(dir, "io.max"), []byte(device+" rbps=max wbps=max riops=max wiops=max"), 0600); err != nil {
					return err
				}
			}
			for _, limit := range group.IOMax {
				value := fmt.Sprintf("%s rbps=%d wbps=%d", limit.Device, limit.ReadBytesPerSecond, limit.WriteBytesPerSecond)
				if err := os.WriteFile(filepath.Join(dir, "io.max"), []byte(value), 0600); err != nil {
					return fmt.Errorf("apply application disk limit %s: %w", name, err)
				}
			}
		}
	}
	// Recovery of the previous non-app layout must clear the parent protection
	// installed by the candidate. Empty unlisted leaves can remain for inspection.
	if err := os.WriteFile(filepath.Join(root, "komizo-production", "memory.low"), []byte(fmt.Sprint(reserve)), 0600); err != nil {
		return err
	}
	return nil
}

func currentIOLimitDevices(path string) ([]string, error) {
	body, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil || len(body) > 64<<10 {
		return nil, errors.New("disk limit inventory is unavailable or oversized")
	}
	var devices []string
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if !blockDeviceID.MatchString(fields[0]) || seen[fields[0]] || len(devices) >= 16 {
			return nil, errors.New("disk limit inventory is ambiguous")
		}
		seen[fields[0]] = true
		devices = append(devices, fields[0])
	}
	return devices, nil
}

// CheckStartup refuses expensive work before pressure reaches a serving app's
// soft threshold. It also reserves the unused portion of other apps' memory.low.
// The host executor serializes startup admission with deployment activation.
func (p HostResources) CheckStartup(app string, resources *ResourcePolicy, parentUsage int64, usage map[string]int64) error {
	if resources == nil || resources.CgroupParent != "/komizo-production/"+app {
		return errors.New("startup requires the installed application allocation")
	}
	if err := p.CheckServingBudget(app, resources); err != nil {
		return err
	}
	group, ok := p.Apps[app]
	current, measured := usage[app]
	if !ok || !measured || current < 0 || parentUsage < current || parentUsage > p.Production.MemoryBytes || resources.StartupAllowanceBytes <= 0 {
		return errors.New("startup requires measured application usage and a positive startup allowance")
	}
	if current > group.MemoryHighBytes-resources.StartupAllowanceBytes {
		return errors.New("application serving pressure refuses startup")
	}
	available := p.Production.MemoryBytes - parentUsage - resources.StartupAllowanceBytes
	var children int64
	for name, other := range p.Apps {
		observed, exists := usage[name]
		if !exists || observed < 0 || observed > other.MemoryBytes {
			return errors.New("application usage is missing or exceeds its installed ceiling")
		}
		children += observed
		if name != app && observed < other.MemoryLowBytes {
			available -= other.MemoryLowBytes - observed
		}
	}
	if children > parentUsage {
		return errors.New("startup usage changed while measuring the application inventory")
	}
	if available < 0 {
		return errors.New("startup would consume another application's serving reserve")
	}
	return nil
}

// CheckServingBudget binds a nested Compose envelope to its installed host
// allocation. Neither a config image nor a second policy may consume another
// application's reserve or exceed the parent's startup-inclusive ceilings.
func (p HostResources) CheckServingBudget(app string, resources *ResourcePolicy) error {
	if resources == nil {
		return errors.New("serving budget is missing")
	}
	if err := resources.Check(); err != nil {
		return err
	}
	if !strings.HasPrefix(resources.CgroupParent, "/komizo-production/") {
		return nil
	}
	if resources.CgroupParent != "/komizo-production/"+app {
		return errors.New("serving budget uses another application's cgroup")
	}
	if err := p.Check(p.PhysicalMemoryBytes, p.PhysicalMilliCPUs); err != nil {
		return err
	}
	group, ok := p.Apps[app]
	if !ok || resources.MaxMemoryReserveBytes != group.MemoryLowBytes {
		return errors.New("serving budget does not fit the installed application reserve and ceilings")
	}
	if resources.AggregateMode == "cgroup" {
		// Compose cannot choose the parent or alter its protected hard limits.
		// Services may share that finite runtime total rather than requiring all
		// their individual admission maxima to be available simultaneously.
		if resources.StartupAllowanceBytes <= 0 || resources.StartupAllowanceBytes > group.MemoryHighBytes-group.MemoryLowBytes {
			return errors.New("startup allowance consumes the application's serving reserve")
		}
		return nil
	}
	if resources.MaxMemoryBytes > group.MemoryBytes || resources.MaxMemorySwapBytes > group.MemoryBytes+group.SwapBytes || resources.MaxMilliCPUs > group.MilliCPUs {
		return errors.New("serving budget does not fit the installed application reserve and ceilings")
	}
	return nil
}
