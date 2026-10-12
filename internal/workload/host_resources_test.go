package workload

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplicationReservesRefuseStarvationAndPreserveHostFloor(t *testing.T) {
	g := HostGroup{MemoryBytes: 64 << 20, MilliCPUs: 200, PIDs: 128}
	p := HostResources{Version: 1, PhysicalMemoryBytes: 512 << 20, OSReserveBytes: 128 << 20, PhysicalMilliCPUs: 1000, OSReserveMilliCPUs: 200, Production: g, Proxy: g, Previews: g, PreviewDatabase: g}
	app := ApplicationGroup{HostGroup: HostGroup{MemoryBytes: 48 << 20, MilliCPUs: 100, PIDs: 32}, BaselineMemoryBytes: 8 << 20, MemoryLowBytes: 16 << 20, MemoryHighBytes: 32 << 20, CPUWeight: 100, IOWeight: 100}
	p.Apps = map[string]ApplicationGroup{"one": app, "two": app}
	if err := p.Check(512<<20, 1000); err != nil {
		t.Fatal(err)
	}
	app.MemoryBytes++
	p.Apps["one"] = app
	if p.Check(512<<20, 1000) == nil {
		t.Fatal("one app can exhaust another app's declared reserve")
	}
	app.MemoryBytes--
	app.MemoryLowBytes = app.BaselineMemoryBytes - 1
	p.Apps["one"] = app
	if p.Check(512<<20, 1000) == nil {
		t.Fatal("reserve below measured baseline accepted")
	}
}

func TestResourcePreflightCreatesNoControllersAndRecoveryClearsParentReserve(t *testing.T) {
	g := HostGroup{MemoryBytes: 64 << 20, MilliCPUs: 200, PIDs: 128}
	p := HostResources{Version: 1, PhysicalMemoryBytes: 512 << 20, OSReserveBytes: 128 << 20,
		PhysicalMilliCPUs: 1000, OSReserveMilliCPUs: 200, Production: g, Proxy: g, Previews: g, PreviewDatabase: g}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte("cpu memory pids io"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := p.Preflight(root, 512<<20, 1000); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 {
		t.Fatal("read-only preflight created controller files", entries, err)
	}
	if err := p.Apply(root, 512<<20, 1000); err != nil {
		t.Fatal(err)
	}
	for name := range p.groups() {
		for _, file := range []string{"memory.current", "memory.swap.current", "pids.current"} {
			if err := os.WriteFile(filepath.Join(root, name, file), []byte("0"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	app := ApplicationGroup{HostGroup: HostGroup{MemoryBytes: 32 << 20, MilliCPUs: 100, PIDs: 32},
		BaselineMemoryBytes: 8 << 20, MemoryLowBytes: 16 << 20, MemoryHighBytes: 24 << 20, CPUWeight: 200, IOWeight: 100}
	p.Apps = map[string]ApplicationGroup{"example": app}
	if err := p.Apply(root, 512<<20, 1000); err != nil {
		t.Fatal(err)
	}
	p.Apps = nil
	if err := p.Apply(root, 512<<20, 1000); err != nil {
		t.Fatal(err)
	}
	if body, err := os.ReadFile(filepath.Join(root, "komizo-production", "memory.low")); err != nil || string(body) != "0" {
		t.Fatal("prior layout retained candidate parent reserve", string(body), err)
	}
}

func TestApplicationUsagePreflightIsAtomicAndLimitsAreApplied(t *testing.T) {
	g := HostGroup{MemoryBytes: 64 << 20, MilliCPUs: 200, PIDs: 128}
	app := ApplicationGroup{HostGroup: HostGroup{MemoryBytes: 32 << 20, MilliCPUs: 100, PIDs: 32}, BaselineMemoryBytes: 8 << 20, MemoryLowBytes: 16 << 20, MemoryHighBytes: 24 << 20, CPUWeight: 200, IOWeight: 100}
	p := HostResources{Version: 1, PhysicalMemoryBytes: 512 << 20, OSReserveBytes: 128 << 20, PhysicalMilliCPUs: 1000, OSReserveMilliCPUs: 200, Production: g, Proxy: g, Previews: g, PreviewDatabase: g, Apps: map[string]ApplicationGroup{"one": app}}
	root := t.TempDir()
	write := func(path, value string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "cgroup.controllers"), "cpu memory pids io")
	write(filepath.Join(root, "cgroup.subtree_control"), "unchanged")
	dir := filepath.Join(root, "komizo-production", "one")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"memory.current", "memory.swap.current", "pids.current"} {
		write(filepath.Join(dir, file), "0")
	}
	for _, file := range []string{"memory.current", "memory.swap.current", "pids.current"} {
		write(filepath.Join(root, "komizo-production", file), "0")
	}
	write(filepath.Join(dir, "memory.current"), "33554433")
	if p.Apply(root, 512<<20, 1000) == nil {
		t.Fatal("shrinking below observed use accepted")
	}
	if b, _ := os.ReadFile(filepath.Join(root, "cgroup.subtree_control")); string(b) != "unchanged" {
		t.Fatal("partial mutation before preflight")
	}
	write(filepath.Join(dir, "memory.current"), "0")
	if err := p.Apply(root, 512<<20, 1000); err != nil {
		t.Fatal(err)
	}
	for file, expected := range map[string]string{"memory.low": "16777216", "memory.high": "25165824", "memory.max": "33554432", "cpu.weight": "200", "io.weight": "default 100"} {
		if b, _ := os.ReadFile(filepath.Join(dir, file)); string(b) != expected {
			t.Fatal("missing app limit", file, string(b))
		}
	}
}

func TestHostGroupsCannotBorrowProductionAndOSReservation(t *testing.T) {
	group := HostGroup{MemoryBytes: 64 << 20, MilliCPUs: 200, PIDs: 128}
	p := HostResources{Version: 1, PhysicalMemoryBytes: 512 << 20, OSReserveBytes: 128 << 20, PhysicalMilliCPUs: 1000, OSReserveMilliCPUs: 200, Production: group, Proxy: group, Previews: group, PreviewDatabase: group}
	if err := p.Check(512<<20, 1000); err != nil {
		t.Fatal(err)
	}
	p.Production.MemoryBytes = 320 << 20
	if p.Check(512<<20, 1000) == nil {
		t.Fatal("host overcommit accepted")
	}
	p.Production = group
	p.Previews.SwapBytes = 1
	if p.Check(512<<20, 1000) == nil {
		t.Fatal("preview swap can pressure production")
	}
	p.Previews = group
	if p.Check(511<<20, 1000) == nil {
		t.Fatal("declared physical memory exceeds measured RAM")
	}
	p.Previews.MilliCPUs = 201
	if p.Check(512<<20, 1000) == nil {
		t.Fatal("CPU ceilings consume the OS CPU reserve")
	}
	p.Previews = group
	if p.Check(512<<20, 999) == nil {
		t.Fatal("declared CPU exceeds measured capacity")
	}
}

func TestHostResourceReductionPreflightsEveryUsageBeforeWriting(t *testing.T) {
	for _, fixture := range []struct{ file, value string }{
		{"memory.current", "67108865"},
		{"memory.swap.current", "1"},
		{"pids.current", "129"},
		{"pids.current", "unreadable-value"},
		{"memory.current", "missing"},
	} {
		t.Run(fixture.file+"-"+fixture.value, func(t *testing.T) {
			root := t.TempDir()
			group := HostGroup{MemoryBytes: 64 << 20, MilliCPUs: 200, PIDs: 128}
			p := HostResources{Version: 1, PhysicalMemoryBytes: 512 << 20, OSReserveBytes: 128 << 20,
				PhysicalMilliCPUs: 1000, OSReserveMilliCPUs: 200, Production: group, Proxy: group, Previews: group, PreviewDatabase: group}
			write := func(path, value string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(value), 0600); err != nil {
					t.Fatal(err)
				}
			}
			write(filepath.Join(root, "cgroup.controllers"), "cpu memory pids")
			write(filepath.Join(root, "cgroup.subtree_control"), "unchanged")
			for name := range p.groups() {
				dir := filepath.Join(root, name)
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				for _, file := range []string{"memory.current", "memory.swap.current", "pids.current"} {
					write(filepath.Join(dir, file), "0")
				}
			}
			target := filepath.Join(root, "komizo-production", fixture.file)
			if fixture.value == "missing" {
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				}
			} else {
				write(target, fixture.value)
			}
			if err := p.Apply(root, 512<<20, 1000); err == nil {
				t.Fatal("unsafe reduction accepted")
			}
			if value, err := os.ReadFile(filepath.Join(root, "cgroup.subtree_control")); err != nil || string(value) != "unchanged" {
				t.Fatal("controllers changed before all current usage was accepted")
			}
			for name := range p.groups() {
				if _, err := os.Stat(filepath.Join(root, name, "memory.max")); !os.IsNotExist(err) {
					t.Fatal("partial limits written before preflight")
				}
			}
		})
	}
}

func TestServingBudgetCannotEscapeItsInstalledAllocation(t *testing.T) {
	group := HostGroup{MemoryBytes: 64 << 20, MilliCPUs: 200, PIDs: 128}
	app := ApplicationGroup{HostGroup: HostGroup{MemoryBytes: 48 << 20, SwapBytes: 16 << 20, MilliCPUs: 100, PIDs: 32}, BaselineMemoryBytes: 8 << 20, MemoryLowBytes: 16 << 20, MemoryHighBytes: 32 << 20, CPUWeight: 100, IOWeight: 100}
	host := HostResources{Version: 1, PhysicalMemoryBytes: 512 << 20, OSReserveBytes: 128 << 20, PhysicalMilliCPUs: 1000, OSReserveMilliCPUs: 200, Production: group, Proxy: group, Previews: group, PreviewDatabase: group, Apps: map[string]ApplicationGroup{"one": app}}
	host.Production.SwapBytes = 16 << 20
	budget := ResourcePolicy{CgroupParent: "/komizo-production/one", Default: ServiceBudget{MemoryBytes: 32 << 20, MemoryReserveBytes: 16 << 20, MemorySwapBytes: 32 << 20, MilliCPUs: 50}, MaxMemoryBytes: 48 << 20, MaxMemoryReserveBytes: 16 << 20, MaxMemorySwapBytes: 64 << 20, MaxMilliCPUs: 100, StartupAllowanceBytes: 16 << 20}
	if err := host.CheckServingBudget("one", &budget); err != nil {
		t.Fatal(err)
	}
	for _, alter := range []func(*ResourcePolicy){
		func(p *ResourcePolicy) { p.CgroupParent = "/komizo-production/two" },
		func(p *ResourcePolicy) { p.MaxMemoryReserveBytes++ },
		func(p *ResourcePolicy) { p.MaxMemoryBytes++ },
		func(p *ResourcePolicy) { p.MaxMemorySwapBytes++ },
		func(p *ResourcePolicy) { p.MaxMilliCPUs++ },
	} {
		changed := budget
		alter(&changed)
		if host.CheckServingBudget("one", &changed) == nil {
			t.Fatal("serving allocation escape accepted")
		}
	}
	delete(host.Apps, "one")
	if host.CheckServingBudget("one", &budget) == nil {
		t.Fatal("unregistered application accepted")
	}
}
