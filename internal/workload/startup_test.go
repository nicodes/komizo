package workload

import (
	"os"
	"path/filepath"
	"testing"
)

func startupFixture() (HostResources, ResourcePolicy) {
	g := HostGroup{MemoryBytes: 64 << 20, MilliCPUs: 200, PIDs: 128}
	app := ApplicationGroup{HostGroup: HostGroup{MemoryBytes: 48 << 20, MilliCPUs: 100, PIDs: 32}, BaselineMemoryBytes: 8 << 20, MemoryLowBytes: 16 << 20, MemoryHighBytes: 32 << 20, CPUWeight: 100, IOWeight: 100}
	host := HostResources{Version: 1, PhysicalMemoryBytes: 512 << 20, OSReserveBytes: 128 << 20, PhysicalMilliCPUs: 1000, OSReserveMilliCPUs: 200, Production: g, Proxy: g, Previews: g, PreviewDatabase: g, Apps: map[string]ApplicationGroup{"one": app, "two": app}}
	resources := ResourcePolicy{CgroupParent: "/komizo-production/one", Default: ServiceBudget{MemoryBytes: 32 << 20, MemoryReserveBytes: 16 << 20, MemorySwapBytes: 32 << 20, MilliCPUs: 100}, MaxMemoryBytes: 48 << 20, MaxMemoryReserveBytes: 16 << 20, MaxMemorySwapBytes: 48 << 20, MaxMilliCPUs: 100, StartupAllowanceBytes: 8 << 20}
	return host, resources
}

func TestStartupProtectsServingThresholdAndOtherUnusedReserves(t *testing.T) {
	host, resources := startupFixture()
	for _, tc := range []struct {
		name     string
		parent   int64
		usage    map[string]int64
		accepted bool
	}{
		{"ordinary", 32 << 20, map[string]int64{"one": 16 << 20, "two": 16 << 20}, true},
		{"soft-threshold", 48 << 20, map[string]int64{"one": (24 << 20) + 1, "two": 16 << 20}, false},
		{"unused-reserve", 44 << 20, map[string]int64{"one": 16 << 20, "two": 0}, false},
		{"parent-full", 64 << 20, map[string]int64{"one": 16 << 20, "two": 16 << 20}, false},
		{"missing-other", 16 << 20, map[string]int64{"one": 16 << 20}, false},
		{"changed-inventory", 16 << 20, map[string]int64{"one": 16 << 20, "two": 16 << 20}, false},
		{"invalid-current", 16 << 20, map[string]int64{"one": -1, "two": 0}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if (host.CheckStartup("one", &resources, tc.parent, tc.usage) == nil) != tc.accepted {
				t.Fatal("incorrect admission decision")
			}
		})
	}
	resources.StartupAllowanceBytes = 0
	if host.CheckStartup("one", &resources, 0, map[string]int64{"one": 0, "two": 0}) == nil {
		t.Fatal("unmeasured startup allowance accepted")
	}
}

func TestDiskPolicyRecoveryRemovesPriorRateLimits(t *testing.T) {
	host, _ := startupFixture()
	host.Apps = map[string]ApplicationGroup{"one": host.Apps["one"]}
	app := host.Apps["one"]
	app.IOMax = []DeviceIOBudget{{Device: "8:0", ReadBytesPerSecond: 1 << 20, WriteBytesPerSecond: 1 << 20}}
	host.Apps["one"] = app
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte("cpu memory pids io"), 0600); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(root, "komizo-production")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	for file, value := range map[string]string{"memory.current": "0", "memory.swap.current": "0", "pids.current": "0", "io.weight": "default 100"} {
		if err := os.WriteFile(filepath.Join(parent, file), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := host.Apply(root, 512<<20, 1000); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "komizo-production/one/io.max")
	if body, err := os.ReadFile(path); err != nil || string(body) != "8:0 rbps=1048576 wbps=1048576" {
		t.Fatal("finite rates not applied", string(body), err)
	}
	for name := range host.groups() {
		for _, file := range []string{"memory.current", "memory.swap.current", "pids.current"} {
			if err := os.WriteFile(filepath.Join(root, name, file), []byte("0"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, file := range []string{"memory.current", "memory.swap.current", "pids.current"} {
		if err := os.WriteFile(filepath.Join(root, "komizo-production/one", file), []byte("0"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	app.IOMax = nil
	host.Apps["one"] = app
	if err := host.Apply(root, 512<<20, 1000); err != nil {
		t.Fatal(err)
	}
	if body, err := os.ReadFile(path); err != nil || string(body) != "8:0 rbps=max wbps=max riops=max wiops=max" {
		t.Fatal("recovery retained stale rates", string(body), err)
	}
	if err := os.WriteFile(path, []byte("invalid-device wbps=1"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := host.Apply(root, 512<<20, 1000); err == nil {
		t.Fatal("ambiguous device inventory accepted")
	}
	if body, _ := os.ReadFile(filepath.Join(root, "cgroup.subtree_control")); string(body) != "unchanged" {
		t.Fatal("refusal changed controllers")
	}
}

func TestDiskBudgetsRejectUnboundedOrAmbiguousDevices(t *testing.T) {
	host, _ := startupFixture()
	for _, limits := range [][]DeviceIOBudget{
		{{Device: "8:0", ReadBytesPerSecond: 1 << 20, WriteBytesPerSecond: 1 << 20}},
		{{Device: "8:0", ReadBytesPerSecond: 0, WriteBytesPerSecond: 1 << 20}},
		{{Device: "8:0\nforeign", ReadBytesPerSecond: 1 << 20, WriteBytesPerSecond: 1 << 20}},
		{{Device: "8:0", ReadBytesPerSecond: 1 << 20, WriteBytesPerSecond: 1 << 20}, {Device: "8:0", ReadBytesPerSecond: 1 << 20, WriteBytesPerSecond: 1 << 20}},
	} {
		app := host.Apps["one"]
		app.IOMax = limits
		host.Apps["one"] = app
		if (host.Check(512<<20, 1000) == nil) != (len(limits) == 1 && limits[0].Device == "8:0" && limits[0].ReadBytesPerSecond > 0) {
			t.Fatal("incorrect disk budget validation")
		}
	}
}

func TestCgroupAggregateModeRequiresProtectedRuntimeAllocation(t *testing.T) {
	host, resources := startupFixture()
	resources.MaxMemoryBytes = 128 << 20
	resources.MaxMemorySwapBytes = 256 << 20
	resources.MaxMilliCPUs = 500
	if host.CheckServingBudget("one", &resources) == nil {
		t.Fatal("implicit service overcommit admitted")
	}
	resources.AggregateMode = "cgroup"
	if err := host.CheckServingBudget("one", &resources); err != nil {
		t.Fatal(err)
	}
	// Runtime limits and unused sibling reserves still govern admission.
	if err := host.CheckStartup("one", &resources, 32<<20, map[string]int64{"one": 16 << 20, "two": 16 << 20}); err != nil {
		t.Fatal(err)
	}
	if host.CheckStartup("one", &resources, 44<<20, map[string]int64{"one": 16 << 20, "two": 0}) == nil {
		t.Fatal("runtime sibling reserve bypassed")
	}
	for _, mutate := range []func(*ResourcePolicy){
		func(p *ResourcePolicy) { p.CgroupParent = "/komizo-production" },
		func(p *ResourcePolicy) { p.CgroupParent = "/komizo-production/two" },
		func(p *ResourcePolicy) { p.MaxMemoryReserveBytes++ },
		func(p *ResourcePolicy) { p.StartupAllowanceBytes = 17 << 20 },
		func(p *ResourcePolicy) { p.StartupAllowanceBytes = 0 },
		func(p *ResourcePolicy) { p.AggregateMode = "unknown" },
	} {
		changed := resources
		mutate(&changed)
		if host.CheckServingBudget("one", &changed) == nil {
			t.Fatal("unbound runtime allocation admitted", changed)
		}
	}
	delete(host.Apps, "one")
	if host.CheckServingBudget("one", &resources) == nil {
		t.Fatal("missing installed runtime allocation admitted")
	}
}
