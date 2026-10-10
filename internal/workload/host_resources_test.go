package workload

import (
	"os"
	"path/filepath"
	"testing"
)

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
