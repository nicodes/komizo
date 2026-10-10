package workload

import "testing"

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
