package workload

import (
	"os"
	"path/filepath"
	"testing"
)

func controlCacheFixture(t *testing.T) (HostResources, string) {
	t.Helper()
	root := t.TempDir()
	group := HostGroup{MemoryBytes: 64 << 20, MilliCPUs: 200, PIDs: 128}
	p := HostResources{PhysicalMemoryBytes: 512 << 20, OSReserveBytes: 128 << 20, Production: group, Proxy: group, Previews: group, PreviewDatabase: group, Controls: map[string]ControlGroup{}}
	for _, name := range []string{"openrc.docker", "openrc.komizo-rootd", "openrc.komizo-api"} {
		p.Controls[name] = ControlGroup{HostGroup: HostGroup{MemoryBytes: 64 << 20, PIDs: 128}, MemoryLowBytes: 16 << 20, MemoryHighBytes: 48 << 20, CPUWeight: 100}
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		for file, value := range map[string]string{"memory.current": "0", "memory.stat": "inactive_file 67108864\n", "memory.reclaim": "unchanged"} {
			if err := os.WriteFile(filepath.Join(dir, file), []byte(value), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return p, root
}

func TestControlReclaimPreflightsAllBeforeEffects(t *testing.T) {
	p, root := controlCacheFixture(t)
	os.WriteFile(filepath.Join(root, "openrc.docker", "memory.current"), []byte("83886080"), 0600)
	os.WriteFile(filepath.Join(root, "openrc.komizo-rootd", "memory.current"), []byte("83886080"), 0600)
	os.WriteFile(filepath.Join(root, "openrc.komizo-rootd", "memory.stat"), []byte("inactive_file 0\n"), 0600)
	if _, err := p.ReclaimControlCache(root); err == nil {
		t.Fatal("live pages were admitted as cache")
	}
	for name := range p.Controls {
		b, _ := os.ReadFile(filepath.Join(root, name, "memory.reclaim"))
		if string(b) != "unchanged" {
			t.Fatal("partial effects before preflight")
		}
	}
}

func TestControlReclaimIsFiniteAndSkipsHealthyGroups(t *testing.T) {
	p, root := controlCacheFixture(t)
	file := filepath.Join(root, "openrc.docker", "memory.current")
	os.WriteFile(file, []byte("83886080"), 0600)
	rows, err := p.ReclaimControlCache(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[0].Name != "openrc.docker" || rows[0].RequestedBytes != 24<<20 {
		t.Fatal(rows)
	}
	request, _ := os.ReadFile(filepath.Join(root, "openrc.docker", "memory.reclaim"))
	if string(request) != "25165824 swappiness=0" {
		t.Fatal("cache drain must explicitly disable anonymous-memory swapping")
	}
	b, _ := os.ReadFile(filepath.Join(root, "openrc.komizo-rootd", "memory.reclaim"))
	if string(b) != "unchanged" {
		t.Fatal("healthy daemon touched")
	}
	os.WriteFile(filepath.Join(root, "openrc.docker", "memory.reclaim"), []byte("retained"), 0600)
	os.WriteFile(file, []byte("134217729"), 0600)
	if _, err := p.ReclaimControlCache(root); err == nil {
		t.Fatal("unbounded drain admitted")
	}
	b, _ = os.ReadFile(filepath.Join(root, "openrc.docker", "memory.reclaim"))
	if string(b) != "retained" {
		t.Fatal("unreviewed large drain wrote")
	}
}
