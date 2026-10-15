package workload

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sshControlsFixture() HostResources {
	p, _ := startupFixture()
	p.OSReserveBytes = 144 << 20
	p.Controls = map[string]ControlGroup{}
	for _, name := range []string{"openrc.docker", "openrc.komizo-rootd", "openrc.komizo-api", "openrc.sshd"} {
		p.Controls[name] = ControlGroup{HostGroup: HostGroup{MemoryBytes: 64 << 20, PIDs: 128}, MemoryLowBytes: 16 << 20, MemoryHighBytes: 48 << 20, CPUWeight: 100}
	}
	return p
}

func recoveryControlsRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte("cpu memory pids io"), 0600)
	os.Mkdir(filepath.Join(root, "komizo-production"), 0700)
	os.WriteFile(filepath.Join(root, "komizo-production/io.weight"), []byte("default 100"), 0600)
	for _, key := range []string{"memory.current", "memory.swap.current", "pids.current"} {
		os.WriteFile(filepath.Join(root, "komizo-production", key), []byte("0"), 0600)
	}
	return root
}

func TestSSHReserveFitsTheOSAndRequiresEveryExistingControl(t *testing.T) {
	p := sshControlsFixture()
	if err := p.Check(512<<20, 1000); err != nil {
		t.Fatal(err)
	}
	p.OSReserveBytes = 127 << 20
	if p.Check(512<<20, 1000) == nil {
		t.Fatal("SSH reserve borrowed base OS memory")
	}
	p.OSReserveBytes = 144 << 20
	delete(p.Controls, "openrc.komizo-api")
	if p.Check(512<<20, 1000) == nil {
		t.Fatal("SSH replaced a required control")
	}
}

func TestSSHControlsRestoreOpenRCDefaultsOnPolicyRecovery(t *testing.T) {
	p := sshControlsFixture()
	root := recoveryControlsRoot(t)
	if err := p.Apply(root, 512<<20, 1000); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "openrc.sshd")
	if b, _ := os.ReadFile(filepath.Join(dir, "memory.low")); string(b) != "16777216" {
		t.Fatal("recovery SSH reserve missing")
	}
	var dirs []string
	for name := range p.Controls {
		dirs = append(dirs, filepath.Join(root, name))
	}
	for name := range p.groups() {
		dirs = append(dirs, filepath.Join(root, name))
	}
	for name := range p.Apps {
		dirs = append(dirs, filepath.Join(root, "komizo-production", name))
	}
	for _, d := range dirs {
		for _, key := range []string{"memory.current", "memory.swap.current", "pids.current"} {
			os.WriteFile(filepath.Join(d, key), []byte("0"), 0600)
		}
	}
	delete(p.Controls, "openrc.sshd")
	if err := p.Apply(root, 512<<20, 1000); err != nil {
		t.Fatal(err)
	}
	for key, expected := range map[string]string{"memory.low": "0", "memory.high": "max", "memory.max": "max", "memory.swap.max": "max", "pids.max": "max", "cpu.max": "max 100000"} {
		if b, _ := os.ReadFile(filepath.Join(dir, key)); string(b) != expected {
			t.Fatalf("stale SSH %s limit: %s", key, b)
		}
	}
}

func TestIOPSBudgetsAreBoundedAndApplied(t *testing.T) {
	p, _ := startupFixture()
	app := p.Apps["one"]
	app.IOMax = []DeviceIOBudget{{Device: "8:0", ReadBytesPerSecond: 16 << 20, WriteBytesPerSecond: 8 << 20, ReadIOPS: 1024, WriteIOPS: 256}}
	p.Apps["one"] = app
	root := recoveryControlsRoot(t)
	if err := p.Apply(root, 512<<20, 1000); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(root, "komizo-production/one/io.max"))
	if !strings.Contains(string(b), "riops=1024 wiops=256") {
		t.Fatal("operation limits missing", string(b))
	}
	for _, bad := range []int64{-1, 1000001} {
		app.IOMax[0].ReadIOPS = bad
		p.Apps["one"] = app
		if p.Check(512<<20, 1000) == nil {
			t.Fatal("invalid read operation rate admitted")
		}
		app.IOMax[0].ReadIOPS = 0
		app.IOMax[0].WriteIOPS = bad
		p.Apps["one"] = app
		if p.Check(512<<20, 1000) == nil {
			t.Fatal("invalid write operation rate admitted")
		}
	}
}
