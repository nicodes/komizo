package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nicodes/komizo/internal/workload"
)

func TestServingPressureRefusesBeforeRegistryOrConfigurationEffects(t *testing.T) {
	f := newDeploymentFixture(t)
	policyPath := filepath.Join(f.h.policies, "example.json")
	var p workload.Policy
	if err := f.h.readJSON(policyPath, &p); err != nil {
		t.Fatal(err)
	}
	g := workload.HostGroup{MemoryBytes: 256 << 20, MilliCPUs: 1000, PIDs: 128}
	app := workload.ApplicationGroup{HostGroup: workload.HostGroup{MemoryBytes: 128 << 20, MilliCPUs: 1000, PIDs: 128}, BaselineMemoryBytes: 16 << 20, MemoryLowBytes: 32 << 20, MemoryHighBytes: 96 << 20, CPUWeight: 100, IOWeight: 100}
	host := workload.HostResources{Version: 1, PhysicalMemoryBytes: 1280 << 20, OSReserveBytes: 256 << 20, PhysicalMilliCPUs: 5000, OSReserveMilliCPUs: 1000, Production: g, Proxy: g, Previews: g, PreviewDatabase: g, Apps: map[string]workload.ApplicationGroup{"example": app}}
	p.Resources.CgroupParent = "/komizo-production/example"
	p.Resources.MaxMemoryReserveBytes = 32 << 20
	p.Resources.Default.MemoryReserveBytes = 32 << 20
	p.Resources.StartupAllowanceBytes = 8 << 20
	if err := workload.WritePrivateJSON(policyPath, p); err != nil {
		t.Fatal(err)
	}
	if err := workload.WritePrivateJSON(filepath.Join(f.h.root, "etc/komizo/resources.json"), host); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "example"} {
		dir := filepath.Join(f.h.root, "sys/fs/cgroup/komizo-production", name)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "memory.current"), []byte("100663296"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	body, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	f.r.PolicySHA256 = deploymentHash(body)
	if _, err := f.h.stageDeployment(t.Context(), f.r, f.queue); err == nil {
		t.Fatal("serving pressure admitted")
	}
	if len(f.calls) != 0 {
		t.Fatal("refusal performed a Docker operation", f.calls)
	}
	op, err := f.h.operation(f.r)
	if err != nil {
		t.Fatal(err)
	}
	if op.Phase != "admitted" {
		t.Fatal("refusal changed operation phase", op.Phase)
	}
}
