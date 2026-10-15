package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
	if op.Phase != "staging_failed" || op.ID != f.r.ID || op.Candidate != f.r.Candidate || op.Previous != f.r.Previous {
		t.Fatal("refusal lost its durable terminal identity", op)
	}
	if _, err := os.Lstat(filepath.Dir(deploymentCredentialPath(f.queue, f.r.ID))); !os.IsNotExist(err) {
		t.Fatal("serving-pressure refusal retained credential slot", err)
	}
}

// A login shell must not supply or conceal kernel usage through its cwd. A
// uniquely named application has no real kernel leaf, even when the caller
// plants an apparently matching relative hierarchy.
func TestStartupUsageIgnoresLoginDirectory(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	app := "startup-cwd-" + filepath.Base(cwd)
	dir := filepath.Join(cwd, "sys/fs/cgroup/komizo-production", app)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(filepath.Dir(dir), "memory.current"), filepath.Join(dir, "memory.current")} {
		if err := os.WriteFile(path, []byte("invalid relative usage\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	host, err := json.Marshal(workload.HostResources{Apps: map[string]workload.ApplicationGroup{app: {}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{"", "/"} {
		h := newHostActivation()
		h.root = root
		h.readBytes = func(path string) ([]byte, error) {
			if path != "/etc/komizo/resources.json" {
				t.Fatalf("relative installed policy path: %s", path)
			}
			return host, nil
		}
		p := workload.Policy{App: app, Resources: &workload.ResourcePolicy{CgroupParent: "/komizo-production/" + app}}
		err := h.startupCapacity(p)
		if err == nil || err.Error() != "current startup usage is unavailable" {
			t.Fatalf("root %q: relative caller data affected startup: %v", root, err)
		}
	}
}

func TestReadOnlyStartupInspectionNeverRunsLifecycleEvenWhenAdmitted(t *testing.T) {
	f := newDeploymentFixture(t)
	original := lookupRoot
	lookupRoot = f.h.root
	t.Cleanup(func() { lookupRoot = original })
	path := filepath.Join(f.h.root, workloadPolicyDirectory, "example.json")
	var p workload.Policy
	if err := f.h.readJSON(filepath.Join(f.h.policies, "example.json"), &p); err != nil {
		t.Fatal(err)
	}
	p.Resources.CgroupParent = "/komizo-production/example"
	p.Resources.MaxMemoryReserveBytes = 32 << 20
	p.Resources.Default.MemoryReserveBytes = 32 << 20
	p.Resources.StartupAllowanceBytes = 8 << 20
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := workload.WritePrivateJSON(path, p); err != nil {
		t.Fatal(err)
	}
	g := workload.HostGroup{MemoryBytes: 256 << 20, MilliCPUs: 1000, PIDs: 128}
	app := workload.ApplicationGroup{HostGroup: workload.HostGroup{MemoryBytes: 128 << 20, MilliCPUs: 1000, PIDs: 128}, BaselineMemoryBytes: 16 << 20, MemoryLowBytes: 32 << 20, MemoryHighBytes: 96 << 20, CPUWeight: 100, IOWeight: 100}
	host := workload.HostResources{Version: 1, PhysicalMemoryBytes: 1280 << 20, OSReserveBytes: 256 << 20, PhysicalMilliCPUs: 5000, OSReserveMilliCPUs: 1000, Production: g, Proxy: g, Previews: g, PreviewDatabase: g, Apps: map[string]workload.ApplicationGroup{"example": app}}
	if err := workload.WritePrivateJSON(filepath.Join(f.h.root, "etc/komizo/resources.json"), host); err != nil {
		t.Fatal(err)
	}
	originalPolicy, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, usage := range []string{"16777216", "100663296", "0"} {
		for _, name := range []string{"", "example"} {
			dir := filepath.Join(f.h.root, "sys/fs/cgroup/komizo-production", name)
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "memory.current"), []byte(usage), 0600); err != nil {
				t.Fatal(err)
			}
		}
		var err error
		if os.Geteuid() == 0 {
			err = runWorkload([]string{"startup-check", "--policy", path})
		} else {
			// Hosted CI is unprivileged: prove the public boundary refuses, then
			// exercise shared admission with the fixture's explicit owner seam.
			if denied := runWorkload([]string{"startup-check", "--policy", path}); denied == nil || !strings.Contains(denied.Error(), "root operator") {
				t.Fatalf("unprivileged startup inspection accepted: %v", denied)
			}
			err = f.h.startupCapacity(p)
		}
		if (err != nil) != (usage == "100663296") {
			t.Fatalf("usage%s: %v", usage, err)
		}
		now, err := os.ReadFile(path)
		if err != nil || string(now) != string(originalPolicy) {
			t.Fatal("inspection changed policy", err)
		}
		if len(f.calls) != 0 {
			t.Fatal("inspection called Docker", f.calls)
		}
	}
	for _, args := range [][]string{{"--policy", path, "--restart"}, {"--policy", path, "extra"}, {"--policy", filepath.Join(f.h.root, "foreign.json")}} {
		if err := runWorkloadStartupCheck(args); err == nil {
			t.Fatalf("invalid inspection accepted %v", args)
		}
	}
}
