package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	yaml "go.yaml.in/yaml/v3"
	"os"
	"path/filepath"
	"testing"

	"github.com/nicodes/komizo/internal/workload"
)

func TestProxyColdDefaultsAreFiniteAndDeclaredPolicyBindsKernelControllers(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "etc/komizo")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	owner := func(os.FileInfo) bool { return true } // Fixture UID only; production calls workloadRootOwner.
	budget, err := proxyBudget(root, owner)
	if err != nil || budget.MemoryBytes != 96<<20 || budget.TotalSwapBytes != 128<<20 || budget.MilliCPUs != 100 || budget.PIDs != 128 || budget.CgroupParent != "" || budget.PolicySHA256 != nil {
		t.Fatalf("cold defaults: %+v %v", budget, err)
	}
	group := workload.HostGroup{MemoryBytes: 64 << 20, SwapBytes: 32 << 20, MilliCPUs: 100, PIDs: 64}
	host := workload.HostResources{Version: 1, PhysicalMemoryBytes: 512 << 20, OSReserveBytes: 256 << 20, PhysicalMilliCPUs: 1000, OSReserveMilliCPUs: 600, Production: group, Proxy: group, Previews: group, PreviewDatabase: group}
	host.Previews.SwapBytes = 0
	host.PreviewDatabase.SwapBytes = 0
	body, _ := json.Marshal(host)
	path := filepath.Join(dir, "resources.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := proxyBudget(root, owner); err == nil {
		t.Fatal("missing controllers accepted")
	}
	kernel := filepath.Join(root, "sys/fs/cgroup/komizo-proxy")
	if err := os.MkdirAll(kernel, 0700); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"memory.max": "67108864", "memory.swap.max": "33554432", "cpu.max": "10000 100000", "pids.max": "64"} {
		if err := os.WriteFile(filepath.Join(kernel, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	budget, err = proxyBudget(root, owner)
	if err != nil || budget.CgroupParent != "/komizo-proxy" || budget.MemoryBytes != 64<<20 || budget.TotalSwapBytes != 96<<20 || budget.PIDs != 64 || budget.PolicySHA256 == nil || *budget.PolicySHA256 != fmt.Sprintf("%x", sha256.Sum256(body)) {
		t.Fatalf("declared: %+v %v", budget, err)
	}
	if err := os.WriteFile(filepath.Join(kernel, "memory.max"), []byte("max"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := proxyBudget(root, owner); err == nil {
		t.Fatal("drifted unlimited controller accepted")
	}
}

func TestProxyBudgetRefusesUnsafePolicyAndAncestry(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "etc/komizo")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "resources.json")
	owner := func(os.FileInfo) bool { return true }
	for _, body := range []string{"{}", "{} {}", string(make([]byte, workload.MaxBytes+1))} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := proxyBudget(root, owner); err == nil {
			t.Fatal("invalid policy accepted")
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "absent"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := proxyBudget(root, owner); err == nil {
		t.Fatal("dangling policy link accepted as absent")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := proxyBudget(root, owner); err == nil {
		t.Fatal("writable ancestry accepted")
	}
}

func TestProxyComposeRuntimeFitsFiniteMemoryAndParsesAsEnvironment(t *testing.T) {
	b := proxyResourceBudget{MemoryBytes: 60 << 20, TotalSwapBytes: 124 << 20, MilliCPUs: 100, PIDs: 128, CgroupParent: "/komizo-proxy"}
	var doc struct {
		Services map[string]struct {
			Environment map[string]string `yaml:"environment"`
			Memory      int64             `yaml:"mem_limit"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte("services:\n  komizo-proxy:\n"+proxyComposeBudget(b)), &doc); err != nil {
		t.Fatal(err)
	}
	s := doc.Services["komizo-proxy"]
	if s.Environment["GOMEMLIMIT"] != "25165824" || s.Environment["GODEBUG"] != "disablethp=1" || s.Memory != b.MemoryBytes {
		t.Fatalf("rendered budget:%+v", s)
	}
}
