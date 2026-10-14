package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/nicodes/komizo/internal/workload"
)

type proxyResourceBudget struct {
	Version        int     `json:"version"`
	MemoryBytes    int64   `json:"memory_bytes"`
	TotalSwapBytes int64   `json:"total_memory_swap_bytes"`
	MilliCPUs      int64   `json:"milli_cpus"`
	PIDs           int64   `json:"pids"`
	CgroupParent   string  `json:"cgroup_parent"`
	PolicySHA256   *string `json:"policy_sha256"`
}

func proxyBudget(root string, owner func(os.FileInfo) bool) (proxyResourceBudget, error) {
	budget := proxyResourceBudget{Version: 1, MemoryBytes: 96 << 20, TotalSwapBytes: 128 << 20, MilliCPUs: 100, PIDs: 128}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return budget, errors.New("proxy budget root is not canonical")
	}
	path := filepath.Join(root, "etc/komizo/resources.json")
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || !owner(info) {
			return budget, errors.New("proxy resources require protected ancestry")
		}
		if parent == root {
			break
		}
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return budget, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || !owner(info) || info.Size() > workload.MaxBytes {
		return budget, errors.New("proxy resource policy is not private and bounded")
	}
	body, err := os.ReadFile(path)
	if err != nil || len(body) > workload.MaxBytes {
		return budget, errors.New("proxy resource policy unavailable")
	}
	var host workload.HostResources
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&host); err != nil {
		return budget, errors.New("invalid proxy resource policy")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return budget, errors.New("one proxy resource policy is required")
	}
	memory, err := hostMemoryBytes()
	if err != nil {
		return budget, err
	}
	if err := host.Check(memory, int64(runtime.NumCPU())*1000); err != nil {
		return budget, err
	}
	group := host.Proxy
	expected := map[string]string{"memory.max": fmt.Sprint(group.MemoryBytes), "memory.swap.max": fmt.Sprint(group.SwapBytes), "cpu.max": fmt.Sprintf("%d 100000", group.MilliCPUs*100), "pids.max": fmt.Sprint(group.PIDs)}
	for name, wanted := range expected {
		body, err := os.ReadFile(filepath.Join(root, "sys/fs/cgroup/komizo-proxy", name))
		if err != nil || len(body) > 64 || strings.Join(strings.Fields(string(body)), " ") != wanted {
			return budget, errors.New("proxy resource controllers drifted; apply reviewed host resources first")
		}
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(body))
	return proxyResourceBudget{Version: 1, MemoryBytes: group.MemoryBytes, TotalSwapBytes: group.MemoryBytes + group.SwapBytes, MilliCPUs: group.MilliCPUs, PIDs: group.PIDs, CgroupParent: "/komizo-proxy", PolicySHA256: &sum}, nil
}

func runProxyBudget(args []string) error {
	if os.Geteuid() != 0 || len(args) > 1 || len(args) == 1 && args[0] != "--compose" {
		return errors.New("proxy budget requires the root operator and optional --compose")
	}
	budget, err := proxyBudget("/", workloadRootOwner)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return json.NewEncoder(os.Stdout).Encode(budget)
	}
	_, err = io.WriteString(os.Stdout, proxyComposeBudget(budget))
	return err
}

func proxyComposeBudget(budget proxyResourceBudget) string {
	var output strings.Builder
	fmt.Fprintf(&output, "    mem_limit: %d\n    memswap_limit: %d\n    cpus: \"%d.%03d\"\n    pids_limit: %d\n", budget.MemoryBytes, budget.TotalSwapBytes, budget.MilliCPUs/1000, budget.MilliCPUs%1000, budget.PIDs)
	soft := budget.MemoryBytes * 2 / 5
	if soft < 8<<20 {
		soft = 8 << 20
	}
	fmt.Fprintf(&output, "    environment:\n      GOMEMLIMIT: \"%d\"\n      GODEBUG: disablethp=1\n", soft)
	if budget.CgroupParent != "" {
		fmt.Fprintf(&output, "    cgroup_parent: %s\n", budget.CgroupParent)
	}
	return output.String()
}
