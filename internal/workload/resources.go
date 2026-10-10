package workload

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// All ceilings are selected by the operator, never by a config image. Memory
// swap is the total RAM+swap ceiling, matching Docker's memswap_limit. Equal
// values disable swap. Aggregate ceilings include every service, including
// migration/profile services, and a separate image/startup allowance.
type ResourcePolicy struct {
	CgroupParent          string                   `json:"cgroup_parent,omitempty"`
	Default               ServiceBudget            `json:"default"`
	Services              map[string]ServiceBudget `json:"services,omitempty"`
	MaxMemoryBytes        int64                    `json:"max_memory_bytes"`
	MaxMemorySwapBytes    int64                    `json:"max_memory_swap_bytes"`
	MaxMilliCPUs          int64                    `json:"max_milli_cpus"`
	StartupAllowanceBytes int64                    `json:"startup_allowance_bytes"`
}

type ServiceBudget struct {
	MemoryBytes     int64 `json:"memory_bytes"`
	MemorySwapBytes int64 `json:"memory_swap_bytes"`
	MilliCPUs       int64 `json:"milli_cpus"`
}

func (b ServiceBudget) check() error {
	if b.MemoryBytes < 4<<20 || b.MemoryBytes > 64<<30 || b.MemorySwapBytes < b.MemoryBytes || b.MemorySwapBytes > 128<<30 || b.MilliCPUs < 1 || b.MilliCPUs > 64000 {
		return errors.New("service budget requires finite memory, CPU and explicit bounded swap")
	}
	return nil
}

func (p ResourcePolicy) Check() error {
	if p.CgroupParent != "" && p.CgroupParent != "/komizo-production" {
		return errors.New("production cgroup must be host owned")
	}
	if err := p.Default.check(); err != nil {
		return err
	}
	if p.MaxMemoryBytes < p.Default.MemoryBytes || p.MaxMemoryBytes > 128<<30 || p.MaxMemorySwapBytes < p.MaxMemoryBytes || p.MaxMemorySwapBytes > 256<<30 || p.MaxMilliCPUs < p.Default.MilliCPUs || p.MaxMilliCPUs > 128000 || p.StartupAllowanceBytes < 0 || p.StartupAllowanceBytes > p.MaxMemoryBytes || len(p.Services) > 32 {
		return errors.New("invalid aggregate resource envelope")
	}
	for name, budget := range p.Services {
		if !identifier.MatchString(name) {
			return errors.New("invalid service budget name")
		}
		if err := budget.check(); err != nil {
			return err
		}
	}
	return nil
}

var memoryAmount = regexp.MustCompile(`^([0-9]+)([bkmgBKMG]?)$`)

func memoryBytes(raw any) (int64, error) {
	match := memoryAmount.FindStringSubmatch(fmt.Sprint(raw))
	if match == nil {
		return 0, errors.New("memory must be positive whole bytes or b/k/m/g units")
	}
	n, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil || n <= 0 {
		return 0, errors.New("memory must be finite and positive")
	}
	scale := int64(1)
	switch strings.ToLower(match[2]) {
	case "k":
		scale = 1 << 10
	case "m":
		scale = 1 << 20
	case "g":
		scale = 1 << 30
	}
	if n > math.MaxInt64/scale {
		return 0, errors.New("memory amount overflow")
	}
	return n * scale, nil
}

func boundResources(services map[string]any, policy *ResourcePolicy) error {
	if policy == nil {
		return errors.New("operator must configure a protected resource envelope before deployment")
	}
	var memory, swap, cpus int64
	for name, raw := range services {
		service := raw.(map[string]any)
		if policy.CgroupParent != "" {
			service["cgroup_parent"] = policy.CgroupParent
		}
		budget := policy.Default
		if override, ok := policy.Services[name]; ok {
			budget = override
		}
		m, ms, cpu, err := boundServiceResources(service, budget)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		memory += m
		swap += ms
		cpus += cpu
	}
	if memory+policy.StartupAllowanceBytes > policy.MaxMemoryBytes || swap+policy.StartupAllowanceBytes > policy.MaxMemorySwapBytes || cpus > policy.MaxMilliCPUs {
		return errors.New("aggregate deployment resource demand exceeds protected envelope")
	}
	return nil
}

func boundServiceResources(service map[string]any, budget ServiceBudget) (int64, int64, int64, error) {
	memory, swap, cpus := budget.MemoryBytes, budget.MemorySwapBytes, budget.MilliCPUs
	var err error
	if raw, ok := service["mem_limit"]; ok {
		memory, err = memoryBytes(raw)
		if err != nil {
			return 0, 0, 0, err
		}
	}
	if raw, ok := service["memswap_limit"]; ok {
		swap, err = memoryBytes(raw)
		if err != nil {
			return 0, 0, 0, err
		}
	}
	if raw, ok := service["cpus"]; ok {
		value, e := strconv.ParseFloat(fmt.Sprint(raw), 64)
		if e != nil || math.IsNaN(value) || math.IsInf(value, 0) || value <= 0 || value > 64 {
			return 0, 0, 0, errors.New("CPU quota must be finite and positive")
		}
		cpus = int64(math.Ceil(value * 1000))
	}
	if memory > budget.MemoryBytes || swap > budget.MemorySwapBytes || swap < memory || cpus > budget.MilliCPUs {
		return 0, 0, 0, errors.New("service resource demand exceeds protected budget")
	}
	service["mem_limit"] = memory
	service["memswap_limit"] = swap
	service["cpus"] = float64(cpus) / 1000
	return memory, swap, cpus, nil
}
