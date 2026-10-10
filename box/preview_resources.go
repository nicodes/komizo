package box

import (
	"fmt"
	"math"
	"strconv"
)

// PreviewHostResources is the capacity view supplied by the root CLI after it
// validates the complete private host policy. The box package owns lifecycle
// primitives and does not depend on the higher-level workload policy package.
type PreviewHostResources struct {
	MemoryBytes, MilliCPUs, ProductionReserveBytes, DatabaseReserveBytes, PhysicalMemoryBytes int64
}

func protectPreviewEnvelope(cfg *PreviewUpConfig) error {
	p := cfg.HostResources
	if p == nil {
		return nil
	} // library fixtures; the host CLI requires a policy
	if p.MemoryBytes < 4<<20 || p.MilliCPUs < 1 || p.MilliCPUs > 64000 || p.ProductionReserveBytes < 64<<20 || p.DatabaseReserveBytes < 4<<20 || p.PhysicalMemoryBytes <= 0 || p.ProductionReserveBytes > p.PhysicalMemoryBytes || p.DatabaseReserveBytes > p.PhysicalMemoryBytes-p.ProductionReserveBytes || p.MemoryBytes > p.PhysicalMemoryBytes-p.ProductionReserveBytes-p.DatabaseReserveBytes {
		return fmt.Errorf("preview up refused: invalid protected host resources")
	}
	cpu, err := strconv.ParseFloat(cfg.Knob.CPULimit, 64)
	if err != nil || math.IsNaN(cpu) || math.IsInf(cpu, 0) || cpu <= 0 || math.Ceil(cpu*1000) > float64(p.MilliCPUs) {
		return fmt.Errorf("preview up refused: CPU_LIMIT exceeds the protected preview envelope")
	}
	cfg.Knob.cgroupParent = "/komizo-previews"
	if cfg.Knob.MemoryBudget == 0 || cfg.Knob.MemoryBudget > p.MemoryBytes {
		cfg.Knob.MemoryBudget = p.MemoryBytes
	}
	cfg.Knob.ProductionReserve = max(cfg.Knob.ProductionReserve, p.ProductionReserveBytes)
	cfg.Knob.DatabaseReserve = max(cfg.Knob.DatabaseReserve, p.DatabaseReserveBytes)
	return nil
}
