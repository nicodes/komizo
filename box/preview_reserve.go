package box

import (
	"encoding/json"
	"fmt"
)

// A host budget is meaningful only after production and the shared database
// are reserved. Use total physical RAM, not swappable current free memory.
func previewProductionReserve(k PreviewKnob, report []byte) error {
	if k.ProductionReserve == 0 {
		return nil
	}
	var r struct {
		System struct {
			Mem *struct {
				Total int64 `json:"total"`
			} `json:"mem"`
		} `json:"system"`
	}
	if err := json.Unmarshal(report, &r); err != nil || r.System.Mem == nil || r.System.Mem.Total <= 0 {
		return fmt.Errorf("preview up requires measured physical RAM for PRODUCTION_RESERVE")
	}
	total := r.System.Mem.Total
	if k.MemoryBudget <= 0 || k.DatabaseReserve <= 0 || k.ProductionReserve >= total || k.DatabaseReserve > total-k.ProductionReserve || k.MemoryBudget > total-k.ProductionReserve-k.DatabaseReserve {
		return fmt.Errorf("preview up refused: preview/database budgets would consume the production reserve")
	}
	return nil
}
