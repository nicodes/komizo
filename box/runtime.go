package box

import (
	"encoding/json"
	"github.com/nicodes/komizo/internal/servicehealth"
	"io"
	"os"
	"path/filepath"
)

// Read only the root-validated desired runtime projection. Legacy YAML or an
// unavailable configuration cannot establish required-service health.
func (p *Probe) runtimeState(app App) string {
	if app.Stopped {
		return "stopped"
	}
	if app.Static != nil {
		if app.Static.Active {
			return "running"
		}
		return "down"
	}
	f, err := os.Open(p.path(filepath.Join(app.Dir, "compose.yml")))
	if err != nil {
		return "unknown"
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return "unknown"
	}
	var doc struct {
		Services map[string]servicehealth.Desired `json:"services"`
	}
	if json.Unmarshal(body, &doc) != nil || len(doc.Services) == 0 || len(doc.Services) > 32 {
		return "unknown"
	}
	containers := map[string]Container{}
	for _, c := range app.Containers {
		if _, exists := containers[c.Service]; exists {
			return "degraded"
		}
		containers[c.Service] = c
	}
	ready, missing, running := 0, 0, 0
	for name, service := range doc.Services {
		c, exists := containers[name]
		if !exists && len(service.Profiles) > 0 {
			continue
		}
		if c.State == "running" {
			running++
		}
		if exists && servicehealth.Ready(service, c.State, c.ExitCode, c.Health) {
			ready++
		} else {
			missing++
		}
	}
	if missing > 0 {
		if ready > 0 || running > 0 {
			return "degraded"
		}
		return "down"
	}
	if ready == 0 {
		return "unknown"
	}
	if running == 0 {
		return "completed"
	}
	return "running"
}
