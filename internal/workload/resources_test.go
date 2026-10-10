package workload

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestResourceDefaultsBelongToHost(t *testing.T) {
	p := testPolicy(t)
	result, err := Validate(strings.NewReader(basic), p, "commit123")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services map[string]struct {
			Memory int64   `json:"mem_limit"`
			Swap   int64   `json:"memswap_limit"`
			CPUs   float64 `json:"cpus"`
		} `json:"services"`
	}
	if err := json.Unmarshal(result, &doc); err != nil {
		t.Fatal(err)
	}
	for _, service := range doc.Services {
		if service.Memory != 128<<20 || service.Swap != service.Memory || service.CPUs != .5 {
			t.Fatalf("unbounded default: %+v", service)
		}
	}
	p.Resources = nil
	if _, err := Validate(strings.NewReader(basic), p, "commit123"); err == nil {
		t.Fatal("missing protected envelope accepted")
	}
}

func TestUntrustedResourceRequestsCannotWidenBudgets(t *testing.T) {
	for _, request := range []string{"mem_limit: 0", "mem_limit: 100g", "mem_limit: 999999999999999999999g", "mem_limit: -1", "memswap_limit: -1", "memswap_limit: 1m", "memswap_limit: 129m", "cpus: 100", "cpus: 0", "cpus: .nan", "cpus: 0.501"} {
		input := "services:\n  api:\n    image: ghcr.io/owner/example-api:commit123\n    " + request + "\n"
		if _, err := Validate(strings.NewReader(input), testPolicy(t), "commit123"); err == nil {
			t.Errorf("accepted %s", request)
		}
	}
}

func TestDeploymentAggregateCountsMigrationAndHeadroom(t *testing.T) {
	p := testPolicy(t)
	p.Resources.MaxMemoryBytes = 256 << 20
	p.Resources.MaxMemorySwapBytes = 256 << 20
	p.Resources.StartupAllowanceBytes = 1
	if _, err := Validate(strings.NewReader(basic), p, "commit123"); err == nil {
		t.Fatal("startup allowance ignored")
	}
	p.Resources.StartupAllowanceBytes = 0
	if _, err := Validate(strings.NewReader(basic), p, "commit123"); err != nil {
		t.Fatal(err)
	}
	input := strings.Replace(basic, "  api:\n", "  migration:\n    image: ghcr.io/owner/example-api:commit123\n    profiles: [migration]\n  api:\n", 1)
	if _, err := Validate(strings.NewReader(input), p, "commit123"); err == nil {
		t.Fatal("migration demand ignored")
	}
}
