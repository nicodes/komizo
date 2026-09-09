package release

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCandidateUsesUniqueNamesAndPrivateNetwork(t *testing.T) {
	f := modelFixture()
	f["name"] = "app"
	f["networks"].(map[string]any)["private"] = map[string]any{"internal": true, "name": "app-private"}
	fixtureService(f, "ui")["depends_on"] = map[string]any{"api": map[string]any{"condition": "service_started"}}
	model := resolveFixture(t, f)
	data, err := model.CandidateCompose("ui", "kmz-unique", "app", "app-private", map[string]string{"io.komizo.app": "app"})
	if err != nil {
		t.Fatal(err)
	}
	var candidate map[string]any
	if err := json.Unmarshal(data, &candidate); err != nil {
		t.Fatal(err)
	}
	services := candidate["services"].(map[string]any)
	if len(services) != 1 || services["ui"] != nil {
		t.Fatal("candidate retained colliding logical service alias")
	}
	service := services["kmz-unique"].(map[string]any)
	if service["container_name"] != "kmz-unique" || service["depends_on"] != nil {
		t.Fatal("candidate has uncontrolled identity or dependency startup")
	}
	network := candidate["networks"].(map[string]any)["private"].(map[string]any)
	if network["external"] != true || network["name"] != "app-private" {
		t.Fatal("candidate would create or use another network")
	}
	// Re-rendering must not have modified the source service.
	if _, err := model.CandidateCompose("ui", "kmz-another", "app", "app-private", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := model.CandidateCompose("ui", "kmz-x", "other", "app-private", nil); err == nil {
		t.Fatal("cross-app rendering accepted")
	}
	if _, err := model.CandidateCompose("ui", "kmz-x", "app", "other", nil); err == nil {
		t.Fatal("cross-network rendering accepted")
	}
}

func TestCandidateRefusesImplicitVolumeCreation(t *testing.T) {
	f := modelFixture()
	f["name"] = "app"
	f["networks"].(map[string]any)["private"] = map[string]any{"name": "app-private"}
	f["volumes"] = map[string]any{"files": map[string]any{"name": "app-files"}}
	fixtureService(f, "api")["volumes"] = []any{map[string]any{"type": "volume", "source": "files", "target": "/files", "read_only": true}}
	model := resolveFixture(t, f)
	if _, err := model.CandidateCompose("api", "kmz-x", "app", "app-private", nil); err == nil {
		t.Fatal("candidate could silently create empty data volume")
	}
	f["volumes"].(map[string]any)["files"].(map[string]any)["external"] = true
	model = resolveFixture(t, f)
	if _, err := model.CandidateCompose("api", "kmz-x", "app", "app-private", nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(model.GoString(), "app-files") {
		t.Fatal("debug rendering exposes private configuration")
	}
}

func TestConcurrentVolumeNeedsExplicitMatchingCapability(t *testing.T) {
	f := modelFixture()
	f["name"] = "app"
	f["networks"].(map[string]any)["private"] = map[string]any{"name": "app-private"}
	f["volumes"] = map[string]any{"files": map[string]any{"name": "app-files", "external": true}}
	fixtureService(f, "api")["volumes"] = []any{map[string]any{"type": "volume", "source": "files", "target": "/data"}}
	fixturePolicy(f, "api")["concurrent_volumes"] = []any{"files"}
	model := resolveFixture(t, f)
	if _, err := model.CandidateCompose("api", "kmz-unique", "app", "app-private", nil); err != nil {
		t.Fatal(err)
	}
	fixturePolicy(f, "api")["concurrent_volumes"] = []any{"other"}
	data, _ := json.Marshal(f)
	if _, err := Resolve(data, make([]byte, 32)); err == nil {
		t.Fatal("unmatched concurrent-writer declaration accepted")
	}
}
