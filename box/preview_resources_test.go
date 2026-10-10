package box

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func previewEnvelopeFixture() *PreviewHostResources {
	return &PreviewHostResources{PhysicalMemoryBytes: 1 << 30, MemoryBytes: 64 << 20, MilliCPUs: 100, ProductionReserveBytes: 736 << 20, DatabaseReserveBytes: 128 << 20}
}

func TestProtectedPreviewEnvelopeCannotBeWidenedByKnobsOrAnotherPreview(t *testing.T) {
	cfg := previewTestConfig(t)
	cfg.HostResources = previewEnvelopeFixture()
	cfg.ReportJSON = []byte(`{"system":{"mem":{"total":1073741824}}}`)
	cfg.Knob, _ = ParsePreviewKnob("MEM_LIMIT=64m\nCPU_LIMIT=0.1\nMEM_BUDGET=1g")
	// Reproduce the physical host's policy presence, which activated the old
	// post-render string rewrite and duplicated the typed parent's YAML key.
	policy := filepath.Join(cfg.Root, "etc", "komizo", "resources.json")
	if err := os.MkdirAll(filepath.Dir(policy), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policy, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	f := &fakeDocker{}
	first, err := PreviewUp(context.Background(), f.run, cfg, "prizm", 1, []string{"gate:head"}, previewNow)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(previewDir(cfg.Root, first.Project), "compose.yml"))
	if err != nil || !strings.Contains(string(body), "cgroup_parent: /komizo-previews") {
		t.Fatalf("preview escaped parent: %v %s", err, body)
	}
	assertPreviewComposeParents(t, filepath.Join(previewDir(cfg.Root, first.Project), "compose.yml"), first.Project, 1)
	f.calls = nil
	if _, err := PreviewUp(context.Background(), f.run, cfg, "prizm", 2, []string{"gate:head"}, previewNow); err == nil || len(f.calls) != 0 {
		t.Fatalf("second preview consumed protected reserve: %v %v", err, f.calls)
	}
	records, err := ListPreviews(cfg.Root)
	if err != nil || len(records) != 1 || records[0].Project != first.Project {
		t.Fatal("budget refusal evicted the original preview")
	}
}

func TestProtectedPreviewEnvelopeRefusesOversizedProfilesAndCPUWithoutDocker(t *testing.T) {
	for _, knob := range []string{"MEM_LIMIT=128m\nCPU_LIMIT=0.1", "MEM_LIMIT=64m\nCPU_LIMIT=0.2"} {
		cfg := previewTestConfig(t)
		cfg.HostResources = previewEnvelopeFixture()
		cfg.ReportJSON = []byte(`{"system":{"mem":{"total":1073741824}}}`)
		cfg.Knob, _ = ParsePreviewKnob(knob)
		f := &fakeDocker{}
		if _, err := PreviewUp(context.Background(), f.run, cfg, "prizm", 1, []string{"gate:head"}, previewNow); err == nil || len(f.calls) != 0 {
			t.Fatalf("oversized preview mutated Docker: %v %v", err, f.calls)
		}
	}
}

func TestRevikEveryPreviewServiceInheritsTheProtectedParent(t *testing.T) {
	cfg := PreviewUpConfig{HostResources: previewEnvelopeFixture()}
	cfg.Knob, _ = ParsePreviewKnob("MEM_LIMIT=64m\nCPU_LIMIT=0.1")
	if err := protectPreviewEnvelope(&cfg); err != nil {
		t.Fatal(err)
	}
	r := PreviewRecord{App: "fieldsofrevik", PR: 1, Project: PreviewProject("fieldsofrevik", 1), Images: revikImages()}
	body := previewCompose(r, cfg.Knob, "edge", false, "")
	if !strings.Contains(body, "x-runtime: &runtime\n  cgroup_parent: /komizo-previews") {
		t.Fatal("Revik runtime escaped protected parent")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "compose.yml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stack.env"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	assertPreviewComposeParents(t, path, r.Project, len(revikPreviewServices))
}

func assertPreviewComposeParents(t *testing.T, path, project string, count int) {
	t.Helper()
	output, err := exec.Command("docker", "compose", "-p", project, "-f", path, "config", "--format", "json").CombinedOutput()
	if err != nil {
		t.Fatalf("real Compose parser rejected protected preview: %v\n%s", err, output)
	}
	var doc struct {
		Services map[string]struct {
			Parent string `json:"cgroup_parent"`
		} `json:"services"`
	}
	if err := json.Unmarshal(output, &doc); err != nil || len(doc.Services) != count {
		t.Fatalf("normalized preview services: %v", err)
	}
	for name, service := range doc.Services {
		if service.Parent != "/komizo-previews" {
			t.Fatalf("normalized service %s escaped its parent", name)
		}
	}
}
