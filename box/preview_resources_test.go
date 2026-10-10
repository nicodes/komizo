package box

import (
	"context"
	"os"
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
	f := &fakeDocker{}
	first, err := PreviewUp(context.Background(), f.run, cfg, "prizm", 1, []string{"gate:head"}, previewNow)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(previewDir(cfg.Root, first.Project), "compose.yml"))
	if err != nil || !strings.Contains(string(body), "cgroup_parent: /komizo-previews") {
		t.Fatalf("preview escaped parent: %v %s", err, body)
	}
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
}
