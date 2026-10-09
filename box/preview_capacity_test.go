package box

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPreviewLimitsCannotDisableCgroupsOrInjectCompose(t *testing.T) {
	for _, value := range []string{"0", "-1", "unlimited", "1e99", "512m # ignored", "999999999999999999999999g"} {
		knob, note := ParsePreviewKnob("MEM_LIMIT=" + value + "\nCPU_LIMIT=" + value)
		if knob.MemLimit != PreviewMemLimitDefault || knob.CPULimit != PreviewCPULimitDefault || note == "" {
			t.Fatalf("invalid limits were accepted: %+v", knob)
		}
	}
	for _, value := range []string{"0", "NaN", ".inf", "1e3", "-1"} {
		if validPreviewCPU(value) {
			t.Fatalf("unbounded or invalid CPU accepted: %s", value)
		}
	}
	knob, note := ParsePreviewKnob("MEM_LIMIT=256m\nCPU_LIMIT=0.5\nMEM_BUDGET=1g")
	if note != "" || knob.MemLimit != "256m" || knob.CPULimit != "0.5" || knob.MemoryBudget != 1<<30 {
		t.Fatalf("valid limits were refused: %+v %s", knob, note)
	}
}

func TestPreviewServiceLimitsMatchAdmissionAndDoNotAllowSwapGrowth(t *testing.T) {
	knob, _ := ParsePreviewKnob("MEM_LIMIT=64m\nMEM_LIMIT.fieldsofrevik.api=32m\nMEM_LIMIT.fieldsofrevik.migrate=32m\nMEM_LIMIT.fieldsofrevik.godot-api=160m\nMEM_LIMIT.prizm=96m")
	reserved, err := previewMemoryReservation(knob, "fieldsofrevik", 4)
	if err != nil || reserved != 416<<20 {
		t.Fatalf("Revik reservation: %d %v", reserved, err)
	}
	reserved, err = previewMemoryReservation(knob, "prizm", 1)
	if err != nil || reserved != 96<<20 {
		t.Fatalf("app reservation: %d %v", reserved, err)
	}
	for _, app := range []string{"prizm", "fieldsofrevik"} {
		r := PreviewRecord{App: app, PR: 1, Project: PreviewProject(app, 1), Images: []string{"gate:head"}}
		if app == "fieldsofrevik" {
			r.Images = revikImages()
		}
		body := previewCompose(r, knob, "edge", false, "")
		if app == "fieldsofrevik" {
			for _, service := range revikPreviewServices {
				limit := previewServiceMemory(knob, app, service)
				if !strings.Contains(body, "mem_limit: "+limit+"\n    memswap_limit: "+limit) {
					t.Fatalf("missing enforced service limit: %s", service)
				}
			}
		} else if !strings.Contains(body, "mem_limit: 96m\n    memswap_limit: 96m") {
			t.Fatal("app override was not enforced")
		}
		if !strings.Contains(body, "cpu_shares: 128") {
			t.Fatal("preview has default production CPU priority")
		}
	}
}

func TestPreviewInvalidAppLimitRefusesBeforeMutation(t *testing.T) {
	for _, value := range []string{"0", "unlimited", "32m\"", "999999999999999999g"} {
		cfg := previewTestConfig(t)
		cfg.Knob, _ = ParsePreviewKnob("MEM_LIMIT.prizm=" + value)
		f := &fakeDocker{}
		if _, err := PreviewUp(context.Background(), f.run, cfg, "prizm", 1, []string{"gate:head"}, previewNow); err == nil || len(f.calls) != 0 {
			t.Fatalf("invalid app limit performed work: %s %v", value, err)
		}
		knob, _ := ParsePreviewKnob("MEM_LIMIT.fieldsofrevik.godot-api=" + value)
		if _, err := previewMemoryReservation(knob, "fieldsofrevik", 4); err == nil {
			t.Fatalf("invalid Revik override accepted: %s", value)
		}
	}
}

func TestPreviewBudgetRefusalPreservesExistingResources(t *testing.T) {
	cfg := previewTestConfig(t)
	cfg.Knob.MemoryBudget = 768 << 20
	f := &fakeDocker{}
	first, err := PreviewUp(context.Background(), f.run, cfg, "prizm", 1, []string{"gate:head"}, previewNow)
	if err != nil || first.MemoryReservedBytes != 512<<20 {
		t.Fatalf("first admission: %+v %v", first, err)
	}
	f.calls = nil
	_, err = PreviewUp(context.Background(), f.run, cfg, "prizm", 2, []string{"gate:head"}, previewNow)
	if err == nil || !strings.Contains(err.Error(), "MEM_BUDGET") || len(f.calls) != 0 {
		t.Fatalf("over-budget preview mutated Docker: %v %v", err, f.calls)
	}
	records, err := ListPreviews(cfg.Root)
	if err != nil || len(records) != 1 || records[0].MemoryReservedBytes != 512<<20 {
		t.Fatalf("existing reservation was not retained: %+v %v", records, err)
	}
	// Replacing the same preview does not double-count its reservation.
	if _, err = PreviewUp(context.Background(), f.run, cfg, "prizm", 1, []string{"gate:newhead"}, previewNow); err != nil {
		t.Fatal(err)
	}
}

func TestPreviewBudgetRejectsInvalidConfigurationAndUnknownLegacyReservation(t *testing.T) {
	cfg := previewTestConfig(t)
	f := &fakeDocker{}
	cfg.Knob, _ = ParsePreviewKnob("MEM_BUDGET=0")
	if _, err := PreviewUp(context.Background(), f.run, cfg, "prizm", 1, []string{"gate:head"}, previewNow); err == nil || len(f.calls) != 0 {
		t.Fatal("invalid budget performed work")
	}
	cfg = previewTestConfig(t)
	cfg.Knob.MemoryBudget = 2 << 30
	writeTestPreview(t, cfg, "prizm", 1, previewNow)
	if _, err := PreviewUp(context.Background(), f.run, cfg, "prizm", 2, []string{"gate:head"}, previewNow); err == nil || len(f.calls) != 0 {
		t.Fatal("unknown legacy reservation was silently treated as zero")
	}
}

func TestPreviewAdmissionDoesNotHideCorruptState(t *testing.T) {
	cfg := previewTestConfig(t)
	old := writeTestPreview(t, cfg, "prizm", 1, previewNow)
	path := filepath.Join(previewDir(cfg.Root, old.Project), "preview.env")
	if err := os.WriteFile(path, []byte("V=1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f := &fakeDocker{}
	if _, err := PreviewUp(context.Background(), f.run, cfg, "prizm", 2, []string{"gate:head"}, previewNow); err == nil || len(f.calls) != 0 {
		t.Fatal("corrupt state was hidden from admission")
	}
}

func TestPreviewLockFailureAndCanceledWaitRefuseMutation(t *testing.T) {
	cfg := previewTestConfig(t)
	if err := os.WriteFile(filepath.Join(cfg.Root, "run"), []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	f := &fakeDocker{}
	if _, err := PreviewUp(context.Background(), f.run, cfg, "prizm", 1, []string{"gate:head"}, previewNow); err == nil || len(f.calls) != 0 {
		t.Fatal("lock failure performed work")
	}
	root := t.TempDir()
	unlock, err := lockPreviews(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := lockPreviews(ctx, root); err == nil {
		t.Fatal("second worker acquired the first worker's lease")
	}
}

func TestPreviewGateServicesHaveNoSharedGenericAlias(t *testing.T) {
	for _, app := range []string{"prizm", "fieldsofrevik"} {
		for _, pr := range []int{1, 2} {
			rec := PreviewRecord{App: app, PR: pr, Project: PreviewProject(app, pr), Images: []string{"gate:head"}}
			if app == "fieldsofrevik" {
				rec.Images = revikImages()
			}
			compose := previewCompose(rec, PreviewKnob{MemLimit: "256m", CPULimit: "0.5"}, "edge", false, "")
			if strings.Contains(compose, "\n  gate:\n") || !strings.Contains(compose, "\n  "+rec.Project+"-gate:\n") {
				t.Fatal("generic gate alias remains on the shared edge")
			}
		}
	}
}

func TestPreviewGateAliasMigrationWithRealCompose(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("Docker unavailable")
	}
	image, err := exec.Command("docker", "image", "inspect", "alpine:latest", "--format", "{{.Id}}").Output()
	if err != nil {
		t.Skip("local Alpine fixture unavailable; pure Compose isolation assertions still run")
	}
	network := fmt.Sprintf("komizo-alias-test-%d", time.Now().UnixNano())
	if output, err := exec.Command("docker", "network", "create", network).CombinedOutput(); err != nil {
		t.Fatalf("create isolated test network: %s %v", output, err)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "network", "rm", network).Run() })
	for pr := 1; pr <= 2; pr++ {
		record := PreviewRecord{App: network, PR: pr, Project: PreviewProject(network, pr), Images: []string{strings.TrimSpace(string(image))}}
		dir := t.TempDir()
		path := filepath.Join(dir, "compose.yml")
		compose := previewCompose(record, PreviewKnob{MemLimit: "64m", CPULimit: "0.1"}, network, false, "")
		compose = strings.Replace(compose, "    image: "+record.Images[0]+"\n", "    image: "+record.Images[0]+"\n    command: [sleep, '120']\n", 1)
		writeAndStart := func(body string) {
			t.Helper()
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command("docker", "compose", "-p", record.Project, "-f", path, "up", "-d", "--remove-orphans").CombinedOutput()
			if err != nil {
				t.Fatalf("start isolated fixture: %s %v", output, err)
			}
		}
		t.Cleanup(func() {
			_ = exec.Command("docker", "compose", "-p", record.Project, "-f", path, "down", "-v", "--remove-orphans").Run()
		})
		if pr == 1 {
			writeAndStart(strings.Replace(compose, "  "+record.Project+"-gate:\n", "  gate:\n", 1))
			if output, err := exec.Command("docker", "compose", "-p", record.Project, "-f", path, "rm", "-s", "-f", "gate").CombinedOutput(); err != nil {
				t.Fatalf("remove only legacy preview gate before service rename: %s %v", output, err)
			}
		}
		writeAndStart(compose)
		limits, err := exec.Command("docker", "inspect", record.Project+"-gate", "--format", "{{.HostConfig.Memory}} {{.HostConfig.MemorySwap}} {{.HostConfig.CpuShares}}").Output()
		if err != nil || strings.TrimSpace(string(limits)) != "67108864 67108864 128" {
			t.Fatalf("real Docker did not enforce preview memory/swap/priority: %s %v", limits, err)
		}
		body, err := exec.Command("docker", "inspect", record.Project+"-gate", "--format", "{{json .NetworkSettings.Networks}}").Output()
		if err != nil {
			t.Fatal(err)
		}
		var networks map[string]struct{ Aliases []string }
		if err := json.Unmarshal(body, &networks); err != nil {
			t.Fatal(err)
		}
		for _, alias := range networks[network].Aliases {
			if alias == "gate" {
				t.Fatal("real Docker endpoint retained ambiguous gate alias after migration")
			}
		}
	}
}
