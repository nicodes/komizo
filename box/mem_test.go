package box

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMemAvailableIsMemAvailableNotMemFree(t *testing.T) {
	f := newFakeBox(t)
	f.write("/proc/meminfo", "MemTotal:       1000 kB\nMemFree:          10 kB\nMemAvailable:    400 kB\n")
	m := f.probe().mem()
	if m == nil {
		t.Fatal("mem is nil")
	}
	if m.Available != 400*1024 {
		t.Errorf("available = %d, want MemAvailable %d", m.Available, 400*1024)
	}
	if m.Used != 600*1024 {
		t.Errorf("used = %d, want total-MemAvailable %d", m.Used, 600*1024)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if !strings.Contains(got, `"available":409600`) {
		t.Errorf("JSON missing MemAvailable: %s", got)
	}
	if strings.Contains(got, `"available":10240`) {
		t.Errorf("JSON used MemFree as available: %s", got)
	}
}

func TestMemReportsSwapWhenPresent(t *testing.T) {
	f := newFakeBox(t)
	f.write("/proc/meminfo", "MemTotal: 1000 kB\nMemAvailable: 400 kB\nSwapTotal: 200 kB\nSwapFree: 50 kB\n")
	m := f.probe().mem()
	if m == nil || m.Swap == nil {
		t.Fatalf("swap missing: %+v", m)
	}
	if m.Swap.Total != 200*1024 || m.Swap.Used != 150*1024 {
		t.Errorf("swap = %+v", m.Swap)
	}
}
