package box

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPressureCountersPreserveUnknownAndMeasuredZero(t *testing.T) {
	f := newFakeBox(t)
	if p := readPressure(f.root, ""); p != nil {
		t.Fatal("missing pressure measured as zero")
	}
	f.write("/proc/pressure/cpu", "some avg10=1.50 avg60=0.20 avg300=0.10 total=123\n")
	f.write("/proc/pressure/memory", "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
	p := readPressure(f.probe().path("/proc/pressure"), "")
	if p.CPU.Some.TotalUsec != 123 || p.CPU.Full != nil || p.Memory.Full.TotalUsec != 0 || p.IO != nil {
		t.Fatalf("pressure changed: %+v", p)
	}
	for _, value := range []string{"NaN", "+Inf", "-1", "101"} {
		f.write("/proc/pressure/io", "some avg10="+value+" avg60=0 avg300=0 total=1\n")
		if readPressure(f.probe().path("/proc/pressure"), "").IO != nil {
			t.Fatalf("invalid pressure %s accepted", value)
		}
	}
	f.write("/proc/pressure/io", strings.Repeat("x", 4097))
	if pressureFile(f.probe().path("/proc/pressure/io")) != nil {
		t.Fatal("oversized pressure accepted")
	}
}

func TestHostEnvelopeReportsThrottlingAndMemoryEvents(t *testing.T) {
	f := newFakeBox(t)
	f.write("/sys/fs/cgroup/komizo-production/cpu.stat", "usage_usec 99\nnr_periods 10\nnr_throttled 3\nthrottled_usec 17\n")
	f.write("/sys/fs/cgroup/komizo-production/memory.events", "max 7\noom_kill 0\n")
	f.write("/sys/fs/cgroup/komizo-production/memory.current", "123")
	f.write("/sys/fs/cgroup/komizo-production/memory.swap.current", "5")
	groups := f.probe().groupStats()
	if len(groups) != 1 {
		t.Fatalf("unexpected groups: %v", groups)
	}
	s := groups[0].Stat
	if *s.CPUThrottledUsec != 17 || *s.CPUThrottledPeriods != 3 || *s.MemoryMaxEvents != 7 || *s.OOMKills != 0 || *s.MemoryCurrent != 123 || *s.Swap != 5 {
		t.Fatalf("counters: %+v", s)
	}
	if _, err := json.Marshal(groups); err != nil {
		t.Fatal(err)
	}
}
