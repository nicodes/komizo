package box

import (
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func readPressure(dir, suffix string) *Pressure {
	p := &Pressure{CPU: pressureFile(filepath.Join(dir, "cpu"+suffix)), Memory: pressureFile(filepath.Join(dir, "memory"+suffix)), IO: pressureFile(filepath.Join(dir, "io"+suffix))}
	if p.CPU == nil && p.Memory == nil && p.IO == nil {
		return nil
	}
	return p
}

func pressureFile(path string) *PressureResource {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(body) > 4096 {
		return nil
	}
	p := &PressureResource{}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 5 {
			continue
		}
		values := map[string]string{}
		for _, f := range fields[1:] {
			key, value, ok := strings.Cut(f, "=")
			if ok {
				values[key] = value
			}
		}
		var avgs [3]float64
		valid := true
		for i, key := range []string{"avg10", "avg60", "avg300"} {
			v, err := strconv.ParseFloat(values[key], 64)
			if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 100 {
				valid = false
			}
			avgs[i] = v
		}
		total, err := strconv.ParseUint(values["total"], 10, 64)
		if !valid || err != nil {
			continue
		}
		v := &PressureLine{Avg10: avgs[0], Avg60: avgs[1], Avg300: avgs[2], TotalUsec: total}
		if fields[0] == "some" {
			p.Some = v
		} else if fields[0] == "full" {
			p.Full = v
		}
	}
	if p.Some == nil && p.Full == nil {
		return nil
	}
	return p
}

func cgroupPressureStats(dir string, cs *ContainerStat) {
	cs.Pressure = readPressure(dir, ".pressure")
	for _, field := range []struct {
		file, key string
		target    **uint64
	}{
		{"cpu.stat", "nr_periods", &cs.CPUPeriods},
		{"cpu.stat", "nr_throttled", &cs.CPUThrottledPeriods},
		{"cpu.stat", "throttled_usec", &cs.CPUThrottledUsec},
		{"memory.events", "max", &cs.MemoryMaxEvents},
		{"memory.events", "oom_kill", &cs.OOMKills},
	} {
		if v, ok := fieldFrom(filepath.Join(dir, field.file), field.key); ok {
			*field.target = &v
		}
	}
	if v, ok := numFrom(filepath.Join(dir, "memory.current")); ok {
		cs.MemoryCurrent = &v
	}
	if v, ok := numFrom(filepath.Join(dir, "memory.swap.current")); ok {
		cs.Swap = &v
	}
}

func (p *Probe) groupStats() []GroupStat {
	var groups []GroupStat
	for _, name := range []string{"komizo-production", "komizo-proxy", "komizo-previews", "komizo-preview-database"} {
		dir := p.path(filepath.Join("/sys/fs/cgroup", name))
		if !dirExists(dir) {
			continue
		}
		stat := ContainerStat{}
		cgroupPressureStats(dir, &stat)
		if v, ok := fieldFrom(filepath.Join(dir, "cpu.stat"), "usage_usec"); ok {
			stat.CPUUsec = &v
		}
		if v, ok := numFrom(filepath.Join(dir, "memory.max")); ok {
			stat.Limit = &v
		}
		groups = append(groups, GroupStat{Name: name, Stat: stat})
	}
	return groups
}
