package workload

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type ControlReclaim struct {
	Name           string `json:"name"`
	BeforeBytes    int64  `json:"before_bytes"`
	RequestedBytes int64  `json:"requested_bytes"`
	AfterBytes     int64  `json:"after_bytes"`
}

func controlCounter(path string) (int64, error) {
	body, err := os.ReadFile(path)
	if err != nil || len(body) > 64 {
		return 0, errors.New("control counter unavailable")
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64)
	if err != nil || value < 0 {
		return 0, errors.New("control counter invalid")
	}
	return value, nil
}

// ReclaimControlCache is a finite Root admission step, never a cache or image
// deletion. Every fixed control group is reviewed before the first write. The
// kernel may reclaim less or more than requested; a subsequent ordinary usage
// preflight still gates the actual limit change. No application group is touched.
func (p HostResources) ReclaimControlCache(root string) ([]ControlReclaim, error) {
	if len(p.Controls) != 3 {
		return nil, errors.New("declared control resources required")
	}
	if err := p.checkControls(); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(p.Controls))
	for name := range p.Controls {
		names = append(names, name)
	}
	sort.Strings(names)
	rows := make([]ControlReclaim, 0, len(names))
	for _, name := range names {
		dir := filepath.Join(root, name)
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("control group unavailable")
		}
		current, err := controlCounter(filepath.Join(dir, "memory.current"))
		if err != nil {
			return nil, err
		}
		row := ControlReclaim{Name: name, BeforeBytes: current, AfterBytes: current}
		if current > p.Controls[name].MemoryBytes {
			// At most 64 MiB per daemon, with 8 MiB admission headroom.
			amount := ((current - p.Controls[name].MemoryBytes + (8 << 20) + (4 << 20) - 1) / (4 << 20)) * (4 << 20)
			if amount > 64<<20 {
				return nil, errors.New("control excess requires a larger reviewed drain")
			}
			body, err := os.ReadFile(filepath.Join(dir, "memory.stat"))
			if err != nil || len(body) > 65536 {
				return nil, errors.New("inactive control cache unavailable")
			}
			inactive := int64(-1)
			for _, line := range strings.Split(string(body), "\n") {
				fields := strings.Fields(line)
				if len(fields) == 2 && fields[0] == "inactive_file" {
					inactive, err = strconv.ParseInt(fields[1], 10, 64)
					if err != nil {
						return nil, errors.New("invalid inactive cache counter")
					}
					break
				}
			}
			if inactive < amount {
				return nil, errors.New("insufficient inactive control cache; live memory cannot be forcibly drained")
			}
			file := filepath.Join(dir, "memory.reclaim")
			info, err = os.Lstat(file)
			if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return nil, errors.New("bounded kernel reclaim interface unavailable")
			}
			row.RequestedBytes = amount
		}
		rows = append(rows, row)
	}
	for i := range rows {
		if rows[i].RequestedBytes == 0 {
			continue
		}
		dir := filepath.Join(root, rows[i].Name)
		if err := os.WriteFile(filepath.Join(dir, "memory.reclaim"), []byte(strconv.FormatInt(rows[i].RequestedBytes, 10)), 0600); err != nil {
			return rows, errors.New("kernel reclaim incomplete; inspect retained receipt and current usage")
		}
		value, err := controlCounter(filepath.Join(dir, "memory.current"))
		if err != nil {
			return rows, err
		}
		rows[i].AfterBytes = value
	}
	return rows, nil
}
