package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nicodes/komizo/internal/workload"
)

func (h *hostActivation) startupCapacity(p workload.Policy) error {
	if p.Resources == nil || !strings.HasPrefix(p.Resources.CgroupParent, "/komizo-production/") {
		return nil
	}
	body, err := h.readBytes(filepath.Join(h.root, "/etc/komizo/resources.json"))
	if err != nil {
		return errors.New("installed startup allocation is unavailable")
	}
	var host workload.HostResources
	if json.Unmarshal(body, &host) != nil {
		return errors.New("installed startup allocation is invalid")
	}
	readUsage := func(name string) (int64, error) {
		body, err := os.ReadFile(filepath.Join(h.root, "/sys/fs/cgroup/komizo-production", name, "memory.current"))
		if err != nil || len(body) > 64 {
			return 0, errors.New("current startup usage is unavailable")
		}
		value, err := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64)
		if err != nil || value < 0 {
			return 0, errors.New("current startup usage is invalid")
		}
		return value, nil
	}
	parent, err := readUsage("")
	if err != nil {
		return err
	}
	usage := map[string]int64{}
	for name := range host.Apps {
		value, err := readUsage(name)
		if err != nil {
			return err
		}
		usage[name] = value
	}
	return host.CheckStartup(p.App, p.Resources, parent, usage)
}
