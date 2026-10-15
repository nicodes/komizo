package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/internal/workload"
)

// Capacity inspection shares the real lifecycle admission check but has no
// lifecycle effect, including when reclaim makes a previously pressured app fit.
func runWorkloadStartupCheck(args []string) error {
	fs := flag.NewFlagSet("startup-check", flag.ContinueOnError)
	path := fs.String("policy", "", "installed protected application policy")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 || fs.NArg() != 0 {
		return errors.New("startup inspection requires the root operator and an installed policy")
	}
	p, err := readWorkloadPolicy(*path)
	if err != nil {
		return err
	}
	if *path != filepath.Join(lookupRoot, workloadPolicyDirectory, p.App+".json") {
		return errors.New("startup inspection uses only the installed policy")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	unlock, err := box.LockDeployment(ctx, lookupRoot, p.App)
	if err != nil {
		return err
	}
	defer unlock()
	current, err := readWorkloadPolicy(*path)
	if err != nil {
		return err
	}
	if current.App != p.App {
		return errors.New("startup inspection policy identity changed")
	}
	h := newHostActivation()
	h.root = lookupRoot
	return h.startupCapacity(current)
}

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
