package main

import (
	"encoding/json"
	"fmt"
	"github.com/nicodes/komizo/internal/workload"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func previewHostResources(path string) (*workload.HostResources, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || !workloadRootOwner(info) || info.Size() > workload.MaxBytes {
		return nil, fmt.Errorf("preview up requires a protected host resource policy")
	}
	body, err := os.ReadFile(path)
	if err != nil || len(body) > workload.MaxBytes {
		return nil, fmt.Errorf("preview up cannot read protected host resources")
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var policy workload.HostResources
	if err := decoder.Decode(&policy); err != nil {
		return nil, fmt.Errorf("invalid protected preview resources: %w", err)
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, fmt.Errorf("one protected resource document is required")
	}
	memory, err := hostMemoryBytes()
	if err != nil {
		return nil, err
	}
	if err := policy.Check(memory, int64(runtime.NumCPU())*1000); err != nil {
		return nil, err
	}
	return &policy, nil
}

func verifyPreviewControllers(policy *workload.HostResources, root string) error {
	p := policy.Previews
	values := map[string]string{"memory.max": fmt.Sprint(p.MemoryBytes), "memory.swap.max": "0", "cpu.max": fmt.Sprintf("%d 100000", p.MilliCPUs*100), "pids.max": fmt.Sprint(p.PIDs)}
	for file, expected := range values {
		body, err := os.ReadFile(filepath.Join(root, "komizo-previews", file))
		if err != nil || strings.Join(strings.Fields(string(body)), " ") != expected {
			return fmt.Errorf("preview up refused: protected preview controller drift (%s); apply reviewed host resources first", file)
		}
	}
	return nil
}
