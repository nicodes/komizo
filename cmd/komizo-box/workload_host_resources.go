package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/nicodes/komizo/internal/workload"
)

func runHostResources(args []string) error {
	fs := flag.NewFlagSet("host-resources", flag.ContinueOnError)
	apply := fs.Bool("apply", false, "apply the installed operator policy")
	check := fs.Bool("check", false, "validate stdin against measured capacity without changing policy or controllers")
	policyPath := fs.String("policy", "", "protected candidate file; accepted only with --check")
	usage := fs.Bool("check-usage", false, "also preflight installed controllers and usage; requires --check")
	reclaim := fs.Bool("reclaim-controls", false, "reclaim bounded inactive control cache before a reviewed resource reduction; applies no limits")
	expected := fs.String("policy-sha256", "", "exact protected candidate hash; required with --reclaim-controls")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 || fs.NArg() != 0 || (*apply && *check) || (!*check && !*reclaim && (*policyPath != "" || *usage)) || (*reclaim && (*apply || *check || *usage || *policyPath == "" || len(*expected) != 64 || strings.Trim(*expected, "0123456789abcdef") != "")) || (!*reclaim && *expected != "") {
		return errors.New("host resources require the root operator")
	}
	const path = "/etc/komizo/resources.json"
	var body []byte
	var err error
	if (*check || *reclaim) && *policyPath != "" {
		if !filepath.IsAbs(*policyPath) || filepath.Clean(*policyPath) != *policyPath {
			return errors.New("candidate resource policy must be an absolute canonical path")
		}
		if err := backupProtectedPath(*policyPath, false); err != nil {
			return err
		}
		body, err = protectedActivationBytes(*policyPath)
	} else if *apply {
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || !workloadRootOwner(info) {
			return errors.New("host resource policy must be a root-owned private regular file")
		}
		body, err = os.ReadFile(path)
	} else {
		body, err = readWorkloadInput(context.Background(), os.Stdin, workload.MaxBytes)
	}
	if err != nil || len(body) > workload.MaxBytes {
		return errors.New("host resource policy unavailable or oversized")
	}
	if *reclaim && deploymentHash(body) != *expected {
		return errors.New("reviewed resource policy changed")
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var policy workload.HostResources
	if err := decoder.Decode(&policy); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("one host resource document is required")
	}
	total, err := hostMemoryBytes()
	if err != nil {
		return err
	}
	if *check {
		if *usage {
			return policy.Preflight("/sys/fs/cgroup", total, int64(runtime.NumCPU())*1000)
		}
		return policy.Check(total, int64(runtime.NumCPU())*1000)
	}
	if *reclaim {
		if err := policy.Check(total, int64(runtime.NumCPU())*1000); err != nil {
			return err
		}
		rows, err := policy.ReclaimControlCache("/sys/fs/cgroup")
		if encodeErr := json.NewEncoder(os.Stdout).Encode(map[string]any{"version": 1, "policy_sha256": *expected, "limits_applied": false, "groups": rows, "complete": err == nil}); encodeErr != nil {
			return encodeErr
		}
		return err
	}
	if err := policy.Apply("/sys/fs/cgroup", total, int64(runtime.NumCPU())*1000); err != nil {
		return err
	}
	if err := applySmallHostKernelMemory("/", total); err != nil {
		return err
	}
	if err := applySmallHostCompressedSwap(total); err != nil {
		return err
	}
	if !*apply {
		return workload.WritePrivateJSON(path, policy)
	}
	return nil
}

func hostMemoryBytes() (int64, error) {
	mem, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(mem), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "MemTotal:" && fields[2] == "kB" {
			n, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil || n <= 0 || n > 1<<50 {
				return 0, errors.New("measured host memory unavailable")
			}
			return n * 1024, nil
		}
	}
	return 0, errors.New("measured host memory unavailable")
}
