package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/nicodes/komizo/internal/workload"
)

func runHostResources(args []string) error {
	fs := flag.NewFlagSet("host-resources", flag.ContinueOnError)
	apply := fs.Bool("apply", false, "apply the installed operator policy")
	check := fs.Bool("check", false, "validate stdin against measured capacity without changing policy or controllers")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 || fs.NArg() != 0 || (*apply && *check) {
		return errors.New("host resources require the root operator")
	}
	const path = "/etc/komizo/resources.json"
	var body []byte
	var err error
	if *apply {
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || !workloadRootOwner(info) {
			return errors.New("host resource policy must be a root-owned private regular file")
		}
		body, err = os.ReadFile(path)
	} else {
		body, err = io.ReadAll(io.LimitReader(os.Stdin, workload.MaxBytes+1))
	}
	if err != nil || len(body) > workload.MaxBytes {
		return errors.New("host resource policy unavailable or oversized")
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
		return policy.Check(total, int64(runtime.NumCPU())*1000)
	}
	if err := policy.Apply("/sys/fs/cgroup", total, int64(runtime.NumCPU())*1000); err != nil {
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
