package app

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// No package installation, Docker call or agent is needed on an untouched box.
// Values are a bounded fixed vocabulary; no environment or private file is read.
const doctorScript = `set -eu
os=unknown
if [ -r /etc/os-release ]; then
 os=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"' | head -n 1)
fi
printf 'os=%s\n' "$os"
printf 'kernel=%s\n' "$(uname -s)"
printf 'arch=%s\n' "$(uname -m)"
printf 'uid=%s\n' "$(id -u)"
printf 'memory_kib=%s\n' "$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
printf 'disk_kib=%s\n' "$(df -Pk /var/lib 2>/dev/null | awk 'END {print $4}')"
printf 'inodes=%s\n' "$(df -Pi /var/lib 2>/dev/null | awk 'END {print $4}')"
if command -v apk >/dev/null 2>&1; then echo apk=yes; else echo apk=no; fi
if command -v rc-service >/dev/null 2>&1; then echo openrc=yes; else echo openrc=no; fi
if [ -r /sys/fs/cgroup/cgroup.controllers ]; then echo cgroup_v2=yes; else echo cgroup_v2=no; fi
if [ -e /var/lib/komizo/version ] || [ -d /var/lib/komizo/apps ]; then echo installed=yes; else echo installed=no; fi
`

type DoctorCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

type DoctorResult struct {
	Version   int               `json:"version"`
	Host      string            `json:"host"`
	Supported bool              `json:"supported"`
	Installed bool              `json:"installed"`
	Checks    []DoctorCheck     `json:"checks"`
	Facts     map[string]string `json:"facts"`
}

func RunDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.Usage = func() {
		usageJourney("doctor", "komizo doctor --host root@HOST", "Read-only checks for supported OS, architecture, privileges and installation space. SSH host trust stays explicit.")
		fs.PrintDefaults()
	}
	host := fs.String("host", "", "server, [user@]HOST")
	port := fs.Int("port", 22, "SSH port")
	accept := fs.Bool("accept-host-key", false, "explicit trust on first use")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("doctor accepts only flags")
	}
	tgt, err := resolveTarget(fs, *host, *port)
	if err != nil {
		return err
	}
	if err := ensureReachable(tgt, *accept); err != nil {
		return err
	}
	result, err := inspectPrerequisites(tgt)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return err
	}
	if !result.Supported {
		return errors.New("server prerequisites failed; inspect doctor checks before setup")
	}
	return nil
}

func inspectPrerequisites(tgt target) (DoctorResult, error) {
	raw, err := tgt.quiet(doctorScript)
	if err != nil {
		return DoctorResult{}, fmt.Errorf("cannot inspect server prerequisites: %w", err)
	}
	return decodePrerequisites(tgt.addr(), raw)
}

func decodePrerequisites(host, raw string) (DoctorResult, error) {
	r := DoctorResult{Version: 1, Host: host, Supported: true, Facts: map[string]string{}}
	allowed := map[string]bool{"os": true, "kernel": true, "arch": true, "uid": true, "memory_kib": true, "disk_kib": true, "inodes": true, "apk": true, "openrc": true, "cgroup_v2": true, "installed": true}
	if len(raw) > 4096 {
		return r, errors.New("oversized prerequisite response")
	}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		name, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok || !allowed[name] || r.Facts[name] != "" || value == "" || len(value) > 128 {
			return r, errors.New("invalid prerequisite response")
		}
		r.Facts[name] = value
	}
	if scanner.Err() != nil || len(r.Facts) != len(allowed) {
		return r, errors.New("incomplete prerequisite response")
	}
	check := func(name string, ok bool, detail string) {
		r.Checks = append(r.Checks, DoctorCheck{name, ok, detail})
		r.Supported = r.Supported && ok
	}
	check("os", r.Facts["os"] == "alpine" && r.Facts["kernel"] == "Linux" && r.Facts["apk"] == "yes" && r.Facts["openrc"] == "yes", "Alpine Linux with apk and OpenRC is required")
	_, archOK := map[string]bool{"x86_64": true, "aarch64": true}[r.Facts["arch"]]
	check("architecture", archOK, "amd64 or arm64 is required")
	check("privileges", r.Facts["uid"] == "0", "setup needs the host operator's root SSH access")
	for _, item := range []struct {
		name, key string
		minimum   uint64
	}{{"memory", "memory_kib", 256 << 10}, {"disk", "disk_kib", 1 << 20}, {"inodes", "inodes", 4096}} {
		n, err := strconv.ParseUint(r.Facts[item.key], 10, 64)
		check(item.name, err == nil && n >= item.minimum, fmt.Sprintf("minimum %d %s; this is setup admission, not application capacity", item.minimum, item.key))
	}
	r.Installed = r.Facts["installed"] == "yes"
	for _, key := range []string{"apk", "openrc", "cgroup_v2", "installed"} {
		if r.Facts[key] != "yes" && r.Facts[key] != "no" {
			return r, errors.New("invalid prerequisite boolean")
		}
	}
	return r, nil
}
