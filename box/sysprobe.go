package box

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// System is one reading of what the box and its containers are spending.
func (p *Probe) System(inv dockerInventory) System {
	return System{
		Cores:      p.cores(),
		CPU:        p.cpu(),
		Mem:        p.mem(),
		Disks:      p.disks(),
		Containers: p.containerStats(inv),
	}
}

// cpu is cumulative jiffies since boot, and the idle part of them.
//
// Idle counts iowait with it. Waiting on a disk is not work, and counting it as
// busy makes a box that is merely reading from a slow disk look loaded.
func (p *Probe) cpu() *CPU {
	for _, ln := range readLines(p.path("/proc/stat")) {
		f := strings.Fields(ln)
		if len(f) < 6 || f[0] != "cpu" {
			continue
		}
		var total uint64
		for _, v := range f[1:] {
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return nil
			}
			total += n
		}
		// Fields 4 and 5 after the label are idle and iowait.
		idle, _ := strconv.ParseUint(f[4], 10, 64)
		iowait, _ := strconv.ParseUint(f[5], 10, 64)
		return &CPU{Total: total, Idle: idle + iowait}
	}
	return nil
}

func (p *Probe) cores() int {
	n := 0
	for _, ln := range readLines(p.path("/proc/cpuinfo")) {
		if strings.HasPrefix(ln, "processor") {
			n++
		}
	}
	return n
}

// mem is measured from MemAvailable, never MemFree.
//
// Free memory on a healthy box is near zero -- the kernel spends everything
// spare on cache and hands it back on demand -- so reporting free as used is
// the classic way to make every server on earth look seconds from death.
func (p *Probe) mem() *Mem {
	var total, avail uint64
	var haveAvail bool
	for _, ln := range readLines(p.path("/proc/meminfo")) {
		k, v, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			continue
		}
		n, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			continue
		}
		switch k {
		case "MemTotal":
			total = n * 1024
		case "MemAvailable":
			avail, haveAvail = n*1024, true
		}
	}
	if total == 0 || !haveAvail {
		return nil
	}
	return &Mem{Total: total, Used: total - avail}
}

// uptime is how long the box has been up, in seconds.
func (p *Probe) uptime() int64 {
	lines := readLines(p.path("/proc/uptime"))
	if len(lines) == 0 {
		return 0
	}
	f := strings.Fields(lines[0])
	if len(f) == 0 {
		return 0
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0
	}
	return int64(v)
}

// disks covers / and /var/lib/docker, because the one that fills is usually not
// the one people watch: images and volumes live under /var/lib/docker, which is
// frequently its own filesystem.
//
// Folded when the two are one filesystem, by DEVICE rather than mount point --
// docker setups routinely bind-mount /var/lib/docker onto itself, which gives
// one filesystem two mount points, and folding by mount point draws that box's
// one disk as two identical bars.
func (p *Probe) disks() []Disk {
	var out []Disk
	seen := map[string]bool{}
	for _, m := range []string{"/", "/var/lib/docker"} {
		d, ok := statfs(p.path(m))
		if !ok || d.Size == 0 {
			continue
		}
		d.Mount = m
		if d.Dev != "" && seen[d.Dev] {
			continue
		}
		if d.Dev != "" {
			seen[d.Dev] = true
		}
		out = append(out, d)
	}
	return out
}

// listeningPorts is what a container is actually listening on.
//
// /proc/<pid>/net/tcp IS that container's network namespace, so this is read
// from the host with no exec, no ss, and no cooperation from the image -- which
// matters because most of these images have no shell tools in them at all.
//
// Observed, not declared: EXPOSE is inherited from base images, so a Caddy gate
// "exposes" 443 and 2019 it never binds.
func (p *Probe) listeningPorts(pid int) []int {
	if pid <= 0 {
		return nil
	}
	seen := map[int]bool{}
	for _, f := range []string{"net/tcp", "net/tcp6"} {
		for _, ln := range readLines(p.path(filepath.Join("/proc", strconv.Itoa(pid), f))) {
			fields := strings.Fields(ln)
			// State 0A is LISTEN.
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			_, hexPort, ok := strings.Cut(fields[1], ":")
			if !ok {
				continue
			}
			n, err := strconv.ParseUint(hexPort, 16, 32)
			if err != nil {
				continue
			}
			// Ephemeral ports are a runtime's private business, not something
			// anything dials on purpose.
			if n >= 32768 && n <= 60999 {
				continue
			}
			seen[int(n)] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]int, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

// containerStats is per-container processor time and memory, for every running
// container the box knows about.
//
// Running containers only. A stopped one has no pid and no cgroup, so there is
// nothing to read -- and its ABSENCE from a reading is the honest record of
// that, which a reader turns back into a zero.
func (p *Probe) containerStats(inv dockerInventory) []ContainerStat {
	var out []ContainerStat
	for _, as := range p.appStates() {
		for _, ci := range inv.forDir(as.dir()) {
			// Running containers only. A stopped one has no pid and no cgroup,
			// so there is nothing to read.
			if ci.pid <= 0 || ci.service == "" {
				continue
			}
			cs := p.cgroupStat(ci.pid)
			cs.App, cs.Service = as.name, ci.service
			out = append(out, cs)
		}
	}
	return out
}

// cgroupStat reads one container's accounting straight out of the cgroup, which
// is where the kernel does it anyway.
//
// `docker stats` reads the same files and then streams, which is why it costs a
// second per call. This is three small reads with no daemon in the path, cheap
// enough to ride a five-second poll.
//
// Nil fields travel as nil. A cgroup this could not read is UNKNOWN, and a zero
// would be a measurement -- one saying the container is using nothing at all.
func (p *Probe) cgroupStat(pid int) ContainerStat {
	var cs ContainerStat
	if pid <= 0 {
		return cs
	}
	lines := readLines(p.path(filepath.Join("/proc", strconv.Itoa(pid), "cgroup")))

	// cgroup v2: one unified hierarchy, on the line whose id is 0.
	for _, ln := range lines {
		f := strings.SplitN(ln, ":", 3)
		if len(f) != 3 || f[0] != "0" {
			continue
		}
		d := p.path(filepath.Join("/sys/fs/cgroup", f[2]))
		if !dirExists(d) {
			break
		}
		if v, ok := fieldFrom(filepath.Join(d, "cpu.stat"), "usage_usec"); ok {
			cs.CPUUsec = &v
		}
		if cur, ok := numFrom(filepath.Join(d, "memory.current")); ok {
			ina, _ := fieldFrom(filepath.Join(d, "memory.stat"), "inactive_file")
			m := saturatingSub(cur, ina)
			cs.Mem = &m
		}
		if lim, ok := numFrom(filepath.Join(d, "memory.max")); ok {
			cs.Limit = &lim
		}
		return cs
	}

	// cgroup v1: a hierarchy per controller, each on its own line. Still what
	// older Alpine and anything with a v1 boot argument presents.
	for _, ln := range lines {
		f := strings.SplitN(ln, ":", 3)
		if len(f) != 3 {
			continue
		}
		ctrls := strings.Split(f[1], ",")
		for _, c := range ctrls {
			switch c {
			case "cpuacct":
				// Nanoseconds here, microseconds under v2. Converted so no reader
				// ever has to know which kind of box it is talking to.
				if v, ok := numFrom(p.path(filepath.Join("/sys/fs/cgroup/cpuacct", f[2], "cpuacct.usage"))); ok {
					us := v / 1000
					cs.CPUUsec = &us
				}
			case "memory":
				base := p.path(filepath.Join("/sys/fs/cgroup/memory", f[2]))
				if cur, ok := numFrom(filepath.Join(base, "memory.usage_in_bytes")); ok {
					ina, _ := fieldFrom(filepath.Join(base, "memory.stat"), "total_inactive_file")
					m := saturatingSub(cur, ina)
					cs.Mem = &m
				}
				if lim, ok := numFrom(filepath.Join(base, "memory.limit_in_bytes")); ok {
					cs.Limit = &lim
				}
			}
		}
	}
	return cs
}

// saturatingSub is a - b, floored at zero.
//
// These are unsigned byte counts read from two different files at two slightly
// different moments. A container whose inactive cache grew between the reads
// would otherwise wrap to sixteen exabytes of memory used, which charts as a
// spike somebody would go looking for.
func saturatingSub(a, b uint64) uint64 {
	if b > a {
		return 0
	}
	return a - b
}

// numFrom reads a file holding one number. "max" -- what cgroup v2 writes for
// an uncapped memory limit -- is not one, and reports absent.
func numFrom(path string) (uint64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// fieldFrom reads "key value" out of a cgroup stat file.
func fieldFrom(path, key string) (uint64, bool) {
	for _, ln := range readLines(path) {
		f := strings.Fields(ln)
		if len(f) < 2 || f[0] != key {
			continue
		}
		v, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			return 0, false
		}
		return v, true
	}
	return 0, false
}

func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

func dirExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}
