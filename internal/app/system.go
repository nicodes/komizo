package app

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// What the box and the things on it are spending: processor, memory, disk.
//
// Read from /proc and from the cgroup filesystem, which is where the kernel
// does this accounting anyway. `docker stats` reads the same cgroup files and
// then streams, which is what makes it cost about a second a call; three small
// file reads cost nothing and can ride the five-second poll.
//
// The host sends CUMULATIVE counters and this file does the subtracting. That
// is not an optimisation -- a rate is a claim about an interval, and only the
// side holding both readings knows what the interval actually was. A poll that
// arrived two seconds late measures the gap it really covered rather than the
// five seconds it was supposed to be.

// systemProbe reads the box and defines how one container is read.
//
// ONE definition, used twice: spliced into the inventory the TUI runs every
// five seconds, and written verbatim into the sampler that cron runs every
// minute. The cgroup handling is the fiddly part -- two hierarchy layouts, two
// time units, values that must stay blank when they cannot be read -- and two
// copies of it would drift, silently, in the direction of whichever one nobody
// happened to be looking at.
const systemProbe = `
# What this machine is spending: processor, memory, disk.
#
# CUMULATIVE COUNTERS, not rates. A rate needs two readings and this script is
# one of them -- the caller keeps the previous sample and does the subtraction.
# That also makes the interval explicit rather than assumed: a poll that arrived
# late measures the longer gap it actually covered.
# %.0f, never %d, for anything that can pass 2^31: BusyBox awk clamps %d to 32
# bits, so a disk over 2GB printed as -2147483648 and the reader -- correctly
# refusing a negative byte count -- dropped the line. Cumulative jiffies and
# byte counts all cross 2^31 on ordinary boxes; %.0f is exact to 2^53.
awk '$1 == "cpu" {
	t = 0
	for (i = 2; i <= NF; i++) t += $i
	# Idle counts iowait with it. Waiting on a disk is not work, and counting it
	# as busy makes a box that is merely reading from a slow disk look loaded.
	printf "sys\tcpu\t%.0f\t%.0f\n", t, $5 + $6
	exit
}' /proc/stat 2>/dev/null
awk '/^processor/ { n++ } END { if (n) printf "sys\tcores\t%d\t0\n", n }' /proc/cpuinfo 2>/dev/null
# MemAvailable, never MemFree. Free memory on a healthy box is near zero -- the
# kernel spends everything spare on cache and hands it back on demand -- so
# reporting free as used is the classic way to make every server on earth look
# seconds from death.
awk '/^MemTotal:/ { t = $2 } /^MemAvailable:/ { a = $2 }
	END { if (t > 0 && a != "") printf "sys\tmem\t%.0f\t%.0f\n", t * 1024, (t - a) * 1024 }' \
	/proc/meminfo 2>/dev/null
# Used and available, rather than the filesystem's raw size. df computes its own
# percentage the same way, excluding the blocks reserved for root -- and a disk
# figure that disagrees with df on the very same box is one nobody will believe,
# however defensible the arithmetic behind it.
#
# Both paths, because the one that fills is usually not the one people watch:
# images and volumes live under /var/lib/docker, which is frequently its own
# filesystem. The device travels with the numbers so the caller can fold the
# two when they are one filesystem -- by DEVICE, not mount point, because
# docker setups routinely bind-mount /var/lib/docker onto itself, and df then
# reports the same filesystem under two names.
for p in / /var/lib/docker; do
	[ -d "$p" ] || continue
	df -k "$p" 2>/dev/null | awk 'NR > 1 && NF >= 4 {
		printf "disk\t%s\t%s\t%.0f\t%.0f\n", $NF, $1, $3 * 1024, ($3 + $4) * 1024
		exit
	}'
done


# What one container is spending.
#
# Read from the CGROUP, which is where the kernel does the accounting anyway --
# 'docker stats' reads the same files and then streams, which is why it costs a
# second per call. This is three small reads with no daemon in the path, cheap
# enough to ride the five-second poll.
#
# Same shape as the box's numbers: cumulative processor time, and memory as of
# now. The caller subtracts.
#
# Memory excludes inactive page cache, which is the convention 'docker stats'
# follows and the honest one: cache is memory the container is BORROWING and the
# kernel will take straight back under pressure. Counting it makes anything that
# has ever read a large file look permanently swollen.
container_stat() {
	_pid="$1"
	[ -n "$_pid" ] && [ "$_pid" != "0" ] || return 0
	_cpu=""; _mem=""; _lim=""
	# cgroup v2: one unified hierarchy, on the line whose id is 0.
	_cg="$(awk -F: '$1 == "0" { print $3; exit }' "/proc/$_pid/cgroup" 2>/dev/null)"
	if [ -n "$_cg" ] && [ -d "/sys/fs/cgroup$_cg" ]; then
		_d="/sys/fs/cgroup$_cg"
		_cpu="$(awk '$1 == "usage_usec" { print $2; exit }' "$_d/cpu.stat" 2>/dev/null)"
		_cur="$(cat "$_d/memory.current" 2>/dev/null)"
		_ina="$(awk '$1 == "inactive_file" { print $2; exit }' "$_d/memory.stat" 2>/dev/null)"
		_lim="$(cat "$_d/memory.max" 2>/dev/null)"
		[ -n "$_cur" ] && _mem=$((_cur - ${_ina:-0}))
	else
		# cgroup v1: a hierarchy per controller, each on its own line. Still what
		# older Alpine and anything with a v1 boot argument presents.
		_c1="$(awk -F: '$2 ~ /(^|,)cpuacct(,|$)/ { print $3; exit }' "/proc/$_pid/cgroup" 2>/dev/null)"
		if [ -n "$_c1" ] && [ -f "/sys/fs/cgroup/cpuacct$_c1/cpuacct.usage" ]; then
			# Nanoseconds there, microseconds under v2. Converted here so the
			# caller never has to know which kind of box it is talking to.
			_cpu="$(awk '{ printf "%.0f", $1 / 1000; exit }' "/sys/fs/cgroup/cpuacct$_c1/cpuacct.usage" 2>/dev/null)"
		fi
		_m1="$(awk -F: '$2 ~ /(^|,)memory(,|$)/ { print $3; exit }' "/proc/$_pid/cgroup" 2>/dev/null)"
		if [ -n "$_m1" ] && [ -f "/sys/fs/cgroup/memory$_m1/memory.usage_in_bytes" ]; then
			_cur="$(cat "/sys/fs/cgroup/memory$_m1/memory.usage_in_bytes" 2>/dev/null)"
			_ina="$(awk '$1 == "total_inactive_file" { print $2; exit }' "/sys/fs/cgroup/memory$_m1/memory.stat" 2>/dev/null)"
			_lim="$(cat "/sys/fs/cgroup/memory$_m1/memory.limit_in_bytes" 2>/dev/null)"
			[ -n "$_cur" ] && _mem=$((_cur - ${_ina:-0}))
		fi
	fi
	# Blanks travel as blanks. A cgroup this could not read is UNKNOWN, and a
	# zero would be a measurement -- one saying the container is using nothing.
	printf '%s\t%s\t%s' "${_cpu:-}" "${_mem:-}" "${_lim:-}"
}

# Every running container on the box, with the app it belongs to.
#
# The sampler's own enumeration. The live poll already walks the apps for other
# reasons and calls container_stat as it goes; cron has no such loop, and
# without this the sampler wrote the box's numbers and nothing else -- so every
# app and container chart was empty however long the box had been up, which is a
# failure that looks exactly like an idle machine.
#
# Membership comes from compose rather than a label match on the project name:
# compose derives that name from the directory and normalises it, so an app
# under a custom --app-dir would not match its own containers.
#
# Running containers only. A stopped one has no pid and no cgroup, so there is
# nothing to read -- and its ABSENCE from a reading is the honest record of it,
# which the reader turns back into a zero.
container_stats_all() {
	command -v docker >/dev/null 2>&1 || return 0
	docker info >/dev/null 2>&1 || return 0
	for _state in /var/lib/komizo/apps/*.env; do
		[ -f "$_state" ] || continue
		_app="${_state##*/}"; _app="${_app%.env}"
		_dir="$(komizo_state "$_state" APP_DIR)"
		[ -n "$_dir" ] && [ -f "$_dir/compose.yml" ] || continue
		for _cid in $(docker compose -f "$_dir/compose.yml" --project-directory "$_dir" ps -q 2>/dev/null); do
			# One inspect for both fields: this runs per container per minute,
			# and two calls would be twice the docker round trips for one row.
			_info="$(docker inspect "$_cid" -f '{{index .Config.Labels "com.docker.compose.service"}}	{{.State.Pid}}' 2>/dev/null)"
			_svc="${_info%%	*}"
			_cpid="${_info##*	}"
			[ -n "$_svc" ] || continue
			printf 'cstat\t%s\t%s\t%s\n' "$_app" "$_svc" "$(container_stat "$_cpid")"
		done
	done
}
`

// sysHistory is how many derived points are kept. At the five-second poll that
// is about half an hour, which is as far back as a number nobody is storing
// can honestly claim to go.
const sysHistory = 360

// Where a usage bar changes colour. Colour means one thing in this interface --
// fine, worth a look, wrong -- and these are the same three states.
//
// The same pair for all three resources, deliberately. They are different
// quantities with genuinely different meanings at 90% (a full disk is fatal, a
// busy processor is a machine doing its job), but per-resource thresholds would
// be three invented numbers instead of one, and the bar is a glance rather than
// an alarm.
const (
	usageWarn = 0.80
	usageErr  = 0.95
)

// sysSample is one reading: the box, and every container that had a readable
// cgroup at that moment.
type sysSample struct {
	at    time.Time
	cores int
	// Cumulative processor jiffies since boot, and the idle part of them.
	cpuTotal, cpuIdle uint64
	haveCPU           bool

	memTotal, memUsed uint64
	haveMem           bool

	disks []diskUse
	cs    []cgroupStat
	// vols is present only on the readings that measured it -- every fifteenth
	// minute, because it costs a du. A reading without it is not a reading of
	// zero storage, it is a minute nobody asked.
	vols []volRow
}

type diskUse struct {
	mount string
	// dev is the filesystem's device, for folding two mount points that are one
	// filesystem. Empty on records written before it was reported, which is
	// most of any box's system.log.
	dev        string
	used, size uint64
}

func (d diskUse) frac() float64 {
	if d.size == 0 {
		return 0
	}
	return float64(d.used) / float64(d.size)
}

// cgroupStat is one container's cumulative processor time and its memory now.
//
// haveCPU and haveMem are separate from the values because a cgroup this could
// not read is UNKNOWN, and zero would be a measurement -- one saying the
// container is using nothing at all.
type cgroupStat struct {
	app, service string
	cpuUsec      uint64
	haveCPU      bool
	mem          uint64
	haveMem      bool
	limit        uint64 // 0 when the container is not capped
	hasLimit     bool
}

func csKey(app, service string) string { return app + "\x00" + service }

func (c cgroupStat) key() string { return csKey(c.app, c.service) }

// parseSystem reads the resource records out of a host script's output,
// ignoring everything else -- the same output also carries the inventory and
// the request counts.
func parseSystem(out string, at time.Time) sysSample {
	s := sysSample{at: at}
	byKey := map[string]int{}
	out = scrub(out)
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimRight(ln, "\r"), "\t")
		switch {
		case len(f) == 4 && f[0] == "sys":
			a, errA := strconv.ParseUint(f[2], 10, 64)
			b, errB := strconv.ParseUint(f[3], 10, 64)
			if errA != nil || errB != nil {
				continue
			}
			switch f[1] {
			case "cpu":
				s.cpuTotal, s.cpuIdle, s.haveCPU = a, b, true
			case "cores":
				s.cores = int(a)
			case "mem":
				s.memTotal, s.memUsed, s.haveMem = a, b, true
			}

		case (len(f) == 4 || len(f) == 5) && f[0] == "disk":
			// Two shapes: mount/used/size, and mount/device/used/size once the
			// probe learned to report the device. The old one still parses
			// because the box's system.log is full of it.
			d := diskUse{mount: f[1]}
			var errU, errS error
			if len(f) == 5 {
				d.dev = f[2]
				d.used, errU = strconv.ParseUint(f[3], 10, 64)
				d.size, errS = strconv.ParseUint(f[4], 10, 64)
			} else {
				d.used, errU = strconv.ParseUint(f[2], 10, 64)
				d.size, errS = strconv.ParseUint(f[3], 10, 64)
			}
			if errU != nil || errS != nil || d.size == 0 {
				continue
			}
			// Folded when the two are one filesystem. Both / and /var/lib/docker
			// are asked for, and on most boxes they are the same one -- listing
			// it twice would read as twice the disk. The DEVICE is what says so:
			// docker setups routinely bind-mount /var/lib/docker onto itself,
			// which gives one filesystem two mount points, and folding by mount
			// point drew that box's one disk as two identical bars.
			dup := false
			for _, x := range s.disks {
				if x.mount == d.mount || (d.dev != "" && x.dev == d.dev) {
					dup = true
					break
				}
			}
			if !dup {
				s.disks = append(s.disks, d)
			}

		case len(f) == 5 && f[0] == "vol":
			n, err := strconv.ParseUint(f[4], 10, 64)
			if err != nil {
				continue
			}
			s.vols = append(s.vols, volRow{app: f[1], service: f[2], name: f[3], bytes: n})

		case len(f) == 6 && f[0] == "cstat":
			c := cgroupStat{app: f[1], service: f[2]}
			if v, err := strconv.ParseUint(f[3], 10, 64); err == nil {
				c.cpuUsec, c.haveCPU = v, true
			}
			if v, err := strconv.ParseUint(f[4], 10, 64); err == nil {
				c.mem, c.haveMem = v, true
			}
			// "max" is cgroup v2 for uncapped, and v1 writes a number so large
			// it means the same thing. Both are "no limit", which is a fact
			// worth showing -- a container with no ceiling is one that can take
			// the box down with it.
			if f[5] != "" && f[5] != "max" {
				if v, err := strconv.ParseUint(f[5], 10, 64); err == nil && v < 1<<62 {
					c.limit, c.hasLimit = v, true
				}
			}
			// Later records win, so a redeployed container's row replaces the
			// stale one rather than appearing twice.
			if i, ok := byKey[c.key()]; ok {
				s.cs[i] = c
				continue
			}
			byKey[c.key()] = len(s.cs)
			s.cs = append(s.cs, c)
		}
	}
	return s
}

// statFor is one container in one reading. Absent means it was not running --
// a stopped container has no cgroup to read, so there is no record of it.
func (s sysSample) statFor(app, service string) (cgroupStat, bool) {
	for _, c := range s.cs {
		if c.app == app && c.service == service {
			return c, true
		}
	}
	return cgroupStat{}, false
}

// The derived layer: readings in, one series out, per subject.
//
// Nothing is pre-computed into a "point" type any more, and that was the source
// of a family of quiet bugs. A point derived from a PAIR of readings gave
// memory and disk -- which are levels and need no pair -- the lifetime of a
// rate, so the first reading of a session charted nothing and any gap dropped a
// level that was perfectly well known. And a point that could not compute the
// box's processor still carried a zero for it, which is indistinguishable on a
// chart from a genuinely idle machine.
//
// So: readings are stored, and a series is built for the subject being asked
// about. Every value is either a real measurement or NaN, and NaN is drawn as a
// gap. Nothing on the way to a chart may invent a number.

// resSeries is one subject's values against the times they were taken.
type resSeries struct {
	times []time.Time
	vals  []float64 // NaN where the reading could not be taken
}

func (r resSeries) any() bool {
	for _, v := range r.vals {
		if !math.IsNaN(v) {
			return true
		}
	}
	return false
}

func (r resSeries) span() time.Duration {
	if len(r.times) < 2 {
		return 0
	}
	return r.times[len(r.times)-1].Sub(r.times[0])
}

// maxRateGap is how far apart two readings may be and still be differenced.
//
// A cumulative counter across a long hole gives a true average of the hole --
// but dated at its end and drawn as one point, which paints a confident value
// over a stretch nobody measured. Beyond this the interval is left unscored.
const maxRateGap = 5 * time.Minute

// boxCPUAt is the fraction of the whole machine that was busy between two
// readings, or false when it cannot be known.
//
// False rather than zero. This used to return zero whenever /proc/stat could
// not be read or had not moved, which charts as an idle box -- the single most
// misleading thing this screen could say about a machine that is on fire.
func boxCPUAt(prev, cur sysSample) (float64, bool) {
	dt := cur.at.Sub(prev.at)
	if dt <= 0 || dt > maxRateGap {
		return 0, false
	}
	if !prev.haveCPU || !cur.haveCPU || cur.cpuTotal <= prev.cpuTotal {
		return 0, false
	}
	dTotal := cur.cpuTotal - prev.cpuTotal
	var dIdle uint64
	if cur.cpuIdle > prev.cpuIdle {
		dIdle = cur.cpuIdle - prev.cpuIdle
	}
	if dIdle > dTotal {
		dIdle = dTotal
	}
	return float64(dTotal-dIdle) / float64(dTotal), true
}

// containerCPUAt is one container's share of the whole machine.
//
// Three outcomes, and they are genuinely different:
//
//   - absent from the newer reading: it is not running, and zero is the true
//     answer. A container that has died SHOULD take its line to the floor.
//   - present in both, counter moved forward: a rate.
//   - anything else -- just started, restarted, cgroup unreadable: unknown.
//     A fresh cgroup counts from zero, so differencing across a restart invents
//     an enormous spike at exactly the moment somebody is looking.
func containerCPUAt(prev, cur sysSample, app, service string) (float64, bool) {
	dt := cur.at.Sub(prev.at)
	if dt <= 0 || dt > maxRateGap || cur.cores <= 0 {
		return 0, false
	}
	now, running := cur.statFor(app, service)
	if !running {
		return 0, true
	}
	before, was := prev.statFor(app, service)
	if !was || !now.haveCPU || !before.haveCPU || now.cpuUsec < before.cpuUsec {
		return 0, false
	}
	used := time.Duration(now.cpuUsec-before.cpuUsec) * time.Microsecond
	return float64(used) / float64(dt) / float64(cur.cores), true
}

// appCPUAt sums an app's containers.
//
// Unknown if ANY container in it is unknown. A sum that silently omits one
// container is not a smaller number, it is a different quantity -- and it dips
// on every deploy, which reads as the app going quiet at the exact moment it
// was restarted.
// An app with no containers in the reading is not unknown -- it is an app whose
// containers are all stopped, and zero is the true answer. Same rule as one
// container: the thing exists, the interface is showing it because the
// inventory lists it, and nothing of it is running.
func appCPUAt(prev, cur sysSample, app string) (float64, bool) {
	var sum float64
	for _, c := range cur.cs {
		if c.app != app {
			continue
		}
		v, ok := containerCPUAt(prev, cur, app, c.service)
		if !ok {
			return 0, false
		}
		sum += v
	}
	return sum, true
}

func cpuAt(prev, cur sysSample, app, service string) (float64, bool) {
	switch {
	case app == "":
		return boxCPUAt(prev, cur)
	case service != "":
		return containerCPUAt(prev, cur, app, service)
	}
	return appCPUAt(prev, cur, app)
}

// memAt is a level, so one reading answers it. No pair, no interval, no gap
// handling -- which is exactly why it must not be derived alongside the rates.
func memAt(s sysSample, app, service string) (uint64, bool) {
	switch {
	case app == "":
		if !s.haveMem {
			return 0, false
		}
		return s.memUsed, true
	case service != "":
		c, running := s.statFor(app, service)
		if !running {
			return 0, true // stopped, and holding nothing
		}
		if !c.haveMem {
			return 0, false
		}
		return c.mem, true
	}
	var sum uint64
	for _, c := range s.cs {
		if c.app != app {
			continue
		}
		if !c.haveMem {
			return 0, false
		}
		sum += c.mem
	}
	return sum, true
}

func diskAt(s sysSample, mount string) (float64, bool) {
	for _, d := range s.disks {
		if d.mount == mount {
			return d.frac(), true
		}
	}
	return 0, false
}

// cpuSeries is a subject's processor use over a run of readings, as a
// percentage of the whole machine.
//
// One value per reading from the second onwards: a rate belongs to the interval
// BEFORE the reading that closes it, so it is dated at that reading and the
// very first one has none.
func cpuSeries(s []sysSample, app, service string) resSeries {
	var r resSeries
	for i := 1; i < len(s); i++ {
		v, ok := cpuAt(s[i-1], s[i], app, service)
		r.times = append(r.times, s[i].at)
		if ok {
			r.vals = append(r.vals, v*100)
		} else {
			r.vals = append(r.vals, math.NaN())
		}
	}
	return r
}

// memSeries is in MB, which is what a person reads a chart of memory in.
func memSeries(s []sysSample, app, service string) resSeries {
	var r resSeries
	for _, x := range s {
		v, ok := memAt(x, app, service)
		r.times = append(r.times, x.at)
		if ok {
			r.vals = append(r.vals, float64(v)/(1024*1024))
		} else {
			r.vals = append(r.vals, math.NaN())
		}
	}
	return r
}

// diskSeries is how full a filesystem was, as a percentage.
func diskSeries(s []sysSample, mount string) resSeries {
	var r resSeries
	for _, x := range s {
		v, ok := diskAt(x, mount)
		r.times = append(r.times, x.at)
		if ok {
			r.vals = append(r.vals, v*100)
		} else {
			r.vals = append(r.vals, math.NaN())
		}
	}
	return r
}

// storageSeries is what an app or container has been holding on disk.
//
// Only the readings that measured it, at the times they measured it -- the rest
// are skipped rather than charted as gaps. A minute the sampler did not run du
// on is not a hole in the measurement; it is simply not one of the measurements,
// and a series of a hundred NaNs around four real points would say the opposite.
func storageSeries(s []sysSample, app, service string) resSeries {
	var r resSeries
	for _, x := range s {
		if len(x.vols) == 0 {
			continue
		}
		v, ok := volTotal(x.vols, app, service)
		if !ok {
			continue
		}
		r.times = append(r.times, x.at)
		r.vals = append(r.vals, float64(v))
	}
	return r
}

// mountsIn is every filesystem seen across a run of readings, in the order the
// box reported them.
func mountsIn(s []sysSample) []string {
	var out []string
	seen := map[string]bool{}
	for _, x := range s {
		for _, d := range x.disks {
			if !seen[d.mount] {
				seen[d.mount] = true
				out = append(out, d.mount)
			}
		}
	}
	return out
}

// volumeProbe measures volumes with du, for one app or for all of them.
//
// One definition, called two ways: with an app name by the monitor, which wants
// an answer now for the app being looked at, and with none by the sampler,
// which walks the box on a slow cadence so there is a history to chart.
//
// Volumes only. A container's writable layer needs `docker ps -s`, which walks
// every layer of every image and is slow enough to notice -- and it should be
// near nothing anyway, because whatever is written outside a volume is deleted
// by the next deploy. The volumes are where an app's disk actually goes.
const volumeProbe = `
volumes_all() {
	_only="${1:-}"
	command -v docker >/dev/null 2>&1 || return 0
	for _state in /var/lib/komizo/apps/*.env; do
		[ -f "$_state" ] || continue
		_app="${_state##*/}"; _app="${_app%.env}"
		[ -z "$_only" ] || [ "$_app" = "$_only" ] || continue
		_dir="$(komizo_state "$_state" APP_DIR)"
		[ -n "$_dir" ] && [ -f "$_dir/compose.yml" ] || continue
		_ids="$(docker compose -f "$_dir/compose.yml" --project-directory "$_dir" ps -aq 2>/dev/null)"
		[ -n "$_ids" ] || continue
		# service, volume name, and where it lives on the host. One line per
		# mount, so a volume shared by two containers appears under both.
		_pairs="$(docker inspect $_ids --format \
			'{{$s := index .Config.Labels "com.docker.compose.service"}}{{range .Mounts}}{{if eq .Type "volume"}}{{$s}}	{{.Name}}	{{.Source}}
{{end}}{{end}}' 2>/dev/null)"
		# Measured once per volume, then attributed. Two containers sharing one
		# volume must not make it count twice, and du is far too expensive to
		# run twice for the same answer.
		_sizes=""
		for _src in $(printf '%s\n' "$_pairs" | awk -F'\t' 'NF >= 3 && $3 != "" { print $3 }' | sort -u); do
			[ -d "$_src" ] || continue
			_sz="$(du -sxk "$_src" 2>/dev/null | awk '{ print $1 * 1024; exit }')"
			[ -n "$_sz" ] && _sizes="$_sizes$_src	$_sz
"
		done
		printf '%s\n' "$_pairs" | awk -F'\t' -v app="$_app" -v sz="$_sizes" '
			BEGIN {
				n = split(sz, L, "\n")
				for (i = 1; i <= n; i++) {
					split(L[i], p, "\t")
					if (p[1] != "") S[p[1]] = p[2]
				}
			}
			NF >= 3 && S[$3] != "" { printf "vol\t%s\t%s\t%s\t%s\n", app, $1, $2, S[$3] }'
	done
}
`

// storageScript is one app's volumes, measured now.
//
// Kept off the five-second poll: it costs a du of every volume the app mounts,
// which is the only figure on this screen that cannot be read from a counter.
// So it runs once, when the monitor is opened, for the one app being looked at.
func storageScript(app string) string {
	return stateHelper + volumeProbe + fmt.Sprintf("\nvolumes_all %s\n", shQuote(app))
}

// volRow is one volume, as much of the box's disk as one app can account for.
type volRow struct {
	app, service string
	name         string
	bytes        uint64
}

func parseVolumes(out string) []volRow {
	var rows []volRow
	seen := map[string]bool{}
	out = scrub(out)
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimRight(ln, "\r"), "\t")
		if len(f) != 5 || f[0] != "vol" {
			continue
		}
		n, err := strconv.ParseUint(f[4], 10, 64)
		if err != nil {
			continue
		}
		k := f[1] + "\x00" + f[2] + "\x00" + f[3]
		if seen[k] {
			continue
		}
		seen[k] = true
		rows = append(rows, volRow{app: f[1], service: f[2], name: f[3], bytes: n})
	}
	return rows
}

// volTotal adds up what one subject is holding on disk.
//
// A volume mounted by two containers is counted ONCE for the app and once for
// each container that mounts it. Both are right for the question being asked:
// "how much disk is this app using" must not double-count shared storage, and
// "what is this container sitting on" must include storage it shares.
func volTotal(rows []volRow, app, service string) (uint64, bool) {
	var sum uint64
	var any bool
	seen := map[string]bool{}
	for _, r := range rows {
		if app != "" && r.app != app {
			continue
		}
		if service != "" && r.service != service {
			continue
		}
		if service == "" && seen[r.app+"\x00"+r.name] {
			continue
		}
		seen[r.app+"\x00"+r.name] = true
		sum, any = sum+r.bytes, true
	}
	return sum, any
}

// bytesText is a size a person reads rather than counts digits in.
//
// Binary units, because that is what the kernel reported and converting to
// powers of ten to look friendlier would make this disagree with df and free on
// the same box.
func bytesText(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	v := float64(n)
	units := []string{"K", "M", "G", "T", "P"}
	// i lags the loop deliberately: it names the unit already divided BY, so
	// the first division lands on K rather than skipping past it to M.
	i := -1
	for v >= unit && i < len(units)-1 {
		v /= unit
		i++
	}
	if v < 10 {
		return fmt.Sprintf("%.1f%s", v, units[i])
	}
	return fmt.Sprintf("%.0f%s", v, units[i])
}

func pctText(f float64) string {
	if f < 0 {
		f = 0
	}
	return fmt.Sprintf("%.0f%%", f*100)
}

// takeSample keeps the newest reading and the recent ones.
//
// Readings, not derived rates. A rate belongs to a pair, and storing only pairs
// meant memory and disk -- which need no pair at all -- inherited a rate's
// requirements and went missing whenever one could not be formed.
//
// The oldest are dropped rather than the buffer grown, so a session left open
// overnight costs the same as one opened a minute ago.
func (m *model) takeSample(s sysSample) {
	if s.at.IsZero() {
		return
	}
	m.sysSamples = append(m.sysSamples, s)
	if n := len(m.sysSamples) - sysHistory; n > 0 {
		m.sysSamples = append([]sysSample(nil), m.sysSamples[n:]...)
	}
	m.sys, m.sysHave = s, true
}

// Where the sampler writes and how much it keeps.
//
// Under /var/lib rather than /srv: /srv is apps, and is mounted into the proxy.
// This is the server's own record and belongs to nothing that ships.
const (
	systemLog = "/var/lib/komizo/system.log"
	// Trimmed by BYTES, not by age. Age would make retention depend on how many
	// containers the box runs -- twenty containers would keep a fifth as long as
	// four for the same disk -- and the thing actually worth bounding is the
	// disk. Roughly a week at a handful of containers.
	systemLogMax  = 8000000
	systemLogKeep = 60000 // lines kept when it is trimmed

	// How often the sampler measures volumes, in minutes.
	//
	// Not every minute, and this is the one measurement that has to be rationed.
	// Everything else here is a counter read -- open a file, read a number. Disk
	// use needs du, which walks the whole tree, and walking a database volume
	// sixty times an hour would make watching the box the heaviest thing
	// happening on it.
	//
	// A quarter hour loses nothing worth having. Storage moves in the direction
	// of full, slowly, and the question it answers -- "what is filling this
	// disk, and how fast" -- is not one that a minute's resolution answers any
	// better than fifteen.
	volEveryMinutes = 15
)

// samplerScript installs the per-minute sampler and makes sure cron is running.
//
// This exists because /proc has no history. The request charts read a log the
// box keeps whether anything is watching or not, and the resource charts had
// nothing equivalent -- what komizo sampled while it happened to be open, gone
// on quit. So something on the box has to write them down, and the smallest
// thing that can is a shell script and a crontab line.
//
// One record per minute, of the same counters the live poll reads: the reader
// subtracts consecutive samples exactly as it does for the live ones, so a
// minute of history and a five-second gap go through identical arithmetic.
//
// Safe to re-run. It is written every time rather than checked for, so a komizo
// that has learned to read something new installs a sampler that writes it.
func samplerScript() string {
	return fmt.Sprintf(installerTemplate, systemLog, samplerFile(), systemLogMax,
		systemLogKeep, volEveryMinutes, systemLog+".lock", komizoStamp(), versionText())
}

// komizoStamp is what komizo has installed on a box, and how the interface can
// tell whether it is current.
//
// A hash of the sampler rather than a version number anybody has to remember to
// bump. The release version IS recorded too, and shown -- "which komizo set this
// box up" is a fair question -- but the version is not what decides "up to
// date": that question is "would running the update change anything", and only
// the content of what gets written can answer it. A version alone answers it
// wrongly the first time somebody edits the script without touching the version,
// which is every edit during development, when the version is "dev" throughout.
//
// Twelve hex characters, like the config SHAs on the app rows, so the two read
// as the same kind of fact.
func komizoStamp() string {
	sum := sha256.Sum256([]byte(samplerFile()))
	return hex.EncodeToString(sum[:])[:12]
}

// samplerFile is the script cron runs, exactly as it lands on the box.
func samplerFile() string {
	return fmt.Sprintf(samplerTemplate, systemLog, stateHelper+systemProbe+volumeProbe,
		systemLogMax, systemLogKeep, volEveryMinutes, systemLog+".lock")
}

const installerTemplate = `
set -eu
log() { printf '\n==> %%s\n' "$*"; }

log "Installing the resource sampler"
mkdir -p /var/lib/komizo
chmod 750 /var/lib/komizo

# Quoted delimiter: everything between here and the end marker is written
# literally, so the probe's own $variables survive into the installed script
# instead of being expanded once, now, against this shell.
cat > /usr/local/bin/komizo-sample <<'KOMIZO_SAMPLER_EOF'
%[2]s
KOMIZO_SAMPLER_EOF
chmod 755 /usr/local/bin/komizo-sample

# The crontab line is replaced rather than appended to, so re-running setup on a
# box that already has one leaves one and not two.
mkdir -p /etc/crontabs
touch /etc/crontabs/root
grep -v 'komizo-sample' /etc/crontabs/root > /etc/crontabs/root.tmp 2>/dev/null || true
printf '* * * * * /usr/local/bin/komizo-sample\n' >> /etc/crontabs/root.tmp
mv /etc/crontabs/root.tmp /etc/crontabs/root

# busybox crond is installed on Alpine but not necessarily running, and a
# crontab nothing reads is the quietest possible failure: every screen looks
# right and the history is simply always empty.
if command -v rc-update >/dev/null 2>&1; then
	rc-update add crond default >/dev/null 2>&1 || true
	rc-service crond start >/dev/null 2>&1 || rc-service crond restart >/dev/null 2>&1 || true
fi

# Written now rather than waiting up to a minute for cron, so the first reading
# exists by the time anyone opens the monitor -- and so a sampler that cannot
# run fails HERE, visibly, in the output of the thing that installed it.
/usr/local/bin/komizo-sample

# Two lines, written together: the komizo VERSION that set this box up, and the
# content STAMP of what it wrote. The version is what the interface shows beside
# the CLI's own -- "which komizo provisioned this box" -- and the stamp is the
# separate, exact answer to "would running the update change anything". An update
# rewrites both, so after one the box reads as the version in your hand.
printf '%%s\n%%s\n' %[8]q %[7]q > /var/lib/komizo/version

if [ -s %[1]s ]; then
	log "Sampling this machine every minute into %[1]s"
else
	printf 'warning: the sampler wrote nothing -- resource history will be empty\n' >&2
fi
`

// systemLogScript reads back what the sampler wrote in a range.
//
// Bounded by bytes as well as by time, for the same reason the access log is:
// the tail is the part anyone is asking about, and a file that has grown must
// not turn into a growing scan.
func systemLogScript(r timeRange) string {
	return fmt.Sprintf(`
if [ -f %[1]s ]; then
	tail -c 4000000 %[1]s 2>/dev/null | awk -F'\t' -v from=%[2]d -v to=%[3]d '
		$1 == "S" && $2 + 0 >= from && $2 + 0 <= to'
fi
`, systemLog, r.from, r.to)
}

// parseSystemLog turns the sampler's records back into readings, one per
// timestamp, oldest first.
//
// Each reading is handed to the same parseSystem the live poll uses -- the
// sampler writes the probe's output verbatim behind a timestamp, so there is
// one parser for both and no second format to keep in step.
func parseSystemLog(out string) []sysSample {
	byTS := map[int64]*strings.Builder{}
	var order []int64
	for _, ln := range strings.Split(out, "\n") {
		f := strings.SplitN(strings.TrimRight(ln, "\r"), "\t", 3)
		if len(f) != 3 || f[0] != "S" {
			continue
		}
		ts, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			continue
		}
		b, ok := byTS[ts]
		if !ok {
			b = &strings.Builder{}
			byTS[ts] = b
			order = append(order, ts)
		}
		b.WriteString(f[2])
		b.WriteString("\n")
	}
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })

	out2 := make([]sysSample, 0, len(order))
	for _, ts := range order {
		out2 = append(out2, parseSystem(byTS[ts].String(), time.Unix(ts, 0)))
	}
	return out2
}

// samplerTemplate is the sampler as it lands on the box.
const samplerTemplate = `#!/bin/sh
# Written by komizo. Edits are lost the next time the server is set up.
#
# One reading of this machine, appended to a log. Run by cron every minute.
set -u
LOG=%[1]q
LOCK=%[6]q
now="$(date +%%s)"

# One sampler at a time. Every minute is comfortable for counter reads, and then
# every fifteenth minute runs du over the volumes -- which on a large one can
# outlast the minute it started in. Two overlapping runs would interleave their
# lines into the log, and a half of one reading merged with a half of another is
# worse than a missing minute: it looks like a reading.
#
# mkdir because it is atomic on every filesystem this will ever run on. A lock
# left behind by a kill -9 is cleared once it is older than any honest run.
if [ -d "$LOCK" ] && [ -z "$(find "$LOCK" -maxdepth 0 -mmin +20 2>/dev/null)" ]; then
	exit 0
fi
rm -rf "$LOCK" 2>/dev/null || true
mkdir "$LOCK" 2>/dev/null || exit 0
trap 'rmdir "$LOCK" 2>/dev/null || true' EXIT INT TERM

# The whole reading is built before ANY of it is written. A sampler killed
# half way through a slow docker call would otherwise leave a partial minute
# in the log -- a box that appears to have lost containers for one minute,
# which is exactly the shape of the incident somebody would come here to
# investigate.
out="$(
%[2]s
container_stats_all
# Volumes on a slower cadence than everything else, because they cost a du
# rather than a file read. Keyed off the clock rather than off a counter kept
# somewhere, so it stays on the same quarter-hours across reboots and re-installs.
#
# Inside this block, and after it, deliberately: the probe DEFINES volumes_all,
# and a shell runs a file as it reads it -- so calling it above would be calling
# a function that does not exist yet, on a line that then quietly produces
# nothing. Which is the same failure the sampler already shipped once.
# Also on the very first run, whether or not the clock has reached a quarter
# hour. Otherwise a box set up at 11:07 records no storage at all until 11:15,
# and needs a second one at 11:30 before there are two points to draw a line
# between -- so the chart is missing for the first half hour after installing
# the thing that draws it, which reads as broken rather than as new.
if [ ! -f "$LOG" ] || [ "$(( now / 60 %% %[5]d ))" -eq 0 ]; then
	volumes_all
fi
)"
[ -n "$out" ] || exit 0
printf '%%s\n' "$out" | sed "s/^/S	$now	/" >> "$LOG"

# Trimmed only when it has grown, rather than rewritten every minute: the copy
# costs the whole file, and paying that once every few days is the difference
# between a cron job nobody notices and one that shows up in iowait.
if [ "$(wc -c < "$LOG" 2>/dev/null || echo 0)" -gt %[3]d ]; then
	tail -n %[4]d "$LOG" > "$LOG.tmp" 2>/dev/null && mv "$LOG.tmp" "$LOG"
fi`
