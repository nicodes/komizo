package app

import (
	"fmt"
	"math"
	"time"

	"github.com/nicodes/komizo/internal/agent"
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
	// csIndex finds a container in cs without walking it.
	//
	// The charts ask this question a great many times. One app's processor rate
	// over a window is a lookup per container per PAIR of readings, and the
	// monitor recomputes the whole window on every frame -- so a linear scan
	// made the cost of drawing grow with the SQUARE of the number of containers
	// on the box. Measured over a day of samples: 2.7ms at ten containers,
	// 19.5ms at forty, per series, per frame, with six panels on screen.
	//
	// Built in parseSystem, which already had this exact map to collapse
	// duplicate records and threw it away.
	//
	// Nil on a sysSample built by hand -- tests do that -- and statFor falls
	// back to the scan, so it stays a pure optimisation rather than a second
	// way to be wrong.
	csIndex map[string]int
	// vols is present only on the readings that measured it -- every fifteenth
	// minute, because it costs a du. A reading without it is not a reading of
	// zero storage, it is a minute nobody asked.
	vols []volRow
}

type diskUse struct {
	mount string
	// dev is the filesystem's device, for folding two mount points that are one
	// filesystem. Empty on records written before it was reported, which is
	// most of any box's history.
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

// statFor is one container in one reading. Absent means it was not running --
// a stopped container has no cgroup to read, so there is no record of it.
func (s sysSample) statFor(app, service string) (cgroupStat, bool) {
	if s.csIndex != nil {
		i, ok := s.csIndex[csKey(app, service)]
		if !ok {
			return cgroupStat{}, false
		}
		return s.cs[i], true
	}
	// A sample built by hand rather than parsed. Same answer, slower.
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
// are skipped rather than charted as gaps. A minute the agent did not measure
// volumes on is not a hole in the measurement; it is simply not one of them,
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

// volRow is one volume, as much of the box's disk as one app can account for.
type volRow struct {
	app, service string
	name         string
	bytes        uint64
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
	// Shifted in place rather than copied into a fresh slice. The old form
	// allocated a new 360-element backing array on every poll once the buffer
	// was full -- once every five seconds, forever, for a window left open --
	// to drop one reading off the front. copy reuses the array it already has.
	if n := len(m.sysSamples) - sysHistory; n > 0 {
		m.sysSamples = m.sysSamples[:copy(m.sysSamples, m.sysSamples[n:])]
	}
	m.sys, m.sysHave = s, true
}

// komizoStamp is what komizo has installed on a box, and how the interface can
// tell whether it is current.
//
// A hash of the AGENT BINARIES, which are what an update installs, rather than
// a version number anybody has to remember to bump. The release version IS
// recorded too, and shown -- "which komizo set this box up" is a fair question
// -- but the version is not what decides "up to date": that question is "would
// running the update change anything", and only the content can answer it. A
// version alone answers it wrongly the first time somebody changes the agent
// without touching the version, which is every change during development, when
// the version is "dev" throughout.
//
// It covers every architecture komizo carries, so two boxes running the same
// release agree about whether they are current even when one is arm64.
//
// Twelve hex characters, like the config SHAs on the app rows, so the two read
// as the same kind of fact.
func komizoStamp() string { return agent.Stamp() }
