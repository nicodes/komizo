package box

import "time"

// What the machine is spending: processor, memory, disk, and the same per
// container.
//
// CUMULATIVE COUNTERS, not rates. A rate needs two readings and a report is one
// of them -- the reader keeps the previous sample and does the subtraction.
// That also makes the interval explicit rather than assumed: a poll that
// arrived late measures the longer gap it actually covered.

// System is one reading of what the box is spending.
type System struct {
	// Cores is the processor count -- the divisor that turns jiffies into a
	// percentage the same way top does.
	Cores int `json:"cores,omitempty"`
	// CPU is cumulative jiffies since boot. Idle counts iowait with it: waiting
	// on a disk is not work, and counting it as busy makes a box that is merely
	// reading from a slow disk look loaded.
	CPU *CPU `json:"cpu,omitempty"`
	// Mem is measured from MemAvailable, never MemFree. Free memory on a healthy
	// box is near zero -- the kernel spends everything spare on cache and hands
	// it back on demand -- so reporting free as used is the classic way to make
	// every server on earth look seconds from death.
	Mem *Mem `json:"mem,omitempty"`

	// Disks covers / and /var/lib/docker, because the one that fills is usually
	// not the one people watch. The device travels with the numbers so a reader
	// can fold the two when they are one filesystem -- by device, not mount
	// point, because docker setups routinely bind-mount /var/lib/docker onto
	// itself and df then reports one filesystem under two names.
	Disks []Disk `json:"disks,omitempty"`

	// Containers is per-container processor time and memory, read from the
	// cgroup -- which is where the kernel does the accounting anyway. `docker
	// stats` reads the same files and then streams, which is why it costs a
	// second per call; this is three small reads with no daemon in the path.
	//
	// Running containers only. A stopped one has no pid and no cgroup, so there
	// is nothing to read, and its ABSENCE is the honest record of that.
	Containers []ContainerStat `json:"containers,omitempty"`

	// Volumes is present only on the readings that measured it -- roughly every
	// fifteenth minute, because it costs a du over the whole tree. A reading
	// without it is not a reading of zero storage, it is a minute nobody asked.
	Volumes []Volume `json:"volumes,omitempty"`
}

// CPU is cumulative processor jiffies since boot.
type CPU struct {
	Total uint64 `json:"total"`
	Idle  uint64 `json:"idle"`
}

// Mem is memory as of now, in bytes.
type Mem struct {
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
}

// Disk is one filesystem's used and total bytes.
//
// Used and available rather than the filesystem's raw size, because df computes
// its own percentage that way -- excluding the blocks reserved for root -- and
// a disk figure that disagrees with df on the very same box is one nobody will
// believe, however defensible the arithmetic behind it.
type Disk struct {
	Mount string `json:"mount"`
	Dev   string `json:"dev,omitempty"`
	Used  uint64 `json:"used"`
	Size  uint64 `json:"size"`
}

// ContainerStat is one container's cumulative processor time and memory now.
//
// The pointers are the point: a cgroup that could not be read is UNKNOWN, and a
// zero would be a measurement -- one saying the container is using nothing at
// all. Blanks travel as blanks.
type ContainerStat struct {
	App     string `json:"app"`
	Service string `json:"service"`
	// CPUUsec is microseconds, normalised here. cgroup v1 reports nanoseconds
	// and v2 microseconds; converting at the source means no reader ever has to
	// know which kind of box it is talking to.
	CPUUsec *uint64 `json:"cpu_usec,omitempty"`
	// Mem excludes inactive page cache, the convention `docker stats` follows
	// and the honest one: cache is memory the container is BORROWING and the
	// kernel will take straight back under pressure. Counting it makes anything
	// that has ever read a large file look permanently swollen.
	Mem *uint64 `json:"mem,omitempty"`
	// Limit is the container's memory cap, absent when it is not capped.
	Limit *uint64 `json:"limit,omitempty"`
}

// Volume is one docker volume's size on disk, attributed to the service that
// mounts it.
//
// Measured once per volume and then attributed, so a volume shared by two
// containers does not count twice -- and because du is far too expensive to run
// twice for the same answer.
type Volume struct {
	App     string `json:"app"`
	Service string `json:"service"`
	Name    string `json:"name"`
	Bytes   uint64 `json:"bytes"`
}

// Sample is one timestamped reading, as written to the history log.
//
// The report is what the box is NOW; this is what it was. They carry the same
// System because they are the same measurement -- one kept, one current.
type Sample struct {
	At     time.Time `json:"at"`
	System System    `json:"system"`
}

// Metrics is request counts over a window, read off the shared proxy's access
// log and attributed to apps.
//
// The proxy is the one place on the box that sees every request, and it is
// komizo's own component rather than anything an app ships -- so this needs
// nothing from apps and works the same for an app running nginx as for one
// running Caddy. The join is the hostname: every app declares the names it
// answers on, and the deploy script records them at /srv/<app>/hostnames.
//
// COUNTS, NEVER LINES. The box does the totalling and reports one record per
// minute per app; raw log lines -- which carry client IPs and request paths --
// never leave the machine. This is a promise, not an optimisation, and it is
// why this type has no field that could hold one.
type Metrics struct {
	// Span is what the log itself covers, which is not the same as the range
	// asked for. Without it every minute before the log started charts as zero
	// -- a confident claim that nothing was served, drawn over a stretch nobody
	// recorded.
	Span *Span    `json:"span,omitempty"`
	Rows []Metric `json:"rows"`
}

// Span is the oldest and newest request the log holds.
type Span struct {
	From int64 `json:"from"`
	To   int64 `json:"to"`
}

// Metric is one minute of one app's traffic, split by status class.
//
// Split rather than totalled because the two questions are different: "is
// anything reaching this" and "is any of it failing". A single number answers
// neither on its own.
type Metric struct {
	// Minute is unix seconds truncated to the minute.
	Minute int64  `json:"minute"`
	App    string `json:"app"`
	// Service is the container the app said serves the hostname these counts
	// came from, or empty when it said nothing. Summing over it gives the app;
	// filtering on it gives the container.
	Service string `json:"service,omitempty"`
	C2      int    `json:"c2,omitempty"`
	C3      int    `json:"c3,omitempty"`
	C4      int    `json:"c4,omitempty"`
	C5      int    `json:"c5,omitempty"`
}

func (m Metric) Total() int { return m.C2 + m.C3 + m.C4 + m.C5 }
