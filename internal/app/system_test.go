package app

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/scripts"
)

// A reading as the agent reports it: the box's counters, its filesystems, and a
// container per entry.
//
// ONE disk, because that is what an agent sends. / and /var/lib/docker are
// measured separately and are usually the same filesystem; the agent folds them
// before reporting -- see box.Probe.disks and TestOneFilesystemUnderTwoMounts.
// A fixture with two would be asserting the reader folds, which it does not and
// must not: two implementations of one rule is how they come to disagree.
func sysFixture() box.System {
	return box.System{
		Cores: 2,
		CPU:   cpuOf(100000, 90000),
		Mem:   memOf(2000000000, 500000000),
		Disks: []box.Disk{diskOf("/", "vda1", 3000000000, 10000000000)},
		Containers: []box.ContainerStat{
			{App: "blog", Service: "api", CPUUsec: u64(1000000), Mem: u64(50000000), Limit: u64(268435456)},
			cstatOf("blog", "db", 2000000, 90000000),
		},
	}
}

// The adapter is where a report becomes the rows the charts are drawn from, so
// it is where "unknown is not zero" either holds or quietly stops holding.
func TestAReadingBecomesASample(t *testing.T) {
	s := sysSampleFrom(sysFixture(), time.Unix(1000, 0))

	if !s.haveCPU || s.cpuTotal != 100000 || s.cpuIdle != 90000 {
		t.Errorf("cpu = %d/%d have=%v", s.cpuTotal, s.cpuIdle, s.haveCPU)
	}
	if s.cores != 2 {
		t.Errorf("cores = %d, want 2", s.cores)
	}
	if !s.haveMem || s.memTotal != 2000000000 || s.memUsed != 500000000 {
		t.Errorf("mem = %d of %d", s.memUsed, s.memTotal)
	}

	if len(s.disks) != 1 || s.disks[0].mount != "/" {
		t.Fatalf("disks = %+v, want one entry for /", s.disks)
	}
	if got := s.disks[0].frac(); got < 0.29 || got > 0.31 {
		t.Errorf("disk fraction = %v, want ~0.3", got)
	}

	if len(s.cs) != 2 {
		t.Fatalf("containers = %+v, want 2", s.cs)
	}
	api, ok := s.statFor("blog", "api")
	if !ok || !api.hasLimit || api.limit != 268435456 {
		t.Errorf("api limit = %d have=%v", api.limit, api.hasLimit)
	}
	// A container with no ceiling is a fact worth showing, not a missing
	// number. The agent reports the limit absent rather than as zero.
	db, _ := s.statFor("blog", "db")
	if db.hasLimit {
		t.Errorf("db reported a limit of %d, but it is uncapped", db.limit)
	}
}

// A cgroup that could not be read is UNKNOWN. Zero would be a measurement --
// one saying the container is using nothing at all. The agent sends nothing,
// and this is the assertion that nothing does not become a number on the way in.
func TestAnUnreadableCgroupIsNotZero(t *testing.T) {
	s := sysSampleFrom(box.System{
		Containers: []box.ContainerStat{{App: "blog", Service: "api"}},
	}, time.Unix(1000, 0))
	if len(s.cs) != 1 {
		t.Fatalf("want the container listed anyway, got %+v", s.cs)
	}
	if s.cs[0].haveCPU || s.cs[0].haveMem {
		t.Errorf("absent readings became values: %+v", s.cs[0])
	}
}

// at builds a reading, with the counters given, so a test can say what changed
// between two of them and nothing else.
func at(sec int64, cpuTotal, cpuIdle int, apiCPU string) sysSample {
	sys := sysFixture()
	sys.CPU = cpuOf(uint64(cpuTotal), uint64(cpuIdle))
	// An empty string is a cgroup that could not be read, which travels as an
	// absent value rather than as a zero.
	if apiCPU == "" {
		sys.Containers[0].CPUUsec = nil
	} else {
		var n uint64
		fmt.Sscanf(apiCPU, "%d", &n)
		sys.Containers[0].CPUUsec = &n
	}
	return sysSampleFrom(sys, time.Unix(sec, 0))
}

func TestRatesComeFromTheGapBetweenTwoReadings(t *testing.T) {
	prev, cur := at(1000, 100000, 90000, "1000000"), at(1010, 100200, 90150, "6000000")

	// 200 jiffies passed and 150 of them were idle.
	v, ok := boxCPUAt(prev, cur)
	if !ok || v < 0.24 || v > 0.26 {
		t.Errorf("box cpu = %v ok=%v, want 0.25", v, ok)
	}
	// Five seconds of processor time in ten seconds of wall clock, on a
	// two-core box: a quarter of the machine. Of the WHOLE machine rather than
	// of one core, so this and the box's own number are comparable.
	v, ok = cpuAt(prev, cur, "blog", "api")
	if !ok || v < 0.24 || v > 0.26 {
		t.Errorf("api cpu = %v ok=%v, want 0.25 of the machine", v, ok)
	}
	// Memory is a level: one reading answers it, no interval required.
	if got, ok := memAt(cur, "blog", "api"); !ok || got != 50000000 {
		t.Errorf("api mem = %d ok=%v", got, ok)
	}
}

// Zero is a measurement, and for a processor it is the single most misleading
// thing this screen could say: an idle machine. Anything that cannot be
// computed has to come back as "no answer" instead.
func TestAnUnreadableProcessorIsNotZero(t *testing.T) {
	cur := at(1010, 100200, 90150, "6000000")

	// No /proc/stat in the older reading.
	blind := sysSampleFrom(box.System{Cores: 2}, time.Unix(1000, 0))
	if _, ok := boxCPUAt(blind, cur); ok {
		t.Error("a reading with no cpu counter should give no rate")
	}
	// A counter that did not move. Impossible in practice, which is exactly why
	// it means something is wrong with the reading rather than with the box.
	if _, ok := boxCPUAt(at(1000, 100200, 90150, "1000000"), cur); ok {
		t.Error("an unmoved counter should give no rate")
	}
	// A gap too long to difference across.
	if _, ok := boxCPUAt(at(0, 1, 1, "1000000"), cur); ok {
		t.Error("a rate should not be computed across a long gap")
	}
}

// A restarted container has a fresh cgroup, so its counter goes backwards.
// There is no interval to measure across that, and the difference taken anyway
// would be an enormous fabricated spike at exactly the moment somebody is
// looking at the screen to find out what happened.
func TestARestartProducesNoProcessorPointRatherThanASpike(t *testing.T) {
	prev, cur := at(1000, 100000, 90000, "1000000"), at(1010, 100200, 90150, "2000")
	if v, ok := cpuAt(prev, cur, "blog", "api"); ok {
		t.Errorf("a restart produced a cpu reading of %v", v)
	}
	// Memory still reports: it is a level, not a difference, so a restart makes
	// it smaller rather than meaningless.
	if _, ok := memAt(cur, "blog", "api"); !ok {
		t.Error("memory should still be readable across a restart")
	}
}

// A container that is not in the reading at all is not running, and zero is the
// true answer -- a container that has died should take its line to the floor.
// A container that IS there but whose cgroup could not be read is unknown.
func TestStoppedIsZeroAndUnreadableIsUnknown(t *testing.T) {
	prev := at(1000, 100000, 90000, "1000000")
	// The container is simply ABSENT from the reading, which is how a stopped
	// one is reported: no pid, no cgroup, nothing to read.
	goneSys := sysFixture()
	goneSys.Containers = goneSys.Containers[1:]
	gone := sysSampleFrom(goneSys, time.Unix(1010, 0))
	if v, ok := cpuAt(prev, gone, "blog", "api"); !ok || v != 0 {
		t.Errorf("a stopped container = %v ok=%v, want 0", v, ok)
	}
	if v, ok := memAt(gone, "blog", "api"); !ok || v != 0 {
		t.Errorf("a stopped container holds %d ok=%v, want 0", v, ok)
	}

	// Present but unreadable: the agent lists the container and sends no
	// numbers with it.
	blindSys := sysFixture()
	blindSys.Containers[0] = box.ContainerStat{App: "blog", Service: "api"}
	blind := sysSampleFrom(blindSys, time.Unix(1010, 0))
	if _, ok := memAt(blind, "blog", "api"); ok {
		t.Error("an unreadable cgroup should not report a memory figure")
	}
}

// An app's processor is the sum of its containers -- and unknown if any one of
// them is unknown. A sum that silently omits a container is not a smaller
// number, it is a different quantity, and it dips on every deploy: the app
// appears to go quiet at the exact moment it was restarted.
func TestAnAppIsUnknownWhenAnyOfItsContainersIs(t *testing.T) {
	prev, cur := at(1000, 100000, 90000, "1000000"), at(1010, 100200, 90150, "6000000")
	// db moved too, so the app is api + db.
	v, ok := cpuAt(prev, cur, "blog", "")
	if !ok || v < 0.24 || v > 0.26 {
		t.Errorf("blog cpu = %v ok=%v, want api's 0.25 plus db's nothing", v, ok)
	}

	// Now restart db. The app's own line goes unknown for that one interval
	// rather than reporting api alone as though it were the whole app.
	restartedSys := sysFixture()
	restartedSys.CPU = cpuOf(100200, 90150)
	restartedSys.Containers[0] = cstatOf("blog", "api", 6000000, 50000000)
	// db's counter went BACKWARDS, which is what a restart looks like: a fresh
	// cgroup counting from zero.
	restartedSys.Containers[1] = cstatOf("blog", "db", 5, 90000000)
	restarted := sysSampleFrom(restartedSys, time.Unix(1010, 0))
	if v, ok := cpuAt(prev, restarted, "blog", ""); ok {
		t.Errorf("the app reported %v while one of its containers was unknown", v)
	}
	// The box is not that sum and is unaffected: the difference is the kernel,
	// sshd, docker itself and komizo's own poll.
	if _, ok := cpuAt(prev, restarted, "", ""); !ok {
		t.Error("the box's own counter should be unaffected by a container restart")
	}
}

func TestAVolumeTwoContainersShareIsCountedOnceForTheApp(t *testing.T) {
	rows := volumesFromBox([]box.Volume{
		volOf("blog", "api", "blog_data", 100),
		volOf("blog", "db", "blog_data", 100),
		volOf("blog", "db", "blog_uploads", 50),
	})
	if len(rows) != 3 {
		t.Fatalf("rows = %+v", rows)
	}
	// The app is holding 150 bytes of disk, not 250: one volume mounted twice
	// is one volume.
	if got, _ := volTotal(rows, "blog", ""); got != 150 {
		t.Errorf("app total = %d, want 150", got)
	}
	// A container's own line DOES include storage it shares, because the
	// question there is what this container is sitting on.
	if got, _ := volTotal(rows, "blog", "db"); got != 150 {
		t.Errorf("db total = %d, want 150", got)
	}
	if got, _ := volTotal(rows, "blog", "api"); got != 100 {
		t.Errorf("api total = %d, want 100", got)
	}
}

func TestSizesReadTheWayDfPrintsThem(t *testing.T) {
	for _, c := range []struct {
		in   uint64
		want string
	}{
		{512, "512B"},
		{1024, "1.0K"},
		{1536, "1.5K"},
		{1024 * 1024, "1.0M"},
		{20 * 1024 * 1024, "20M"},
		{3 * 1024 * 1024 * 1024, "3.0G"},
	} {
		if got := bytesText(c.in); got != c.want {
			t.Errorf("bytesText(%d) = %s, want %s", c.in, got, c.want)
		}
	}
}

func sampledLog() []box.Sample {
	return []box.Sample{
		sample(1785232675, box.System{
			Cores:      16,
			CPU:        cpuOf(374177611, 356049689),
			Mem:        memOf(32713216000, 17545588736),
			Disks:      []box.Disk{diskOf("/", "vda1", 175837097984, 1018959839232)},
			Containers: []box.ContainerStat{cstatOf("blog", "api", 1000000, 50000000)},
		}),
		sample(1785232676, box.System{
			Cores:      16,
			CPU:        cpuOf(374179265, 356051248),
			Mem:        memOf(32713216000, 17529319424),
			Disks:      []box.Disk{diskOf("/", "vda1", 175837097984, 1018959839232)},
			Containers: []box.ContainerStat{cstatOf("blog", "api", 1400000, 50000000)},
		}),
	}
}

func TestReadingsComeBackAsASeries(t *testing.T) {
	s := histOf(sampledLog()...)
	if len(s) != 2 {
		t.Fatalf("got %d readings, want 2", len(s))
	}
	// Oldest first, so consecutive pairs can be differenced in order.
	if !s[0].at.Before(s[1].at) {
		t.Errorf("readings are out of order: %v then %v", s[0].at, s[1].at)
	}
	if s[0].cores != 16 || !s[0].haveCPU || !s[0].haveMem {
		t.Errorf("first reading is incomplete: %+v", s[0])
	}
	// Parsed by exactly the same code the live poll uses, so the duplicate
	// filesystem is folded here too.
	if len(s[0].disks) != 1 {
		t.Errorf("disks = %+v, want one filesystem", s[0].disks)
	}

	// 1654 jiffies passed, 1559 of them idle: about 6% busy.
	if v, ok := boxCPUAt(s[0], s[1]); !ok || v < 0.05 || v > 0.07 {
		t.Errorf("box cpu = %v ok=%v, want ~0.057", v, ok)
	}
	// 0.4s of processor in 1s of wall clock across 16 cores.
	if v, ok := cpuAt(s[0], s[1], "blog", "api"); !ok || v < 0.024 || v > 0.026 {
		t.Errorf("api cpu = %v ok=%v, want 0.025 of the machine", v, ok)
	}
}

// The box was down, or the agent was killed. A cumulative
// counter differenced across the hole gives a true average OF the hole, dated
// at its end and drawn as one point -- a confident value painted over a stretch
// nobody measured.
func TestAGapInTheRecordIsNotBridged(t *testing.T) {
	var ss []box.Sample
	for _, ts := range []int64{1000, 1060, 1120, 100000, 100060} {
		ss = append(ss, sample(ts, box.System{Cores: 2, CPU: cpuOf(uint64(1000+ts), uint64(500+ts))}))
	}
	r := cpuSeries(histOf(ss...), "", "")
	if len(r.vals) != 4 {
		t.Fatalf("got %d values for five readings, want 4", len(r.vals))
	}
	// The one closing the gap is a gap itself; the rest are real.
	for i, v := range r.vals {
		gap := r.times[i].Unix() == 100000
		if gap != math.IsNaN(v) {
			t.Errorf("value at %v = %v, gap=%v", r.times[i].Unix(), v, gap)
		}
	}
}

// The box's own record is the better source: it covers hours, it survives
// quitting, and it exists whether anything was watching. What this session
// happened to sample is the fallback, and the caption has to say which.
func TestTheChartedNumbersAreTheArithmetic(t *testing.T) {
	start := int64(1785200000) / 60 * 60
	var log []box.Sample
	cpuTotal, cpuIdle, apiUsec := 1000000, 900000, 5000000
	for i := 0; i < 120; i++ {
		ts := start + int64(i)*60
		if i >= 70 && i < 76 {
			continue // cron stopped
		}
		busy, api := 0.10, 0.05
		if i >= 95 && i < 105 {
			busy, api = 0.60, 0.35
		}
		cpuTotal += 6000
		cpuIdle += int(6000 * (1 - busy))
		apiUsec += int(api * 2 * 60 * 1000000) // cores x seconds x usec
		if i == 110 {
			apiUsec = 1000 // restarted: a fresh cgroup counts from zero
		}
		log = append(log, sample(ts, box.System{
			Cores: 2,
			CPU:   cpuOf(uint64(cpuTotal), uint64(cpuIdle)),
			Mem:   memOf(2000000000, uint64(500000000+i*1000000)),
			Containers: []box.ContainerStat{
				cstatOf("blog", "api", uint64(apiUsec), 300*1024*1024),
				cstatOf("blog", "db", uint64(1000000+i*1000000), 90*1024*1024),
			},
		}))
	}

	hist := histOf(log...)
	whole := cpuSeries(hist, "", "")
	api := cpuSeries(hist, "blog", "api")
	app := cpuSeries(hist, "blog", "")

	valueAt := func(r resSeries, min int) float64 {
		for i, tm := range r.times {
			if tm.Unix() == start+int64(min)*60 {
				return r.vals[i]
			}
		}
		t.Fatalf("no value at minute %d", min)
		return 0
	}
	near := func(name string, got, want float64) {
		if math.Abs(got-want) > 0.01 {
			t.Errorf("%s = %.3f, want %.3f", name, got, want)
		}
	}
	near("box steady", valueAt(whole, 50), 10)
	near("box burst", valueAt(whole, 100), 60)
	near("api steady", valueAt(api, 50), 5)
	near("api burst", valueAt(api, 100), 35)
	// An app is its containers added up, and nothing else is folded in.
	near("app steady", valueAt(app, 50), 5.833)

	// The reading that closes the six-minute hole is not differenced across it.
	if v := valueAt(whole, 76); !math.IsNaN(v) {
		t.Errorf("a value of %v was computed across the gap", v)
	}
	// A restart is unknown for the container AND for the app that contains it,
	// rather than an enormous spike or a silently smaller sum.
	if v := valueAt(api, 110); !math.IsNaN(v) {
		t.Errorf("the restart produced %v", v)
	}
	if v := valueAt(app, 110); !math.IsNaN(v) {
		t.Errorf("the app reported %v while one container was unknown", v)
	}
	// And it recovers on the very next reading.
	near("after the restart", valueAt(api, 111), 5)
}

// Storage rides the rollups on a slower cadence than everything else, because
// it costs a du rather than a file read.
func TestTheStampFollowsWhatIsActuallyInstalled(t *testing.T) {
	sum := komizoStamp()
	if sum == "" {
		// Built without `make agents`. The stamp is empty rather than a hash of
		// nothing, which is the honest answer for a komizo with no agent to
		// install -- and the rest of this test has nothing to measure.
		t.Skip("no agents embedded; run `make agents`")
	}
	if len(sum) != 12 {
		t.Errorf("stamp = %q, want 12 characters", sum)
	}
	// The installer writes the same stamp the interface compares against.
	if !strings.Contains(scripts.AgentInstall(sum, versionText()), sum) {
		t.Error("the installer does not write the stamp the row reads")
	}
}

// Updating is one operation, on the komizo server row, and it re-runs the whole
// setup -- Docker included. There is one thing to press and no way to have run
// half of it; the docker row it replaced is gone.
func TestDomainsLandOnTheContainerTheAppNamed(t *testing.T) {
	a := appRow{
		name: "blog",
		containers: []containerRow{
			{app: "blog", service: "blog-gate", name: "blog-gate-1"},
			{app: "blog", service: "api", name: "blog-api-1"},
			{app: "blog", service: "pb", name: "blog-pb-1"},
			{app: "blog", service: "worker", name: "blog-worker-1"},
		},
		hosts: []hostRow{
			{app: "blog", name: "blog.dev", service: "blog-gate"},
			{app: "blog", name: "www.blog.dev"}, // no arrow
			{app: "blog", name: "api.blog.dev", service: "api"},
			{app: "blog", name: "*.preview.blog.dev", service: "api"},
			{app: "blog", name: "gone.blog.dev", service: "removed"}, // names nothing
		},
		routes: []routeRow{{app: "blog",
			sites:    "blog.dev,www.blog.dev,api.blog.dev,*.preview.blog.dev,gone.blog.dev",
			upstream: "blog-gate", port: "80"}},
	}
	net := netRow{name: "edge", members: []netMember{
		{container: "blog-gate-1", aliases: []string{"blog-gate"}},
	}}
	got := a.routesByContainer(net)

	if want := []string{"api.blog.dev", "*.preview.blog.dev"}; !sameSet(got["blog-api-1"], want) {
		t.Errorf("api serves %v, want %v", got["blog-api-1"], want)
	}
	// The gate keeps what it was named for, plus everything the app did not
	// annotate -- which is the honest answer for those: the app did not say, and
	// the gate is genuinely where the request goes.
	if want := []string{"blog.dev", "www.blog.dev", "gone.blog.dev"}; !sameSet(got["blog-gate-1"], want) {
		t.Errorf("the gate serves %v, want %v", got["blog-gate-1"], want)
	}
	// A container nothing names gets nothing, rather than inheriting the app's.
	if len(got["blog-worker-1"]) != 0 {
		t.Errorf("worker serves %v, want nothing", got["blog-worker-1"])
	}
	// And no name is shown twice.
	seen := map[string]int{}
	for _, hs := range got {
		for _, h := range hs {
			seen[h]++
		}
	}
	for h, n := range seen {
		if n > 1 {
			t.Errorf("%s appears on %d rows", h, n)
		}
	}
}

func sameSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	have := map[string]bool{}
	for _, g := range got {
		have[g] = true
	}
	for _, w := range want {
		if !have[w] {
			return false
		}
	}
	return true
}

// The deployed commit and the listening ports have a column of their own.
//
// In brackets after the name they pushed the name's width around -- a long SHA
// on one app and none on the next left the column ragged, and the name is the
// thing the eye scans down. They share one column because both answer "which
// one is this" and neither is wide, so a column each would be half empty on
// every row.
func TestTheDeviationLineIsQuietWhenNothingIsHappening(t *testing.T) {
	quiet := make([]float64, 120)
	for i := range quiet {
		quiet[i] = float64(26 + (i%17)/2 + i/40) // a slow rise, with jitter
	}
	measure := func(score []float64) (off int, peak float64) {
		for _, s := range score {
			if math.IsNaN(s) {
				continue
			}
			if a := math.Abs(s); a > peak {
				peak = a
			}
			if s != 0 {
				off++
			}
		}
		return
	}
	raw := trailingBaseline(quiet).score
	rawOff, _ := measure(raw)
	_, quietPeak := measure(quietened(raw))
	if rawOff < 30 {
		t.Fatalf("the raw score is meant to be noisy here; got %d minutes off the reference", rawOff)
	}
	if quietPeak > 1 {
		t.Errorf("quiet traffic reached %.1f deviations past the dead zone, should hug the reference", quietPeak)
	}

	// And an incident still shouts. Twenty deviations is not a subtle signal.
	incident := append([]float64(nil), quiet...)
	for i := 70; i < 88; i++ {
		incident[i] = 96
	}
	_, peak := measure(quietened(trailingBaseline(incident).score))
	if peak < 10 {
		t.Errorf("an incident only reached %.1f deviations", peak)
	}
}

// Ordinary variation draws as FLAT, which is the whole point: the line lifting
// off the reference is itself the signal, before any colour is read.
func TestOrdinaryVariationIsPinnedToTheReference(t *testing.T) {
	in := []float64{0, 0.4, -0.7, 1, -1, 0.9}
	for i, got := range quietened(in) {
		if got != 0 {
			t.Errorf("score %v drew at %v, want flat", in[i], got)
		}
	}
	// Past a deviation it lifts off by the excess, not by the whole score --
	// so the colours move out by one, which is the documented trade.
	out := quietened([]float64{3, 3, 3, 3})
	if out[3] != 2 {
		t.Errorf("a 3-sigma minute drew at %v, want 2", out[3])
	}
}
