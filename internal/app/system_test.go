package app

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

// A sample as the host script actually emits it: the three box records, two
// filesystems that turn out to be one, and a container per line.
const sysSampleOut = "server\tready\tDocker version 26\n" +
	"sys\tcpu\t100000\t90000\n" +
	"sys\tcores\t2\t0\n" +
	"sys\tmem\t2000000000\t500000000\n" +
	"disk\t/\t3000000000\t10000000000\n" +
	"disk\t/\t3000000000\t10000000000\n" +
	"cstat\tblog\tapi\t1000000\t50000000\t268435456\n" +
	"cstat\tblog\tdb\t2000000\t90000000\tmax\n" +
	"app\tblog\tdeploy-blog\t/srv/blog\tv1\t2\timg\t\n"

func TestSystemRecordsAreReadOutOfTheSameOutput(t *testing.T) {
	s := parseSystem(sysSampleOut, time.Unix(1000, 0))

	if !s.haveCPU || s.cpuTotal != 100000 || s.cpuIdle != 90000 {
		t.Errorf("cpu = %d/%d have=%v", s.cpuTotal, s.cpuIdle, s.haveCPU)
	}
	if s.cores != 2 {
		t.Errorf("cores = %d, want 2", s.cores)
	}
	if !s.haveMem || s.memTotal != 2000000000 || s.memUsed != 500000000 {
		t.Errorf("mem = %d of %d", s.memUsed, s.memTotal)
	}

	// / and /var/lib/docker are asked about separately and are usually the same
	// filesystem. Listing it twice would read as twice the disk.
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
	// "max" is cgroup v2 for uncapped. A container with no ceiling is a fact
	// worth showing, not a missing number.
	db, _ := s.statFor("blog", "db")
	if db.hasLimit {
		t.Errorf("db reported a limit of %d, but its cgroup says max", db.limit)
	}
}

// A cgroup that could not be read is UNKNOWN. Zero would be a measurement --
// one saying the container is using nothing at all.
func TestAnUnreadableCgroupIsNotZero(t *testing.T) {
	s := parseSystem("cstat\tblog\tapi\t\t\t\n", time.Unix(1000, 0))
	if len(s.cs) != 1 {
		t.Fatalf("want the container listed anyway, got %+v", s.cs)
	}
	if s.cs[0].haveCPU || s.cs[0].haveMem {
		t.Errorf("blank readings became values: %+v", s.cs[0])
	}
}

// at builds a reading, with the counters given, so a test can say what changed
// between two of them and nothing else.
func at(sec int64, cpuTotal, cpuIdle int, apiCPU string) sysSample {
	out := strings.NewReplacer(
		"sys\tcpu\t100000\t90000", "sys\tcpu\t"+itoa(cpuTotal)+"\t"+itoa(cpuIdle),
		"cstat\tblog\tapi\t1000000", "cstat\tblog\tapi\t"+apiCPU,
	).Replace(sysSampleOut)
	return parseSystem(out, time.Unix(sec, 0))
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
	blind := parseSystem("sys\tcores\t2\t0\n", time.Unix(1000, 0))
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
	gone := parseSystem(strings.Replace(sysSampleOut,
		"cstat\tblog\tapi\t1000000\t50000000\t268435456\n", "", 1), time.Unix(1010, 0))
	if v, ok := cpuAt(prev, gone, "blog", "api"); !ok || v != 0 {
		t.Errorf("a stopped container = %v ok=%v, want 0", v, ok)
	}
	if v, ok := memAt(gone, "blog", "api"); !ok || v != 0 {
		t.Errorf("a stopped container holds %d ok=%v, want 0", v, ok)
	}

	blind := parseSystem(strings.Replace(sysSampleOut,
		"cstat\tblog\tapi\t1000000\t50000000\t268435456",
		"cstat\tblog\tapi\t\t\t", 1), time.Unix(1010, 0))
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
	restarted := parseSystem(strings.Replace(
		strings.NewReplacer(
			"sys\tcpu\t100000\t90000", "sys\tcpu\t100200\t90150",
			"cstat\tblog\tapi\t1000000", "cstat\tblog\tapi\t6000000",
		).Replace(sysSampleOut),
		"cstat\tblog\tdb\t2000000", "cstat\tblog\tdb\t5", 1), time.Unix(1010, 0))
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
	rows := parseVolumes(
		"vol\tblog\tapi\tblog_data\t100\n" +
			"vol\tblog\tdb\tblog_data\t100\n" +
			"vol\tblog\tdb\tblog_uploads\t50\n")
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

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// sysModel is a model with enough readings for the charts to draw.
func sysModel(app, service string) model {
	m := testModel()
	m.scr, m.monitorOf, m.monitorSvc, m.monitorReady = screenMonitor, app, service, true
	m.width, m.height = 100, 30
	for i := 0; i <= 8; i++ {
		m.takeSample(at(int64(1000+10*i), 100000+200*i, 90000+150*i, itoa(1000000+500000*i)))
	}
	return m
}

// The resource charts must survive every "no traffic to show" case. A container
// no hostname names is exactly the one where processor and memory are the only
// thing this screen can say about it -- and that case used to take over the
// whole window.
func TestAContainerWithNoHostnameStillShowsWhatItIsSpending(t *testing.T) {
	// Read from the page rather than the window: this page is longer than a
	// terminal and the note is below the fold, which is a scrolling question
	// and not the one being asked here.
	m := sysModel("blog", "api")
	out := stripANSI(m.pageBody())

	if !strings.Contains(out, "Processor") || !strings.Contains(out, "Memory") {
		t.Errorf("the resource charts are missing:\n%s", out)
	}
	if !strings.Contains(out, "no hostname declares api") {
		t.Errorf("the unmeasurable-traffic note is missing:\n%s", out)
	}
}

// The bars are the box's, and they live on the index under the docker row --
// not on the monitor, and not per app.
func TestTheBarsAreOnTheIndexAndAreTheBoxs(t *testing.T) {
	m := sysModel("", "")
	if got := stripANSI(m.pageBody()); strings.Contains(got, "█") {
		t.Errorf("the monitor should not draw usage bars:\n%s", got)
	}

	idx := sysModel("", "")
	idx.scr = screenIndex
	out := stripANSI(idx.pageBody())
	for _, want := range []string{"processor", "memory", "disk", "2 cores"} {
		if !strings.Contains(out, want) {
			t.Errorf("the index is missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "█") {
		t.Errorf("no bar drawn on the index:\n%s", out)
	}
}

// One reading cannot make a rate. The bar is simply absent rather than empty:
// an empty bar is a measurement, and it says the machine is idle.
func TestOneReadingDrawsNoProcessorBarRatherThanAnEmptyOne(t *testing.T) {
	m := testModel()
	m.scr, m.width, m.height = screenIndex, 100, 30
	m.takeSample(parseSystem(sysSampleOut, time.Unix(1000, 0)))
	out := stripANSI(m.pageBody())
	if strings.Contains(out, "processor") {
		t.Errorf("a processor bar was drawn from a single reading:\n%s", out)
	}
	// Memory and disk are levels, not rates, so one reading is enough for them.
	if !strings.Contains(out, "memory") {
		t.Errorf("memory needs no second reading:\n%s", out)
	}
}

// The session history is a window, not a log. A session left open overnight
// must cost the same as one opened a minute ago.
func TestTheSessionHistoryIsBounded(t *testing.T) {
	m := testModel()
	for i := 0; i <= sysHistory+50; i++ {
		m.takeSample(at(int64(1000+10*i), 100000+200*i, 90000+150*i, "1000000"))
	}
	if len(m.sysSamples) != sysHistory {
		t.Errorf("kept %d readings, cap is %d", len(m.sysSamples), sysHistory)
	}
}

// Captured from the sampler actually running, with the container line it now
// writes: two readings a second apart, and the duplicate disk line the two df
// calls really produce.
const sampledLog = "S\t1785232675\tsys\tcpu\t374177611\t356049689\n" +
	"S\t1785232675\tsys\tcores\t16\t0\n" +
	"S\t1785232675\tsys\tmem\t32713216000\t17545588736\n" +
	"S\t1785232675\tdisk\t/\t175837097984\t1018959839232\n" +
	"S\t1785232675\tdisk\t/\t175837097984\t1018959839232\n" +
	"S\t1785232675\tcstat\tblog\tapi\t1000000\t50000000\tmax\n" +
	"S\t1785232676\tsys\tcpu\t374179265\t356051248\n" +
	"S\t1785232676\tsys\tcores\t16\t0\n" +
	"S\t1785232676\tsys\tmem\t32713216000\t17529319424\n" +
	"S\t1785232676\tdisk\t/\t175837097984\t1018959839232\n" +
	"S\t1785232676\tcstat\tblog\tapi\t1400000\t50000000\tmax\n"

func TestTheSamplersRecordsComeBackAsReadings(t *testing.T) {
	s := parseSystemLog(sampledLog)
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
		t.Errorf("disks = %+v, want the duplicate folded away", s[0].disks)
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

// Cron stopped, or the box was down, or the sampler was killed. A cumulative
// counter differenced across the hole gives a true average OF the hole, dated
// at its end and drawn as one point -- a confident value painted over a stretch
// nobody measured.
func TestAGapInTheRecordIsNotBridged(t *testing.T) {
	var b strings.Builder
	for _, ts := range []int{1000, 1060, 1120, 100000, 100060} {
		b.WriteString("S\t" + itoa(ts) + "\tsys\tcpu\t" + itoa(1000+ts) + "\t" + itoa(500+ts) + "\n")
		b.WriteString("S\t" + itoa(ts) + "\tsys\tcores\t2\t0\n")
	}
	r := cpuSeries(parseSystemLog(b.String()), "", "")
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
func TestTheBoxsRecordWinsOverWhatThisSessionSampled(t *testing.T) {
	m := sysModel("", "")
	if _, sampledHere := m.resourceHistory(); !sampledHere {
		t.Error("with no sampler on the box, the session's own samples are all there is")
	}
	if got := stripANSI(m.pageBody()); !strings.Contains(got, "sampled by this session") {
		t.Errorf("the weaker claim must be labelled:\n%s", got)
	}
	// And with only a couple of minutes of it, no how-unusual line is drawn: a
	// trailing median needs half an hour BEFORE each point, and the same
	// arithmetic over two minutes scores each point against the last two --
	// producing a confident line indistinguishable from the real thing.
	h2, live := m.resourceHistory()
	for _, p := range m.systemPanels(h2, live) {
		if p.scored {
			t.Errorf("%q claims a baseline it does not have", p.title)
		}
	}

	m.sysLog = parseSystemLog(sampledLog)
	hist, sampledHere := m.resourceHistory()
	if sampledHere || len(hist) != 2 {
		t.Errorf("the sampler's history should win, got %d readings sampledHere=%v", len(hist), sampledHere)
	}
}

// Two polls is ten seconds. Bucketing the session's own samples into minutes
// meant nothing appeared until it crossed its second CLOCK minute -- up to two
// minutes of staring at a page that looks broken on any box without a sampler,
// which is every box until server setup is re-run.
func TestTheChartsDrawWithinTwoPollsOnABoxWithNoSampler(t *testing.T) {
	m := testModel()
	m.scr, m.monitorReady, m.width, m.height = screenMonitor, true, 96, 40
	m.takeSample(at(1000, 100000, 90000, "1000000"))
	m.takeSample(at(1005, 100300, 90150, "1500000"))

	out := stripANSI(m.pageBody())
	for _, want := range []string{"Processor", "Memory", "Disk /"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q is missing ten seconds in:\n%s", want, out)
		}
	}
}

// Disk had no history at all: the derived point type never carried it, so the
// chart could not have been drawn however long you waited.
func TestDiskIsChartedFromTheRollups(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 40; i++ {
		ts := itoa(100000 + i*60)
		b.WriteString("S\t" + ts + "\tsys\tcpu\t" + itoa(1000+i*100) + "\t" + itoa(500+i*50) + "\n")
		b.WriteString("S\t" + ts + "\tsys\tcores\t2\t0\n")
		b.WriteString("S\t" + ts + "\tdisk\t/\t" + itoa(3000000000+i*9000000) + "\t10000000000\n")
	}
	hist := parseSystemLog(b.String())
	if got := mountsIn(hist); len(got) != 1 || got[0] != "/" {
		t.Fatalf("mounts = %v", got)
	}
	r := diskSeries(hist, "/")
	if !r.any() {
		t.Fatal("no disk readings survived into the chart")
	}
	// Filling steadily, and read as a percentage so the top of the chart is the
	// full disk rather than whatever range it happened to occupy.
	if r.vals[0] < 29 || r.vals[0] > 32 || r.vals[len(r.vals)-1] <= r.vals[0] {
		t.Errorf("disk series = %v ... %v", r.vals[0], r.vals[len(r.vals)-1])
	}

	m := testModel()
	m.scr, m.monitorReady, m.width, m.height = screenMonitor, true, 96, 40
	m.sysLog = hist
	out := stripANSI(m.pageBody())
	if !strings.Contains(out, "Disk /") {
		t.Errorf("no disk chart:\n%s", out)
	}
	// No how-unusual line on it: a disk creeps up almost monotonically, so a
	// robust spread collapses and ordinary growth would read as permanently
	// unusual, which is how a colour stops meaning anything.
	//
	for _, p := range m.diskPanels(hist) {
		if p.scored {
			t.Errorf("%q should carry no baseline", p.title)
		}
	}
}

// An app has no disk history -- its storage is volumes, measured with du on
// demand -- so it gets the storage list and no chart.
func TestAnAppGetsNoDiskChart(t *testing.T) {
	m := sysModel("blog", "")
	m.sysLog = parseSystemLog(sampledLog)
	if out := stripANSI(m.pageBody()); strings.Contains(out, "% full") {
		t.Errorf("an app should have no filesystem chart:\n%s", out)
	}
}

// The sampler defined the cgroup reader and never called it, so it wrote the
// box's numbers and nothing else -- every app and container chart was empty
// however long the box had been up, which looks exactly like an idle machine.
func TestTheSamplerActuallyReadsContainers(t *testing.T) {
	sh := samplerScript()
	if !strings.Contains(sh, "container_stats_all() {") {
		t.Fatal("the sampler has no container enumeration")
	}
	// A line that is nothing but the name is a call; the definition ends in
	// "() {". Matched that way rather than by scanning to the end of the command
	// substitution, which the probe is itself full of.
	called := false
	for _, ln := range strings.Split(sh, "\n") {
		if strings.TrimSpace(ln) == "container_stats_all" {
			called = true
		}
	}
	if !called {
		t.Error("the sampler defines the container reader but never calls it")
	}
}

// End to end over two hours of rollups with KNOWN values, so what reaches a
// chart is checked against arithmetic rather than eyeballed.
//
// The box runs at 10% and bursts to 60%; api sits at 5% of the machine and
// bursts to 35%; db burns one processor-second a minute, which on two cores is
// 0.833%. Cron stops for six minutes, and api restarts once.
func TestTheChartedNumbersAreTheArithmetic(t *testing.T) {
	start := int64(1785200000) / 60 * 60
	var log strings.Builder
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
		row := func(f string, a ...any) {
			fmt.Fprintf(&log, "S\t%d\t"+f+"\n", append([]any{ts}, a...)...)
		}
		row("sys\tcpu\t%d\t%d", cpuTotal, cpuIdle)
		row("sys\tcores\t2\t0")
		row("sys\tmem\t2000000000\t%d", 500000000+i*1000000)
		row("cstat\tblog\tapi\t%d\t%d\tmax", apiUsec, 300*1024*1024)
		row("cstat\tblog\tdb\t%d\t%d\tmax", 1000000+i*1000000, 90*1024*1024)
	}

	hist := parseSystemLog(log.String())
	box := cpuSeries(hist, "", "")
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
	near("box steady", valueAt(box, 50), 10)
	near("box burst", valueAt(box, 100), 60)
	near("api steady", valueAt(api, 50), 5)
	near("api burst", valueAt(api, 100), 35)
	// An app is its containers added up, and nothing else is folded in.
	near("app steady", valueAt(app, 50), 5.833)

	// The reading that closes the six-minute hole is not differenced across it.
	if v := valueAt(box, 76); !math.IsNaN(v) {
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
func TestStorageIsChartedFromTheReadingsThatMeasuredIt(t *testing.T) {
	var log strings.Builder
	start := int64(1785200000) / 60 * 60
	for i := 0; i < 40; i++ {
		ts := start + int64(i)*60
		fmt.Fprintf(&log, "S\t%d\tsys\tmem\t2000000000\t500000000\n", ts)
		// Only every fifteenth minute carries volumes, growing as it goes.
		if i%15 == 0 {
			fmt.Fprintf(&log, "S\t%d\tvol\tblog\tapi\tblog_data\t%d\n", ts, 100000000+i*1000000)
			fmt.Fprintf(&log, "S\t%d\tvol\tblog\tdb\tblog_data\t%d\n", ts, 100000000+i*1000000)
			fmt.Fprintf(&log, "S\t%d\tvol\tblog\tdb\tblog_up\t%d\n", ts, 50000000)
		}
	}
	hist := parseSystemLog(log.String())
	if len(hist) != 40 {
		t.Fatalf("got %d readings", len(hist))
	}

	r := storageSeries(hist, "blog", "")
	// Three measurements in forty minutes, not forty. A minute the sampler did
	// not run du on is not a hole in the measurement -- it is simply not one of
	// them, and a series of gaps around three real points says the opposite.
	if len(r.vals) != 3 {
		t.Fatalf("got %d storage points, want 3", len(r.vals))
	}
	// One volume mounted by two containers counts once for the app.
	if r.vals[0] != 150000000 {
		t.Errorf("app storage = %v, want 150000000", r.vals[0])
	}
	if r.vals[2] <= r.vals[0] {
		t.Errorf("storage should be growing: %v then %v", r.vals[0], r.vals[2])
	}
	// A container's own figure includes storage it shares.
	if c := storageSeries(hist, "blog", "db"); c.vals[0] != 150000000 {
		t.Errorf("db storage = %v, want 150000000", c.vals[0])
	}

	m := testModel()
	m.scr, m.monitorReady, m.width, m.height = screenMonitor, true, 96, 40
	m.monitorOf, m.sysLog = "blog", hist
	out := stripANSI(m.pageBody())
	if !strings.Contains(out, "Storage") || !strings.Contains(out, "MB in volumes") {
		t.Errorf("no storage chart:\n%s", out)
	}
}

// A shell runs a file as it reads it, so a function called above its own
// definition is a function that does not exist yet -- on a line that then
// quietly produces nothing, which is exactly how the sampler shipped once
// already with a container reader it never called.
func TestTheSamplerDefinesEveryFunctionBeforeItCallsIt(t *testing.T) {
	sh := samplerScript()
	for _, fn := range []string{"container_stat", "container_stats_all", "volumes_all"} {
		def := strings.Index(sh, fn+"() {")
		if def < 0 {
			t.Errorf("%s is never defined", fn)
			continue
		}
		called := -1
		for i, ln := range strings.Split(sh, "\n") {
			t := strings.TrimSpace(ln)
			if t == fn || strings.HasPrefix(t, fn+" ") || strings.HasPrefix(t, fn+"(\"") {
				if !strings.Contains(t, "() {") {
					called = i
					break
				}
			}
		}
		if called < 0 {
			continue // called indirectly, covered by the test above
		}
		defLine := strings.Count(sh[:def], "\n")
		if called < defLine {
			t.Errorf("%s is called on line %d but defined on line %d", fn, called+1, defLine+1)
		}
	}
}

// du on a large volume can outlast the minute it started in. Two overlapping
// runs would interleave their lines, and half of one reading merged with half
// of another is worse than a missing minute: it looks like a reading.
func TestTheSamplerTakesALock(t *testing.T) {
	sh := samplerScript()
	if !strings.Contains(sh, "mkdir \"$LOCK\"") {
		t.Error("the sampler does not take a lock")
	}
	if !strings.Contains(sh, "trap 'rmdir \"$LOCK\"") {
		t.Error("the sampler does not release its lock")
	}
	// And a lock left by a kill -9 must not stop it forever.
	if !strings.Contains(sh, "-mmin +20") {
		t.Error("a stale lock is never cleared")
	}
}

// rollupModel is a model with two hours of the box's own per-minute record, so
// the charts take their scored, gridded form.
func rollupModel(app, svc string) model {
	m := testModel()
	m.scr, m.monitorReady = screenMonitor, true
	m.monitorOf, m.monitorSvc = app, svc
	start := time.Now().Unix()/60*60 - 120*60
	var log strings.Builder
	cpuTotal, cpuIdle, apiUsec := 1000000, 900000, 5000000
	for i := 0; i < 120; i++ {
		ts := start + int64(i)*60
		cpuTotal += 6000
		cpuIdle += 5280
		apiUsec += 6000000
		row := func(f string, a ...any) {
			fmt.Fprintf(&log, "S\t%d\t"+f+"\n", append([]any{ts}, a...)...)
		}
		row("sys\tcpu\t%d\t%d", cpuTotal, cpuIdle)
		row("sys\tcores\t2\t0")
		row("sys\tmem\t2000000000\t%d", 600000000+i*2000000)
		row("disk\t/\t%d\t10000000000", 3000000000+i*8000000)
		row("cstat\tblog\tapi\t%d\t%d\tmax", apiUsec, 300*1024*1024)
		if i%15 == 0 {
			row("vol\tblog\tapi\tblog_data\t%d", 700000000+i*3000000)
		}
	}
	m.sysLog = parseSystemLog(log.String())
	now := time.Now().Unix() / 60 * 60
	for i := 0; i < 200; i++ {
		m.monitor = append(m.monitor, metricRow{minute: now - int64(199-i)*60,
			app: "blog", service: svc, c2: 30 + i%17, c5: (i / 40) % 3})
	}
	return m
}

// The grid gives up columns rather than clipping them. The frame truncates long
// rows, so a layout that assumed width would lose its right-hand panel entirely
// on a narrow terminal -- silently, which is the failure this whole screen is
// built to avoid.
func TestTheGridGivesUpColumnsRatherThanWidth(t *testing.T) {
	for _, w := range []int{200, 120, 96, 70, 50, 34} {
		m := rollupModel("blog", "api")
		m.width, m.height = w, 60
		body := stripANSI(m.pageBody())
		for i, ln := range strings.Split(body, "\n") {
			if got := lipglossWidth(ln); got > w {
				t.Errorf("width %d: row %d is %d columns:\n%s", w, i, got, ln)
			}
		}
		// Whatever the width, every chart is still on the page somewhere.
		for _, want := range []string{"Requests", "Failures", "Processor", "Memory", "Storage"} {
			if !strings.Contains(body, want) {
				t.Errorf("width %d: %q went missing", w, want)
			}
		}
	}
}

// Panels sit side by side while they can be read, and stack when they cannot.
func TestPanelsPerRowFollowTheTerminal(t *testing.T) {
	p := []panel{
		{title: "a", draw: func(w, h int) string { return strings.Repeat("x", w) }},
		{title: "b", draw: func(w, h int) string { return strings.Repeat("x", w) }},
		{title: "c", draw: func(w, h int) string { return strings.Repeat("x", w) }},
	}
	rowsOfTitles := func(width int) int {
		m := testModel()
		m.width = width
		n := 0
		for _, ln := range strings.Split(strings.TrimRight(stripANSI(m.grid(p, 3, 4)), "\n"), "\n") {
			if strings.HasPrefix(ln, gutter+"a") {
				n++
			}
		}
		return n
	}
	// Three across at a width that can afford three; the same three panels
	// stacked when it cannot. Counted by how many rows begin a new block.
	wide := stripANSI(testModelAt(200).grid(p, 3, 4))
	if !strings.Contains(strings.Split(wide, "\n")[0], "a") ||
		!strings.Contains(strings.Split(wide, "\n")[0], "c") {
		t.Errorf("three panels should share one row at 200 columns:\n%s", wide)
	}
	narrow := stripANSI(testModelAt(40).grid(p, 3, 4))
	if strings.Contains(strings.Split(narrow, "\n")[0], "b") {
		t.Errorf("40 columns cannot hold two panels:\n%s", narrow)
	}
	if rowsOfTitles(200) != 1 {
		t.Error("a wide terminal should need one row")
	}
}

func testModelAt(w int) model {
	m := testModel()
	m.width = w
	return m
}

// A title too long for its column is cut with a marker, never wrapped: the
// frame clips, so a wrapped title would push the chart under it off the page.
func TestATitleTooWideForItsColumnIsCut(t *testing.T) {
	if got := cut("Processor (% of the machine)", 12); lipglossWidth(got) > 12 {
		t.Errorf("cut to %q, %d columns", got, lipglossWidth(got))
	}
	if !strings.HasSuffix(cut("Processor (% of the machine)", 12), "…") {
		t.Error("a cut title should say it was cut")
	}
	if got := cut("short", 12); got != "short" {
		t.Errorf("cut(%q) = %q, want it untouched", "short", got)
	}
}

// The box gets both disk questions, which are easy to confuse and answer
// different things: how full the filesystem is, which is what kills a machine,
// and how much of it is the apps' own data, which is the part anyone can act on.
func TestTheBoxChartsBothItsDiskAndItsStorage(t *testing.T) {
	var log strings.Builder
	start := int64(1785200000) / 60 * 60
	for i := 0; i < 40; i++ {
		ts := start + int64(i)*60
		fmt.Fprintf(&log, "S\t%d\tdisk\t/\t%d\t10000000000\n", ts, 3000000000+i*9000000)
		if i%15 == 0 {
			fmt.Fprintf(&log, "S\t%d\tvol\tblog\tapi\tblog_data\t%d\n", ts, 700000000+i*1000000)
			fmt.Fprintf(&log, "S\t%d\tvol\tblog\tdb\tblog_data\t%d\n", ts, 700000000+i*1000000)
			fmt.Fprintf(&log, "S\t%d\tvol\tshop\tdb\tshop_db\t%d\n", ts, 300000000)
		}
	}
	m := testModel()
	m.scr, m.monitorReady, m.width, m.height = screenMonitor, true, 170, 60
	m.sysLog = parseSystemLog(log.String())

	var titles []string
	for _, p := range m.diskPanels(m.sysLog) {
		titles = append(titles, p.title)
	}
	want := []string{"Disk /", "Storage"}
	if len(titles) != 2 || titles[0] != want[0] || titles[1] != want[1] {
		t.Fatalf("box disk panels = %v, want %v", titles, want)
	}

	// Every app added together, with a volume mounted twice counted once:
	// 700MB of blog + 300MB of shop, not 1700MB.
	r := storageSeries(m.sysLog, "", "")
	if r.vals[0] != 1000000000 {
		t.Errorf("box storage = %v, want 1000000000", r.vals[0])
	}

	out := stripANSI(m.pageBody())
	// And the number is broken down, or it is a figure with nothing to do
	// about it.
	if !strings.Contains(out, "Volumes by app") {
		t.Errorf("no per-app breakdown:\n%s", out)
	}
	for _, want := range []string{"blog", "shop"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q missing from the breakdown:\n%s", want, out)
		}
	}
}

// The breakdown comes from the newest reading that MEASURED volumes, which is
// not the newest reading: du runs on a slow cadence, so most readings have none.
func TestTheBreakdownComesFromTheLastMeasuredReading(t *testing.T) {
	m := testModel()
	m.sysLog = parseSystemLog(
		"S\t1000\tvol\tblog\tapi\tblog_data\t100\n" +
			"S\t1060\tsys\tcores\t2\t0\n" +
			"S\t1120\tsys\tcores\t2\t0\n")
	rows := m.latestVols()
	if len(rows) != 1 || rows[0].bytes != 100 {
		t.Errorf("latestVols = %+v, want the reading from 1000", rows)
	}
}

// Opening the monitor measures the app's volumes right then. That is the newest
// point of the same series, not a different one -- and without it the chart
// needs two rollup readings, which at four an hour means up to half an hour of
// a page that shows a volume list and no line.
func TestTheStorageChartIncludesTheMeasurementTakenOnOpening(t *testing.T) {
	m := testModel()
	m.scr, m.monitorReady, m.width, m.height = screenMonitor, true, 120, 50
	m.monitorOf = "blog"
	// One rollup reading: not enough for a line on its own.
	m.sysLog = parseSystemLog("S\t1785200000\tvol\tblog\tapi\tblog_data\t700000000\n")
	if got := storageSeries(m.sysLog, "blog", ""); len(got.times) != 1 {
		t.Fatalf("want one rollup point, got %d", len(got.times))
	}
	var titles []string
	for _, p := range m.diskPanels(m.sysLog) {
		titles = append(titles, p.title)
	}
	if len(titles) != 0 {
		t.Errorf("one point is not a line: %v", titles)
	}

	// The du that runs when the monitor opens makes it two.
	m.vols = parseVolumes("vol\tblog\tapi\tblog_data\t900000000\n")
	r := m.storageSeriesNow()
	if len(r.times) != 2 {
		t.Fatalf("want the live measurement appended, got %d points", len(r.times))
	}
	if r.vals[1] != 900000000 {
		t.Errorf("newest point = %v, want the freshly measured 900000000", r.vals[1])
	}
	if !r.times[1].After(r.times[0]) {
		t.Error("the live measurement must be the newest point")
	}
	if out := stripANSI(m.pageBody()); !strings.Contains(out, "Storage") {
		t.Errorf("no storage chart:\n%s", out)
	}
}

// A box set up at 11:07 would otherwise record no storage until 11:15, and need
// a second reading at 11:30 before a line could be drawn -- so the chart is
// missing for the first half hour after installing the thing that draws it,
// which reads as broken rather than as new.
func TestTheSamplerMeasuresVolumesOnItsFirstRun(t *testing.T) {
	sh := samplerScript()
	if !strings.Contains(sh, `if [ ! -f "$LOG" ] || [ "$(( now / 60 % 15 ))" -eq 0 ]; then`) {
		t.Error("the first run does not measure volumes")
	}
}

// Storage must not follow the fallback the other charts use. The five-second
// poll does not run du, so a box whose sampler has only one reading yet would
// fall back to session readings -- a series that is always empty, and a chart
// that never appears however long you wait.
func TestStorageReadsTheBoxsRecordEvenWhenTheOtherChartsDoNot(t *testing.T) {
	m := testModel()
	m.scr, m.monitorReady, m.width, m.height = screenMonitor, true, 120, 50
	m.monitorOf = "blog"
	// One rollup reading, so processor and memory fall back to the session.
	m.sysLog = parseSystemLog("S\t1785200000\tvol\tblog\tapi\tblog_data\t700000000\n")
	m.takeSample(at(1000, 100000, 90000, "1000000"))
	m.takeSample(at(1005, 100300, 90150, "1500000"))
	if _, sampledHere := m.resourceHistory(); !sampledHere {
		t.Fatal("one rollup reading should not win over the session's two")
	}
	m.vols = parseVolumes("vol\tblog\tapi\tblog_data\t900000000\n")

	out := stripANSI(m.pageBody())
	if !strings.Contains(out, "Storage") {
		t.Errorf("storage chart missing while the others fell back:\n%s", out)
	}
	if !strings.Contains(out, "Processor") {
		t.Errorf("the session charts should still be there:\n%s", out)
	}
}

// The komizo row reports what the BOX has, not what this komizo would install.
// The alternative is a fact about the laptop, and it reads as up to date on a
// server that has never been touched.
func TestTheKomizoRowComparesTheBoxAgainstThisKomizo(t *testing.T) {
	m := testModel()
	m.scr, m.width, m.height = screenIndex, 96, 30

	m.srv.komizo = ""
	if got := stripANSI(m.komizoLine()); !strings.Contains(got, "not installed") {
		t.Errorf("no stamp should read as not installed, got %q", got)
	}
	m.srv.komizo = "0badc0ffee11"
	if got := stripANSI(m.komizoLine()); !strings.Contains(got, "out of date") {
		t.Errorf("a different stamp should read as out of date, got %q", got)
	}
	m.srv.komizo = komizoStamp()
	got := stripANSI(m.komizoLine())
	if strings.Contains(got, "out of date") || strings.Contains(got, "not installed") {
		t.Errorf("a matching stamp is current, got %q", got)
	}
	if !strings.Contains(got, shortText(komizoStamp())) {
		t.Errorf("the row should show the stamp, got %q", got)
	}
	// And it is on the page, above docker.
	body := stripANSI(m.pageBody())
	ki, di := strings.Index(body, "komizo"), strings.Index(body, "docker")
	if ki < 0 || di < 0 || ki > di {
		t.Errorf("komizo should sit above docker:\n%s", body)
	}
}

// The stamp is a hash of what gets written, not a constant somebody has to
// remember to bump. "Up to date" means "running the update would change
// nothing", and only the content can answer that.
func TestTheStampFollowsWhatIsActuallyInstalled(t *testing.T) {
	if len(komizoStamp()) != 12 {
		t.Errorf("stamp = %q, want 12 characters", komizoStamp())
	}
	// The installer writes the same stamp the interface compares against.
	if !strings.Contains(samplerScript(), komizoStamp()) {
		t.Error("the installer does not write the stamp the row reads")
	}
	// And it covers the sampler's contents: change the probe and the stamp
	// moves, which is what makes a stale box detectable at all.
	sum := komizoStamp()
	if strings.Contains(samplerFile(), "container_stats_all") != true {
		t.Fatal("the sampler no longer contains the probe this test relies on")
	}
	if sum == "" {
		t.Error("empty stamp")
	}
}

// Docker and komizo are updated on different occasions and by different keys.
// Bundling them would mean a routine Docker update rewrote scripts nobody asked
// it to touch.
func TestDockerAndKomizoAreUpdatedSeparately(t *testing.T) {
	m := testModel()
	m.cursor = m.rowIndex(focusServer)
	next, _ := m.primaryAction()
	d := next.(model).prompt
	if d == nil || !strings.Contains(d.question+d.detail, "Docker") {
		t.Fatalf("the docker row should ask about Docker, got %+v", d)
	}
	if !strings.Contains(d.detail, "komizo's own scripts are not touched") {
		t.Error("it should say komizo's scripts are left alone")
	}

	m.cursor = m.rowIndex(focusKomizo)
	next, _ = m.primaryAction()
	k := next.(model).prompt
	if k == nil || !strings.Contains(k.question, "Update komizo") {
		t.Fatalf("the komizo row should ask about komizo, got %+v", k)
	}
	if strings.Contains(k.detail, "Docker") {
		t.Error("updating komizo should not mention Docker")
	}
}

// The sparkline column carries containers too, and a container has one state an
// app does not: unmeasurable. The proxy only ever talks to the app's gateway, so
// which container answered is whatever the app declared in its hostnames file --
// a container nobody named there cannot be measured from here at all.
func TestTheSparklineColumnTellsQuietFromUnmeasurable(t *testing.T) {
	m := testModel()
	m.scr, m.width, m.height = screenIndex, 132, 30
	m.apps[0].containers = []containerRow{
		{app: "blog", service: "api", name: "blog-api-1", state: "running", status: "Up 3 hours"},
		{app: "blog", service: "db", name: "blog-db-1", state: "running", status: "Up 3 hours"},
		{app: "blog", service: "worker", name: "blog-worker-1", state: "running", status: "Up 3 hours"},
	}
	now := time.Now().Unix() / 60 * 60
	for i := 0; i < 40; i++ {
		mn := now - int64(39-i)*60
		m.metrics = append(m.metrics,
			metricRow{minute: mn, app: "blog", service: "api", c2: 20},
			// db is named by a hostname and served nothing this window.
			metricRow{minute: mn, app: "blog", service: "db"})
		// worker is named by nothing at all.
	}

	// Serving: a chart and a rate.
	if got := stripANSI(m.sparkForService("blog", "api")); !strings.ContainsAny(got, "▁▂▃▄▅▆▇█") {
		t.Errorf("a serving container should have a sparkline, got %q", got)
	}
	// Quiet: dots and a dash. Measured, and nothing arrived.
	if got := stripANSI(m.sparkForService("blog", "db")); !strings.Contains(got, "·") {
		t.Errorf("a quiet container should read as dots, got %q", got)
	}
	// Both strips read the same for it: nothing arrived, so nothing arrived to
	// fail either. Dots in both, rather than dots beside a blank -- a blank
	// errors strip means "measured, none", and nothing was measured here.
	if got := stripANSI(m.errSparkForService("blog", "db")); !strings.Contains(got, "·") {
		t.Errorf("a quiet container's errors = %q, want dots", got)
	}
	// Unmeasurable: blank. Dots would claim a measurement nobody took.
	if got := m.sparkForService("blog", "worker"); got != "" {
		t.Errorf("an unnamed container should be blank, got %q", got)
	}
	if got := m.errSparkForService("blog", "worker"); got != "" {
		t.Errorf("an unnamed container's errors should be blank, got %q", got)
	}

	// And the app row is its containers added up, so the column reads down.
	if got := stripANSI(m.sparkFor("blog")); strings.Contains(got, "·") {
		t.Errorf("the app should show its containers' traffic, got %q", got)
	}
}

// Title and units share a line: what it is in white, what it is measured in
// beside it in grey. Two lines cost a row of every panel on the page to carry
// half a phrase.
func TestAPanelHeadingIsOneLine(t *testing.T) {
	got := stripANSI(headingLine("Processor", "% of the machine", 60))
	if strings.Contains(got, "\n") {
		t.Errorf("the heading wrapped: %q", got)
	}
	if got != "Processor  % of the machine" {
		t.Errorf("heading = %q", got)
	}

	// The sub is cut first. A panel that cannot say what it is measured in is
	// still readable; one that cannot say what it IS is not.
	narrow := stripANSI(headingLine("Processor", "% of the machine", 20))
	if !strings.HasPrefix(narrow, "Processor") {
		t.Errorf("the title lost width to the sub: %q", narrow)
	}
	if lipglossWidth(narrow) > 20 {
		t.Errorf("heading is %d columns in a 20-column cell: %q", lipglossWidth(narrow), narrow)
	}
	// And to nothing at all when there is no room for both.
	if got := stripANSI(headingLine("Processor", "% of the machine", 11)); got != "Processor" {
		t.Errorf("heading = %q, want the title alone", got)
	}

	// On the page, the pair is one row rather than two.
	m := rollupModel("blog", "api")
	m.width, m.height = 160, 60
	for _, ln := range strings.Split(stripANSI(m.pageBody()), "\n") {
		if strings.Contains(ln, "Processor") && !strings.Contains(ln, "% of the machine") {
			t.Errorf("the units are not beside the title: %q", ln)
		}
	}
}

// The how-unusual line is not named on any chart: it is on nearly all of them,
// so saying so four times distinguishes nothing. Its absence stays visible
// without a label, because an unscored chart has ONE line rather than a green
// one -- a missing line is not a reassuring line.
func TestNoChartNamesTheOverlayInItsSubtitle(t *testing.T) {
	m := rollupModel("blog", "api")
	m.width, m.height = 160, 60
	hist, sampledHere := m.resourceHistory()

	var scored, unscored []string
	for _, p := range append(m.networkPanels(), m.systemPanels(hist, sampledHere)...) {
		if strings.Contains(p.sub, "unusual") || strings.Contains(p.title, "unusual") {
			t.Errorf("%q still names the overlay: %q", p.title, p.sub)
		}
		if p.scored {
			scored = append(scored, p.title)
		} else {
			unscored = append(unscored, p.title)
		}
	}
	// The rule the label used to carry, asserted instead of printed.
	if len(scored) != 4 {
		t.Errorf("scored = %v, want requests, failures, processor and memory", scored)
	}
	if len(unscored) != 1 || unscored[0] != "Storage" {
		t.Errorf("unscored = %v, want storage alone", unscored)
	}
	if out := stripANSI(m.pageBody()); strings.Contains(out, "how unusual") {
		t.Errorf("the phrase survives on the page:\n%s", out)
	}
}

// Every chart on the page is drawn on the same x axis: the range asked for.
// Four charts of the same moment on four different axes is a page you cannot
// read across, and reading across is the entire reason they share a screen.
func TestEveryChartSharesOneXAxis(t *testing.T) {
	m := rollupModel("blog", "api")
	m.width, m.height = 150, 70
	now := time.Now()
	// A range far wider than either record reaches.
	m.monitorRange = timeRange{from: now.Add(-12 * time.Hour).Unix(), to: now.Unix()}
	m.span, m.hasSpan = timeRange{from: now.Add(-2 * time.Hour).Unix(), to: now.Unix()}, true

	hist, sampledHere := m.resourceHistory()
	panels := append(m.networkPanels(), m.systemPanels(hist, sampledHere)...)
	if len(panels) < 4 {
		t.Fatalf("expected the full set of charts, got %d", len(panels))
	}

	// Rendered at one width so the axes are comparable character for character.
	var axes []string
	for _, p := range panels {
		lines := strings.Split(strings.TrimRight(stripANSI(p.draw(60, 12)), "\n"), "\n")
		axes = append(axes, lines[len(lines)-1])
	}
	for i, a := range axes {
		if a != axes[0] {
			t.Errorf("%q has a different axis:\n  %s\n  %s", panels[i].title, axes[0], a)
		}
	}
	// And it is the range that was asked for, not the extent of any one series.
	if !strings.Contains(axes[0], now.Add(-12*time.Hour).Format("15:04")) {
		t.Errorf("the axis does not start at the range: %q", axes[0])
	}
}

// A range wider than the record loses its data, not its axis -- and the empty
// part is left empty. Nothing at all is drawn there, not even the reference
// line the overlay is read against.
func TestNothingIsDrawnWhereThereIsNoData(t *testing.T) {
	m := rollupModel("blog", "api")
	m.width, m.height = 150, 70
	now := time.Now()
	m.monitorRange = timeRange{from: now.Add(-12 * time.Hour).Unix(), to: now.Unix()}
	m.span, m.hasSpan = timeRange{from: now.Add(-2 * time.Hour).Unix(), to: now.Unix()}, true

	req := m.networkPanels()[0]
	for _, ln := range strings.Split(stripANSI(req.draw(60, 12)), "\n") {
		i := strings.Index(ln, "│")
		if i < 0 {
			continue
		}
		// The left five sixths of the plot are before the log begins.
		body := []rune(ln[i+len("│"):])
		if len(body) < 20 {
			continue
		}
		for j, r := range body[:len(body)*3/5] {
			if r != ' ' {
				t.Errorf("column %d is %q, but nothing was recorded there:\n%s", j, r, ln)
				break
			}
		}
	}
}

// One line of heading per chart, not two. A section title above a panel title
// read as a single title split in half -- "Network" then "Requests" -- which is
// the same complaint the units answered when they moved up beside the title.
func TestAChartHasOneHeadingLine(t *testing.T) {
	m := rollupModel("blog", "api")
	m.width, m.height = 120, 60
	body := stripANSI(m.pageBody())

	for _, gone := range []string{"Network", "System"} {
		for _, ln := range strings.Split(body, "\n") {
			if strings.TrimSpace(ln) == gone {
				t.Errorf("%q is still a heading of its own above the charts", gone)
			}
		}
	}
	// The panel titles are what name them, and each is on the line with its
	// units and nothing else.
	for _, want := range []string{"Requests  req/min", "Processor  % of the machine"} {
		if !strings.Contains(body, want) {
			t.Errorf("%q is not a single heading line:\n%s", want, body)
		}
	}
	// The rows are still separated, which is what the headings were doing
	// besides naming things.
	if !strings.Contains(body, "\n\n  Processor") {
		t.Error("the system row should be separated from the network row")
	}
}

// Which domain reaches which container comes from what the APP declared.
//
// Every app fronts itself with its own gateway now, so the proxy's upstream is
// always <app>-gateway: matching on that put every hostname on the gateway row,
// which is true of the first hop and no use as an answer to "what serves this
// domain".
func TestDomainsLandOnTheContainerTheAppNamed(t *testing.T) {
	a := appRow{
		name: "blog",
		containers: []containerRow{
			{app: "blog", service: "blog-gateway", name: "blog-gateway-1"},
			{app: "blog", service: "api", name: "blog-api-1"},
			{app: "blog", service: "pb", name: "blog-pb-1"},
			{app: "blog", service: "worker", name: "blog-worker-1"},
		},
		hosts: []hostRow{
			{app: "blog", name: "blog.dev", service: "blog-gateway"},
			{app: "blog", name: "www.blog.dev"}, // no arrow
			{app: "blog", name: "api.blog.dev", service: "api"},
			{app: "blog", name: "*.preview.blog.dev", service: "api"},
			{app: "blog", name: "gone.blog.dev", service: "removed"}, // names nothing
		},
		routes: []routeRow{{app: "blog",
			sites:    "blog.dev,www.blog.dev,api.blog.dev,*.preview.blog.dev,gone.blog.dev",
			upstream: "blog-gateway", port: "80"}},
	}
	net := netRow{name: "edge", members: []netMember{
		{container: "blog-gateway-1", aliases: []string{"blog-gateway"}},
	}}
	got := a.routesByContainer(net)

	if want := []string{"api.blog.dev", "*.preview.blog.dev"}; !sameSet(got["blog-api-1"], want) {
		t.Errorf("api serves %v, want %v", got["blog-api-1"], want)
	}
	// The gateway keeps what it was named for, plus everything the app did not
	// annotate -- which is the honest answer for those: the app did not say, and
	// the gateway is genuinely where the request goes.
	if want := []string{"blog.dev", "www.blog.dev", "gone.blog.dev"}; !sameSet(got["blog-gateway-1"], want) {
		t.Errorf("the gateway serves %v, want %v", got["blog-gateway-1"], want)
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

// The annotation has to survive the inventory to be shown. It is dropped from
// the app's own routes line on purpose -- an arrow reads as noise in a list of
// addresses -- so it travels in a record of its own.
func TestTheInventoryCarriesWhatServesEachName(t *testing.T) {
	if !strings.Contains(inventoryScript, `printf "host\t%s\t%s\t%s\n"`) {
		t.Error("the inventory does not report what serves each hostname")
	}
	apps, _, _, _, _ := parseInventory(
		"app\tblog\tdeploy-blog\t/srv/blog\tv1\t2\timg\t\n" +
			"host\tblog\tapi.blog.dev\tapi\n" +
			"host\tblog\tblog.dev\t\n")
	if len(apps) != 1 || len(apps[0].hosts) != 2 {
		t.Fatalf("hosts = %+v", apps)
	}
	if apps[0].hosts[0].service != "api" {
		t.Errorf("the arrow was lost: %+v", apps[0].hosts[0])
	}
	if apps[0].hosts[1].service != "" {
		t.Errorf("a name with no arrow should have no service: %+v", apps[0].hosts[1])
	}
}

// The deployed commit and the listening ports have a column of their own.
//
// In brackets after the name they pushed the name's width around -- a long SHA
// on one app and none on the next left the column ragged, and the name is the
// thing the eye scans down. They share one column because both answer "which
// one is this" and neither is wide, so a column each would be half empty on
// every row.
func TestTheVersionAndPortsHaveTheirOwnColumn(t *testing.T) {
	m := testModel()
	m.scr, m.width, m.height = screenIndex, 140, 30
	m.apps[0].containers = []containerRow{
		{app: "blog", service: "api", name: "blog-api-1", state: "running", status: "Up 3h", ports: "8080,9090"},
		{app: "blog", service: "worker", name: "blog-worker-1", state: "running", status: "Up 3h"},
	}
	body := stripANSI(m.pageBody())

	if strings.Contains(body, "blog (") || strings.Contains(body, "api (:") {
		t.Errorf("the name column still carries the detail in brackets:\n%s", body)
	}
	var appLine, apiLine, workerLine string
	for _, ln := range strings.Split(body, "\n") {
		switch {
		case strings.Contains(ln, " blog "):
			appLine = ln
		case strings.Contains(ln, " api "):
			apiLine = ln
		case strings.Contains(ln, "worker"):
			workerLine = ln
		}
	}
	if !strings.Contains(appLine, "a1b2c3d4e5f6") {
		t.Errorf("the version is missing: %q", appLine)
	}
	if !strings.Contains(apiLine, ":8080, :9090") {
		t.Errorf("the ports are missing: %q", apiLine)
	}
	// A container that binds nothing leaves the cell empty rather than
	// inventing a dash: it is not listening, and there is nothing to report.
	if strings.Contains(workerLine, ":") {
		t.Errorf("worker binds nothing and should say nothing: %q", workerLine)
	}
	// The columns line up: the version and the ports start in the same place.
	if strings.Index(appLine, "a1b2c3d4e5f6") != strings.Index(apiLine, ":8080") {
		t.Errorf("the column is ragged:\n%s\n%s", appLine, apiLine)
	}
}

// Two strips per row: traffic in blue, failures in red, at the same width so a
// bar in one sits directly under the minute it came from in the other.
//
// The numbers that used to sit beside them are gone. A rate is one minute of a
// window the chart already draws, and the chart says more in the same space.
func TestTheErrorsStripIsBesideTheTrafficOne(t *testing.T) {
	m := testModel()
	m.scr, m.width, m.height = screenIndex, 140, 30
	m.apps[0].containers = []containerRow{
		{app: "blog", service: "api", name: "blog-api-1", state: "running", status: "Up 3h"},
		{app: "blog", service: "web", name: "blog-web-1", state: "running", status: "Up 3h"},
	}
	m.apps[0].hosts = []hostRow{
		{app: "blog", name: "api.blog.dev", service: "api"},
		{app: "blog", name: "blog.dev", service: "web"},
	}
	now := time.Now().Unix() / 60 * 60
	for i := 0; i < 40; i++ {
		mn := now - int64(39-i)*60
		errs := 0
		if i > 24 && i < 30 {
			errs = 3
		}
		m.metrics = append(m.metrics,
			metricRow{minute: mn, app: "blog", service: "api", c2: 20, c5: errs},
			metricRow{minute: mn, app: "blog", service: "web", c2: 5})
	}

	bars := "▁▂▃▄▅▆▇█"
	// Failing: bars in both strips.
	if got := stripANSI(m.sparkForService("blog", "api")); !strings.ContainsAny(got, bars) {
		t.Errorf("api traffic strip = %q", got)
	}
	if got := stripANSI(m.errSparkForService("blog", "api")); !strings.ContainsAny(got, bars) {
		t.Errorf("api errors strip = %q, want bars", got)
	}
	// Healthy: traffic, and an EMPTY errors strip. Zero draws no bar, which is
	// the sparkline's own encoding rather than a special case -- so a healthy
	// app is quiet in the column that exists to be noticed.
	if got := stripANSI(m.sparkForService("blog", "web")); !strings.ContainsAny(got, bars) {
		t.Errorf("web traffic strip = %q", got)
	}
	if got := stripANSI(m.errSparkForService("blog", "web")); strings.ContainsAny(got, bars) {
		t.Errorf("web has no failures but its strip has bars: %q", got)
	}
	// Both strips are the same width, or the same minute is in two places.
	if a, b := lipglossWidth(stripANSI(m.sparkForService("blog", "api"))),
		lipglossWidth(stripANSI(m.errSparkForService("blog", "api"))); a != b {
		t.Errorf("strips are %d and %d columns wide", a, b)
	}
	// And no per-minute number survives anywhere on the page.
	if body := stripANSI(m.pageBody()); strings.Contains(body, "/min") {
		t.Errorf("a rate is still printed:\n%s", body)
	}
}

// The mouse belongs to the TERMINAL by default. A program that asks for mouse
// events is one the terminal stops selecting text for, so wheel scrolling would
// cost the ability to highlight anything on any screen -- a bad trade to make on
// somebody's behalf, and the reason this starts off.
func TestTheMouseIsTheTerminalsUntilAskedFor(t *testing.T) {
	if m := testModel(); m.mouseOn {
		t.Error("a fresh model should not be holding the mouse")
	}
	if l := newLoginModel(); l.mouseOn {
		t.Error("neither should the login screen")
	}

	m := testModel()
	m.scr, m.width, m.height = screenLogs, 100, 30
	// Off, so the footer offers what pressing it would GET you: the wheel.
	if !strings.Contains(stripANSI(m.logsKeys()), "wheel") {
		t.Errorf("keys = %q", stripANSI(m.logsKeys()))
	}

	on, cmd := sendCmd(m, "s")
	if !on.mouseOn || cmd == nil {
		t.Fatal("s should ask the terminal for the wheel")
	}
	// And it says what that cost, because text going unselectable with no
	// explanation is the confusing half of this trade.
	if !strings.Contains(on.status, "select") {
		t.Errorf("status = %q", on.status)
	}
	if !strings.Contains(stripANSI(on.logsKeys()), "select") {
		t.Errorf("the key should offer selection back: %q", stripANSI(on.logsKeys()))
	}
	if !strings.Contains(stripANSI(on.monitorKeys()), "select") {
		t.Errorf("the monitor should offer it too: %q", stripANSI(on.monitorKeys()))
	}

	off, cmd := sendCmd(on, "s")
	if off.mouseOn || cmd == nil {
		t.Error("s again should give it back")
	}
}

// It must not eat an "s" out of a field. Every printable key belongs to the
// input while one is open.
func TestSelectingDoesNotStealSFromATextField(t *testing.T) {
	m := testModel()
	m.scr, m.width, m.height = screenIndex, 100, 30
	m.cursor = m.rowIndex(focusApp)
	// The config prompt is an input.
	m = m.ask(m.configPrompt(m.apps[0]))
	before := m.prompt.typed

	next, _ := sendCmd(m, "s")
	if next.mouseOn {
		t.Error("s in a text field is a letter, not a command")
	}
	if next.prompt == nil || next.prompt.typed != before+"s" {
		t.Errorf("typed = %q, want %q", next.prompt.typed, before+"s")
	}

	// Same on the login screen, where the whole page is one field.
	l := newLoginModel()
	l.width, l.height = 100, 30
	if lit, _ := sendCmd(l, "s"); lit.mouseOn {
		t.Error("s on the login screen is a letter")
	}
}
