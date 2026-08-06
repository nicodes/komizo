package box

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A fake box on disk, plus a fake docker. Between them every probe in this
// package can be exercised without a server, which is the point of the Root and
// Docker seams on Probe.

type fakeBox struct {
	t    *testing.T
	root string
	// replies are matched on the joined argument list containing the key, first
	// match wins. A prefix is enough to pick out one call and keeps the tests
	// from restating docker's whole format string.
	replies []reply
}

type reply struct{ match, out string }

func newFakeBox(t *testing.T) *fakeBox {
	t.Helper()
	return &fakeBox{t: t, root: t.TempDir()}
}

func (f *fakeBox) write(path, content string) {
	f.t.Helper()
	full := filepath.Join(f.root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeBox) mkdir(path string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Join(f.root, path), 0o755); err != nil {
		f.t.Fatal(err)
	}
}

// reply sets what docker says for calls containing match, REPLACING any reply
// already set for the same key. Appending instead would mean a test that
// overrides one of readyBox's defaults silently gets the default, because the
// lookup takes the first match -- which is a test that passes while measuring
// nothing.
func (f *fakeBox) reply(match, out string) *fakeBox {
	for i := range f.replies {
		if f.replies[i].match == match {
			f.replies[i].out = out
			return f
		}
	}
	f.replies = append(f.replies, reply{match, out})
	return f
}

func (f *fakeBox) probe() *Probe {
	at := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	return &Probe{
		Root:  f.root,
		Now:   func() time.Time { return at },
		Agent: "test",
		Docker: func(_ context.Context, args ...string) (string, error) {
			joined := strings.Join(args, " ")
			for _, r := range f.replies {
				if strings.Contains(joined, r.match) {
					return r.out, nil
				}
			}
			return "", fmt.Errorf("no docker reply for %q", joined)
		},
	}
}

// A box with docker up, one app, and a proxy. The shape most tests want.
func readyBox(t *testing.T) *fakeBox {
	f := newFakeBox(t)
	f.write("/etc/os-release", "NAME=\"Alpine Linux\"\nPRETTY_NAME=\"Alpine Linux v3.20\"\n")
	f.write("/var/lib/komizo/version", "0.0.12\nabc123\n")
	f.write("/var/lib/komizo/apps/blog.env",
		"APP_DIR=/srv/blog\nCI_USER=komizo-blog\nCONFIG_IMAGE=ghcr.io/n/blog-config\nKNOWN_AS=blog.example.com\n")
	f.write("/srv/blog/compose.yml", "services:\n  web:\n    image: x\n")
	f.write("/srv/blog/.env", "APP_VERSION=e1b2557\n")
	f.write("/srv/blog/hostnames", "blog.example.com -> web\n# a comment\nwww.example.com\n")
	f.write("/proc/stat", "cpu  100 0 50 800 20 0 0 0 0 0\ncpu0 1 2 3 4 5\n")
	f.write("/proc/cpuinfo", "processor\t: 0\nprocessor\t: 1\n")
	f.write("/proc/meminfo", "MemTotal:       1000 kB\nMemAvailable:    400 kB\n")
	f.write("/proc/uptime", "91238.15 700000.00\n")
	f.write("/etc/ssh/ssh_host_ed25519_key.pub", "ssh-ed25519 AAAAC3Nz root@box\n")

	// Two calls describe the whole box, and these are their shapes.
	//
	// The working_dir is unprefixed even though Probe.Root is set: Root is a
	// fiction for the FILESYSTEM, and docker on a real box reports the same
	// absolute path the app's state file records as APP_DIR. That equality is
	// what joins a container to its app.
	//
	// ps:      id, name, state, status, service, image, compose working_dir
	// inspect: id, startedAt, finishedAt, exitCode, pid, networks, mounts
	f.reply("info", "29.1.3").
		reply("--version", "Docker version 29.1.3, build f52814d").
		reply("ps -a --no-trunc", ps(
			"cid1\tblog-web-1\trunning\tUp 3 hours\tweb\tghcr.io/n/blog:e1b2557\t"+"/srv/blog")).
		reply("inspect --format {{.Id}}", inspect(
			"cid1\t2026-08-02T09:00:00Z\t0001-01-01T00:00:00Z\t0\t1234\tedge=blog-web,web, \t")).
		reply("network inspect edge --format {{.Driver}}", "bridge\t172.22.0.0/16")
	return f
}

// ps and inspect exist to name what a fixture is, since both are tab-separated
// lines and the two are easy to confuse at a glance.
func ps(lines ...string) string      { return strings.Join(lines, "\n") }
func inspect(lines ...string) string { return strings.Join(lines, "\n") }

func TestReportReadsTheBox(t *testing.T) {
	f := readyBox(t)
	r := f.probe().Report(context.Background())

	if r.V != Version {
		t.Errorf("V = %d, want %d", r.V, Version)
	}
	if !r.Server.Ready() {
		t.Fatalf("server state = %q, want ready", r.Server.State)
	}
	if r.Server.OS != "Alpine Linux v3.20" {
		t.Errorf("OS = %q", r.Server.OS)
	}
	if r.Server.UptimeS != 91238 {
		t.Errorf("uptime = %d, want 91238", r.Server.UptimeS)
	}
	// Read back, not assumed: two lines means version then stamp.
	if r.Server.Komizo.Version != "0.0.12" || r.Server.Komizo.Stamp != "abc123" {
		t.Errorf("komizo install = %+v", r.Server.Komizo)
	}
	if !r.Server.Komizo.Installed {
		t.Error("komizo should read as installed")
	}
	if r.Server.Komizo.Agent != "test" {
		t.Errorf("agent = %q, want test", r.Server.Komizo.Agent)
	}
	if len(r.Server.HostKeys) != 1 || r.Server.HostKeys[0].Type != "ssh-ed25519" {
		t.Errorf("host keys = %+v", r.Server.HostKeys)
	}

	if len(r.Apps) != 1 {
		t.Fatalf("apps = %d, want 1", len(r.Apps))
	}
	a := r.Apps[0]
	if a.Name != "blog" || a.User != "komizo-blog" || a.Version != "e1b2557" {
		t.Errorf("app = %+v", a)
	}
	if a.ConfigImage != "ghcr.io/n/blog-config" {
		t.Errorf("config image = %q", a.ConfigImage)
	}
	if len(a.KnownAs) != 1 || a.KnownAs[0] != "blog.example.com" {
		t.Errorf("known as = %v", a.KnownAs)
	}
	if a.Running() != 1 {
		t.Errorf("running = %d, want 1", a.Running())
	}
	if len(a.Containers) != 1 || a.Containers[0].Service != "web" {
		t.Fatalf("containers = %+v", a.Containers)
	}
	if got := a.Containers[0].StartedAt; got.Hour() != 9 {
		t.Errorf("startedAt = %v", got)
	}
	// A container that has never stopped reports a zero time from docker, which
	// parses fine and would otherwise read as an uptime measured from year 1.
	if !a.Containers[0].FinishedAt.IsZero() {
		t.Errorf("finishedAt should be zero, got %v", a.Containers[0].FinishedAt)
	}

	// The comment line is dropped; the arrow is kept where it was given and
	// empty where it was not.
	want := []Host{{Name: "blog.example.com", Service: "web"}, {Name: "www.example.com"}}
	if fmt.Sprint(a.Hosts) != fmt.Sprint(want) {
		t.Errorf("hosts = %+v, want %+v", a.Hosts, want)
	}

	if r.System.Cores != 2 {
		t.Errorf("cores = %d, want 2", r.System.Cores)
	}
	// Total is every field; idle counts iowait with it.
	if r.System.CPU == nil || r.System.CPU.Total != 970 || r.System.CPU.Idle != 820 {
		t.Errorf("cpu = %+v, want total 970 idle 820", r.System.CPU)
	}
	// Used is total minus AVAILABLE, never minus free.
	if r.System.Mem == nil || r.System.Mem.Used != 600*1024 {
		t.Errorf("mem = %+v, want used %d", r.System.Mem, 600*1024)
	}
}

func TestBareAndStoppedBoxesAreStatesNotErrors(t *testing.T) {
	t.Run("bare", func(t *testing.T) {
		f := newFakeBox(t)
		r := f.probe().Report(context.Background())
		if r.Server.State != "bare" {
			t.Errorf("state = %q, want bare", r.Server.State)
		}
		// Nothing else is true about it, and nothing else is claimed.
		if len(r.Apps) != 0 || r.Proxy != nil || r.Network != nil {
			t.Errorf("a bare box should report nothing else: %+v", r)
		}
	})
	t.Run("docker installed but down", func(t *testing.T) {
		f := newFakeBox(t)
		f.reply("--version", "Docker version 29.1.3")
		r := f.probe().Report(context.Background())
		if r.Server.State != "docker-stopped" {
			t.Errorf("state = %q, want docker-stopped", r.Server.State)
		}
	})
}

// The version file is two lines and komizo writes both. A file with one is not
// a file komizo wrote, and picking a field out of it would be a guess presented
// as a fact -- so it reads as installed with nothing known about it, which is
// exactly what it is.
func TestAMalformedVersionFileClaimsNothing(t *testing.T) {
	f := newFakeBox(t)
	f.write("/var/lib/komizo/version", "abc123\n")
	k := f.probe().komizoInstall()
	if !k.Installed {
		t.Error("the file exists, so komizo is installed")
	}
	if k.Version != "" || k.Stamp != "" {
		t.Errorf("a one-line file should yield no fields, got %+v", k)
	}
}

func TestOrphansSkipKomizosOwnDirectories(t *testing.T) {
	f := newFakeBox(t)
	f.mkdir("/srv/_proxy")   // komizo's own, never has a state file
	f.mkdir("/srv/blog")     // has one, below
	f.mkdir("/srv/leftover") // does not
	f.write("/var/lib/komizo/apps/blog.env", "APP_DIR=/srv/blog\n")

	got := f.probe().orphans()
	if len(got) != 1 || got[0] != "leftover" {
		t.Errorf("orphans = %v, want [leftover]", got)
	}
}

func TestAppsAreFoundByStateFileNotByDirectory(t *testing.T) {
	// An app placed elsewhere with --app-dir. A glob over /srv would miss it
	// entirely, and its charts would be permanently empty.
	f := readyBox(t)
	f.write("/var/lib/komizo/apps/api.env", "APP_DIR=/opt/api\nCI_USER=komizo-api\n")
	f.write("/opt/api/compose.yml", "services: {}\n")
	f.write("/opt/api/.env", "APP_VERSION=deadbee\n")

	r := f.probe().Report(context.Background())
	var names []string
	for _, a := range r.Apps {
		names = append(names, a.Name)
	}
	if fmt.Sprint(names) != "[api blog]" {
		t.Errorf("apps = %v, want [api blog]", names)
	}
	for _, a := range r.Apps {
		if a.Name == "api" && a.Version != "deadbee" {
			t.Errorf("api version = %q, want deadbee", a.Version)
		}
	}
}

func TestStoppedIsHeldOnTheBox(t *testing.T) {
	f := readyBox(t)
	f.write("/var/lib/komizo/apps/blog.env",
		"APP_DIR=/srv/blog\nCI_USER=komizo-blog\nSTOPPED=1\nSTOPPED_BY=alice\nSTOPPED_AT=2026-08-01T10:30:00Z\n")

	r := f.probe().Report(context.Background())
	a := r.Apps[0]
	if !a.Stopped || a.StoppedBy != "alice" {
		t.Fatalf("stopped state = %+v", a)
	}
	if a.StoppedAt.Day() != 1 {
		t.Errorf("stoppedAt = %v", a.StoppedAt)
	}
}

// THE TWO READERS OF THIS RECORD MUST AGREE, and only one of them was tested.
//
// The marker is read twice by different code in different languages: here, to
// decide whether the report says an app is stopped and therefore whether
// diagnose.go raises app_down; and by the generated deploy script, to decide
// whether a deploy starts the app. scripts/deploy_stopped_test.go pins the
// shell side over exactly these cases. Nothing pinned this side, so widening
// `== "1"` to `!= ""` passed the whole suite -- and the two would then disagree
// about the same file, which is the one thing this design cannot afford. An app
// the report calls stopped while the deploy starts it is komizo#57's state, and
// it never pages again.
//
// Each case below is the same case the shell test makes, in the same order, so
// the pair can be read side by side.
func TestTheReportAndTheDeployReadTheMarkerTheSameWay(t *testing.T) {
	// ONE TABLE, in ../testdata, read by this test and by the shell's. It used
	// to be two, kept in step by a comment saying they were the same cases in
	// the same order -- and deleting a case from either left the whole suite
	// green. Including in the direction that matters: the shell growing a case
	// the Go reader was never asked about.
	for _, tc := range markerCases(t) {
		t.Run(tc.Name, func(t *testing.T) {
			f := readyBox(t)
			f.write("/var/lib/komizo/apps/blog.env", tc.Record)
			a := f.probe().Report(context.Background()).Apps[0]
			if a.Stopped != tc.Stopped {
				t.Errorf("Stopped = %v, want %v, for record %q\n%s", a.Stopped, tc.Stopped, tc.Record, tc.Why)
			}
		})
	}
}

func TestListeningPortsComeFromTheNetworkNamespace(t *testing.T) {
	f := newFakeBox(t)
	// State 0A is LISTEN. 0x1F90 is 8080; 0x9C40 is 40000, an ephemeral port
	// that is a runtime's private business; 01 is not LISTEN.
	f.write("/proc/42/net/tcp", strings.Join([]string{
		"  sl  local_address rem_address   st",
		"   0: 00000000:1F90 00000000:0000 0A",
		"   1: 00000000:9C40 00000000:0000 0A",
		"   2: 00000000:0050 00000000:0000 01",
	}, "\n"))
	f.write("/proc/42/net/tcp6", "   0: 00000000000000000000000000000000:01BB 00000000:0000 0A\n")

	got := f.probe().listeningPorts(42)
	if fmt.Sprint(got) != "[443 8080]" {
		t.Errorf("ports = %v, want [443 8080]", got)
	}
	if f.probe().listeningPorts(0) != nil {
		t.Error("a container with no pid has no namespace to read")
	}
}

func TestCgroupUnknownIsNotZero(t *testing.T) {
	f := newFakeBox(t)
	// A pid with no cgroup this can read at all.
	f.write("/proc/7/cgroup", "0::/nope\n")
	cs := f.probe().cgroupStat(7)
	if cs.CPUUsec != nil || cs.Mem != nil {
		t.Errorf("unreadable cgroup should report nil, got %+v", cs)
	}
}

func TestCgroupV2(t *testing.T) {
	f := newFakeBox(t)
	f.write("/proc/7/cgroup", "0::/docker/abc\n")
	f.write("/sys/fs/cgroup/docker/abc/cpu.stat", "usage_usec 1234567\nuser_usec 1\n")
	f.write("/sys/fs/cgroup/docker/abc/memory.current", "10000\n")
	f.write("/sys/fs/cgroup/docker/abc/memory.stat", "inactive_file 4000\n")
	f.write("/sys/fs/cgroup/docker/abc/memory.max", "max\n")

	cs := f.probe().cgroupStat(7)
	if cs.CPUUsec == nil || *cs.CPUUsec != 1234567 {
		t.Errorf("cpu = %v", cs.CPUUsec)
	}
	// Inactive page cache is memory the container is BORROWING.
	if cs.Mem == nil || *cs.Mem != 6000 {
		t.Errorf("mem = %v, want 6000", cs.Mem)
	}
	// "max" is not a number and means uncapped.
	if cs.Limit != nil {
		t.Errorf("limit = %v, want nil for an uncapped container", cs.Limit)
	}
}

func TestCgroupV1ConvertsNanosecondsToMicroseconds(t *testing.T) {
	f := newFakeBox(t)
	f.write("/proc/7/cgroup", "3:cpuacct,cpu:/docker/abc\n4:memory:/docker/abc\n")
	f.write("/sys/fs/cgroup/cpuacct/docker/abc/cpuacct.usage", "1234567000\n")
	f.write("/sys/fs/cgroup/memory/docker/abc/memory.usage_in_bytes", "10000\n")
	f.write("/sys/fs/cgroup/memory/docker/abc/memory.stat", "total_inactive_file 4000\n")

	cs := f.probe().cgroupStat(7)
	if cs.CPUUsec == nil || *cs.CPUUsec != 1234567 {
		t.Errorf("cpu = %v, want the v2 unit", cs.CPUUsec)
	}
	if cs.Mem == nil || *cs.Mem != 6000 {
		t.Errorf("mem = %v", cs.Mem)
	}
}

func TestMemoryNeverWrapsBelowZero(t *testing.T) {
	// current and inactive_file are read from two files a moment apart. A
	// container whose cache grew between them would wrap to sixteen exabytes.
	f := newFakeBox(t)
	f.write("/proc/7/cgroup", "0::/docker/abc\n")
	f.write("/sys/fs/cgroup/docker/abc/memory.current", "1000\n")
	f.write("/sys/fs/cgroup/docker/abc/memory.stat", "inactive_file 5000\n")

	cs := f.probe().cgroupStat(7)
	if cs.Mem == nil || *cs.Mem != 0 {
		t.Errorf("mem = %v, want 0 rather than a wrap", cs.Mem)
	}
}

// / and /var/lib/docker are measured separately, because the one that fills is
// usually not the one people watch. On most boxes they are the same filesystem,
// and listing it twice reads as twice the disk.
//
// Folded by DEVICE, not by mount point: docker setups routinely bind-mount
// /var/lib/docker onto itself, which gives one filesystem two mount points, and
// folding by mount point drew that box's one disk as two identical bars.
//
// This is the only place the rule lives. The reader trusts what it is sent --
// two implementations of one rule is how they come to disagree.
func TestOneFilesystemUnderTwoMounts(t *testing.T) {
	// statfs is the real syscall here, so this asserts against whatever this
	// machine actually has. /var/lib/docker either is its own filesystem or is
	// not, and both are answers this must handle.
	p := &Probe{}
	got := p.disks()
	if len(got) == 0 {
		t.Skip("no readable filesystem")
	}
	seen := map[string]bool{}
	for _, d := range got {
		if d.Dev == "" {
			t.Errorf("a disk with no device cannot be folded: %+v", d)
			continue
		}
		if seen[d.Dev] {
			t.Errorf("device %s reported twice: %+v", d.Dev, got)
		}
		seen[d.Dev] = true
		if d.Size == 0 {
			t.Errorf("a filesystem with no size is not a measurement: %+v", d)
		}
		if d.Used > d.Size {
			t.Errorf("used exceeds size: %+v", d)
		}
	}
	// / is always there and is always first, so the row order is stable.
	if got[0].Mount != "/" {
		t.Errorf("first disk = %q, want /", got[0].Mount)
	}
}

func TestProxyAndNetwork(t *testing.T) {
	f := readyBox(t)
	f.write("/srv/_proxy/compose.yml", "services:\n  proxy:\n    image: caddy:2\nnetworks:\n  edge:\n    name: edge\n")
	f.write("/srv/_proxy/Caddyfile", "{\n  on_demand_tls {\n    ask https://gate.example.com/check\n  }\n}\n")
	f.reply("ps -a --no-trunc", ps(
		"cid1\tblog-web-1\trunning\tUp 3 hours\tweb\tghcr.io/n/blog:e1b2557\t"+"/srv/blog",
		"cid2\tkomizo-proxy\trunning\tUp 5 hours\tproxy\tcaddy:2\t"+"/srv/_proxy"))
	f.reply("inspect --format {{.Id}}", inspect(
		"cid1\t2026-08-02T09:00:00Z\t0001-01-01T00:00:00Z\t0\t1234\tedge=blog-web,web, \t",
		"cid2\t2026-08-02T07:00:00Z\t0001-01-01T00:00:00Z\t0\t5678\tedge=komizo-proxy, \t"))

	r := f.probe().Report(context.Background())
	if r.Proxy == nil {
		t.Fatal("proxy should be installed")
	}
	if !r.Proxy.Running() || r.Proxy.Image != "caddy:2" || r.Proxy.Network != "edge" {
		t.Errorf("proxy = %+v", r.Proxy)
	}
	if r.Proxy.TLSAsk != "https://gate.example.com/check" {
		t.Errorf("tls ask = %q", r.Proxy.TLSAsk)
	}
	if r.Network == nil || r.Network.Driver != "bridge" || r.Network.Subnet != "172.22.0.0/16" {
		t.Errorf("network = %+v", r.Network)
	}
}

func TestReportCarriesNoSecrets(t *testing.T) {
	// The standing promise. An app's .env and secrets.env are 600 root, and this
	// runs as root -- so the only thing keeping them off the wire is that
	// nothing reads them.
	f := readyBox(t)
	f.write("/srv/blog/.env", "APP_VERSION=e1b2557\nDATABASE_URL=postgres://user:hunter2@db/blog\n")
	f.write("/srv/blog/secrets.env", "STRIPE_KEY=sk_live_totallyreal\n")

	r := f.probe().Report(context.Background())
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"hunter2", "sk_live_totallyreal", "DATABASE_URL", "STRIPE_KEY"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("report leaked %q:\n%s", secret, b)
		}
	}
	// And the one value from that file that IS meant to travel.
	if !strings.Contains(string(b), "e1b2557") {
		t.Error("the deployed version should be reported")
	}
}
