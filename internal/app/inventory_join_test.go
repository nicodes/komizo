package app

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/scripts"
)

// The inventory's per-container join, executed.
//
// It reads two buffers -- `docker ps -a` and `docker inspect` -- and produces
// the container and cstat records the interface is built from. It used to do
// that with five separate `printf | awk` pipelines over the same two buffers,
// which is ten processes per container on a five-second poll; it is now two
// passes with a \034 record between the buffers so awk can tell them apart.
//
// That rewrite moves every field, which is exactly the kind of change that
// compiles, parses, runs, and quietly puts the image where the status should be.
// So: run the real awk against real buffer text, and feed what comes out to the
// real parser.

// joinAwk pulls one of the two awk programs out of the inventory script.
//
// By its `-v` signature rather than by line number, so reformatting the script
// does not silently make this test check nothing. Neither program contains a
// single quote, so the first quote after the marker opens it and the next one
// closes it.
func joinAwk(t *testing.T, marker string) string {
	t.Helper()
	i := strings.Index(scripts.Inventory(), marker)
	if i < 0 {
		t.Fatalf("could not find %q in the inventory script -- has the join been rewritten?", marker)
	}
	rest := scripts.Inventory()[i+len(marker):]
	j := strings.Index(rest, "'")
	if j < 0 {
		t.Fatal("the awk program is not quoted as expected")
	}
	rest = rest[j+1:]
	k := strings.Index(rest, "'")
	if k < 0 {
		t.Fatal("could not find the end of the awk program")
	}
	return rest[:k]
}

// The two buffers as the script builds them, joined the way cinfo() joins them.
//
// allc:   id, name, state, status, service, image
// starts: id, startedAt, finishedAt, exitCode, pid
func cinfo(allc, starts []string) string {
	return strings.Join(allc, "\n") + "\n\034\n" + strings.Join(starts, "\n") + "\n"
}

func runJoin(t *testing.T, prog string, vars map[string]string, in string) string {
	t.Helper()
	args := []string{"-F", "\t"}
	// Sorted for a stable command line; awk does not care which order these
	// arrive in.
	for _, k := range []string{"id", "app", "pt", "st"} {
		if v, ok := vars[k]; ok {
			args = append(args, "-v", k+"="+v)
		}
	}
	args = append(args, prog)
	cmd := exec.Command("awk", args...)
	cmd.Stdin = strings.NewReader(in)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("awk failed: %v\n%s", err, out)
	}
	return string(out)
}

const (
	pidMarker    = `info="$(cinfo | awk -F'\t' -v id="$cid" `
	recordMarker = `cinfo | awk -F'\t' -v id="$cid" -v app="$app" -v pt="$cports" -v st="$cst" `
)

// The row the join is supposed to produce, end to end: awk output straight into
// the parser the interface uses.
func TestTheContainerJoinEmitsEveryFieldInTheRightPlace(t *testing.T) {
	needs(t, "awk")

	in := cinfo(
		[]string{
			"deadbeef\tblog-web-1\trunning\tUp 3 hours\tweb\tghcr.io/you/blog-web:abc123",
			"cafe0001\tshop-web-1\trunning\tUp 2 days\tweb\tghcr.io/you/shop-web:def456",
		},
		[]string{
			"deadbeef\t2026-07-31T10:00:00.5Z\t0001-01-01T00:00:00Z\t0\t4242",
			"cafe0001\t2026-07-29T09:00:00Z\t0001-01-01T00:00:00Z\t0\t99",
		},
	)

	out := runJoin(t, joinAwk(t, recordMarker), map[string]string{
		"id": "deadbeef", "app": "blog", "pt": "80,8080", "st": "12345\t67890\t0",
	}, in)

	inv := parseInventory("app\tblog\tkomizo-blog\t/srv/blog\tabc123\t1\tghcr.io/you/blog-config\t\n" + out)
	apps := inv.apps
	if len(apps) != 1 || len(apps[0].containers) != 1 {
		t.Fatalf("expected one app with one container, got %d apps: %q", len(apps), out)
	}
	c := apps[0].containers[0]

	for _, x := range []struct{ name, got, want string }{
		{"app", c.app, "blog"},
		{"service", c.service, "web"},
		{"name", c.name, "blog-web-1"},
		{"state", c.state, "running"},
		{"status", c.status, "Up 3 hours"},
		{"image", c.image, "ghcr.io/you/blog-web:abc123"},
		{"ports", c.ports, "80,8080"},
	} {
		if x.got != x.want {
			t.Errorf("%s: got %q, want %q", x.name, x.got, x.want)
		}
	}
	if c.startedAt.IsZero() {
		t.Error("startedAt did not parse -- the timestamp landed in the wrong field")
	}
	// Docker's zero time means "never stopped", which parseStamp turns back into
	// a zero Time. A non-zero here would mean finishedAt picked up startedAt.
	if !c.finishedAt.IsZero() {
		t.Errorf("finishedAt should be zero for a running container, got %v", c.finishedAt)
	}
	if c.exitCode != 0 {
		t.Errorf("exitCode: got %d, want 0", c.exitCode)
	}
}

// The cstat record rides on the same pass. It is deliberately a separate
// RECORD -- a reading that could not be taken must leave the row alone -- and
// the rewrite is what makes it share a pass rather than a shape.
func TestTheJoinEmitsTheResourceRecordToo(t *testing.T) {
	needs(t, "awk")

	in := cinfo(
		[]string{"deadbeef\tblog-web-1\trunning\tUp 3 hours\tweb\tghcr.io/you/blog-web:abc"},
		[]string{"deadbeef\t2026-07-31T10:00:00Z\t0001-01-01T00:00:00Z\t0\t4242"},
	)
	out := runJoin(t, joinAwk(t, recordMarker), map[string]string{
		"id": "deadbeef", "app": "blog", "pt": "", "st": "12345\t67890\t134217728",
	}, in)

	s := parseSystem(out, time.Unix(0, 0))
	c, ok := s.statFor("blog", "web")
	if !ok {
		t.Fatalf("no cstat record for blog/web: %q", out)
	}
	if !c.haveCPU || c.cpuUsec != 12345 {
		t.Errorf("cpu: got %d (have=%v), want 12345", c.cpuUsec, c.haveCPU)
	}
	if !c.haveMem || c.mem != 67890 {
		t.Errorf("mem: got %d (have=%v), want 67890", c.mem, c.haveMem)
	}
	if !c.hasLimit || c.limit != 134217728 {
		t.Errorf("limit: got %d (has=%v), want 134217728", c.limit, c.hasLimit)
	}
}

// A container that stopped: the exit code and the finish time are the whole
// reason the record carries them, and they come from the SECOND buffer -- the
// half the \034 marker exists to separate.
func TestTheJoinCarriesAnExitedContainersCodeAndTime(t *testing.T) {
	needs(t, "awk")

	in := cinfo(
		[]string{"deadbeef\tblog-web-1\texited\tExited (137) 5 minutes ago\tweb\tghcr.io/you/blog-web:abc"},
		[]string{"deadbeef\t2026-07-31T10:00:00Z\t2026-07-31T11:00:00Z\t137\t0"},
	)
	out := runJoin(t, joinAwk(t, recordMarker), map[string]string{
		"id": "deadbeef", "app": "blog", "pt": "", "st": "\t\t",
	}, in)

	inv := parseInventory("app\tblog\tkomizo-blog\t/srv/blog\tabc\t0\tghcr.io/you/blog-config\t\n" + out)
	apps := inv.apps
	if len(apps) != 1 || len(apps[0].containers) != 1 {
		t.Fatalf("expected one container, got %q", out)
	}
	c := apps[0].containers[0]
	if c.exitCode != 137 {
		t.Errorf("exitCode: got %d, want 137", c.exitCode)
	}
	if c.finishedAt.IsZero() {
		t.Error("finishedAt did not parse")
	}
	if c.state != "exited" {
		t.Errorf("state: got %q, want exited", c.state)
	}
}

// A container listed by compose that docker no longer reports emits nothing at
// all, rather than a row of empty fields. `have` is what decides that, and the
// pass is written so an unmatched id falls straight through.
func TestTheJoinEmitsNothingForAContainerThatIsGone(t *testing.T) {
	needs(t, "awk")

	in := cinfo(
		[]string{"cafe0001\tshop-web-1\trunning\tUp 2 days\tweb\tghcr.io/you/shop-web:def"},
		[]string{"cafe0001\t2026-07-29T09:00:00Z\t0001-01-01T00:00:00Z\t0\t99"},
	)
	out := runJoin(t, joinAwk(t, recordMarker), map[string]string{
		"id": "deadbeef", "app": "blog", "pt": "", "st": "\t\t",
	}, in)
	if strings.TrimSpace(out) != "" {
		t.Errorf("expected no records for an id in neither buffer, got %q", out)
	}
}

// Pass one: the pid the /proc reads need, and the state the running count is
// built from. Both are defaulted in awk, because the shell splits the answer on
// a single space and an empty field would shift the other one into its place.
func TestThePidPassAlwaysReturnsTwoFields(t *testing.T) {
	needs(t, "awk")
	prog := joinAwk(t, pidMarker)

	cases := []struct {
		name, id, allc, starts string
		wantPid, wantState     string
	}{
		{
			name:   "a running container",
			id:     "deadbeef",
			allc:   "deadbeef\tblog-web-1\trunning\tUp 3 hours\tweb\tghcr.io/you/blog-web:abc",
			starts: "deadbeef\t2026-07-31T10:00:00Z\t0001-01-01T00:00:00Z\t0\t4242",
			// The state drives the running count, and the pid drives every
			// resource number on the row.
			wantPid: "4242", wantState: "running",
		},
		{
			name: "a stopped container has no pid",
			id:   "deadbeef",
			allc: "deadbeef\tblog-web-1\texited\tExited (0) 1 hour ago\tweb\tghcr.io/you/blog-web:abc",
			// docker reports pid 0 for a container that is not running.
			starts:  "deadbeef\t2026-07-31T10:00:00Z\t2026-07-31T11:00:00Z\t0\t0",
			wantPid: "0", wantState: "exited",
		},
		{
			name:   "absent from both buffers still yields two fields",
			id:     "nosuch",
			allc:   "deadbeef\tblog-web-1\trunning\tUp 3 hours\tweb\tghcr.io/you/blog-web:abc",
			starts: "deadbeef\t2026-07-31T10:00:00Z\t0001-01-01T00:00:00Z\t0\t4242",
			// Never empty: the shell does ${info%% *} / ${info#* } on this, and
			// a blank pid would make the state be read as the pid.
			wantPid: "0", wantState: "-",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := runJoin(t, prog, map[string]string{"id": c.id},
				cinfo([]string{c.allc}, []string{c.starts}))
			parts := strings.Split(out, " ")
			if len(parts) != 2 {
				t.Fatalf("expected exactly two space-separated fields, got %q", out)
			}
			if parts[0] != c.wantPid {
				t.Errorf("pid: got %q, want %q", parts[0], c.wantPid)
			}
			if parts[1] != c.wantState {
				t.Errorf("state: got %q, want %q", parts[1], c.wantState)
			}
		})
	}
}
