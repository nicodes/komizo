package box

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// The property docker.go exists to defend, asserted rather than described.
//
// The cost of talking to docker is per CALL, not per container, and this runs
// on a five-second poll. An earlier version asked per app -- a `compose ps` to
// find an app's containers, an `inspect` for each one's service and pid,
// another for its mounts -- which put a six-app box at roughly eighty
// invocations per report. Nothing about that shows up in a passing test suite,
// which is why it needs one of its own.
func TestDockerCallsDoNotGrowWithTheBox(t *testing.T) {
	count := func(apps int) (int, []string) {
		f := newFakeBox(t)
		var psLines, inspectLines []string
		for i := range apps {
			name := fmt.Sprintf("app%02d", i)
			f.write("/var/lib/komizo/apps/"+name+".env", "APP_DIR=/srv/"+name+"\n")
			for _, svc := range []string{"web", "db", "worker"} {
				id := name + "-" + svc
				psLines = append(psLines,
					id+"\t"+id+"-1\trunning\tUp 3 hours\t"+svc+"\timg\t/srv/"+name)
				inspectLines = append(inspectLines,
					id+"\t2026-08-02T09:00:00Z\t0001-01-01T00:00:00Z\t0\t1234\tedge="+svc+", \tvol-"+id+"=/v/"+id+" ")
			}
		}
		f.reply("info", "29.1.3").
			reply("--version", "Docker version 29.1.3").
			reply("ps -a --no-trunc", ps(psLines...)).
			reply("inspect --format {{.Id}}", inspect(inspectLines...)).
			reply("network inspect edge --format {{.Driver}}", "bridge\t172.22.0.0/16")

		p := f.probe()
		inner := p.Docker
		var seen []string
		p.Docker = func(ctx context.Context, args ...string) (string, error) {
			seen = append(seen, strings.Join(args, " "))
			return inner(ctx, args...)
		}

		r := p.Report(context.Background())
		// Asserted, so a version that makes no calls because it found nothing
		// cannot pass this by measuring an empty box.
		if len(r.Apps) != apps {
			t.Fatalf("probed %d apps, want %d", len(r.Apps), apps)
		}
		for _, a := range r.Apps {
			if len(a.Containers) != 3 {
				t.Fatalf("%s has %d containers, want 3", a.Name, len(a.Containers))
			}
		}
		return len(seen), seen
	}

	one, _ := count(1)
	many, calls := count(20)
	if one != many {
		t.Errorf("docker calls grew with the box: %d at one app, %d at twenty:\n  %s",
			one, many, strings.Join(calls, "\n  "))
	}
	// A ceiling as well as a constant, so a call added out of habit is noticed
	// rather than merely being constant at some larger number: --version, info,
	// ps, inspect, and one network inspect.
	if many > 5 {
		t.Errorf("%d docker calls per report, want at most 5:\n  %s", many, strings.Join(calls, "\n  "))
	}
}
