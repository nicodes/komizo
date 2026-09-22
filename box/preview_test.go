package box

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The preview contract, pinned as tests. A preview is a GUEST: it gets its
// own project, database, route and ports, and it may never touch production
// data, another preview's things, or the proxy's other routes. The gates for
// the whole program live here.

var previewNow = time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)

// fakeDocker records argv and answers the handful of calls a lifecycle makes.
type fakeDocker struct {
	calls       [][]string
	validateErr error
	psqlErr     error
}

func (f *fakeDocker) run(_ context.Context, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{}, args...))
	switch args[0] {
	case "ps":
		return "gdam-db-1\tpostgres:16\n", nil
	case "exec":
		// caddy validate/reload against the proxy; psql against the db.
		if len(args) > 2 && args[2] == "caddy" && args[3] == "validate" && f.validateErr != nil {
			return "", f.validateErr
		}
		if len(args) > 2 && args[2] == "psql" && f.psqlErr != nil {
			return "", f.psqlErr
		}
		return "", nil
	default:
		return "", nil
	}
}

func (f *fakeDocker) matching(want ...string) [][]string {
	var out [][]string
	for _, c := range f.calls {
		j := strings.Join(c, " ")
		ok := true
		for _, w := range want {
			if !strings.Contains(j, w) {
				ok = false
			}
		}
		if ok {
			out = append(out, c)
		}
	}
	return out
}

func previewTestConfig(t *testing.T) PreviewUpConfig {
	t.Helper()
	root := t.TempDir()
	cfg := PreviewUpConfig{
		Knob:      PreviewKnob{Domain: "preview.gdam.dev", TTL: PreviewTTLDefault, Max: 5, MemLimit: "512m", CPULimit: "0.75", AskPort: 8487, PortRange: "20000-20010"},
		Root:      root,
		RoutesDir: filepath.Join(root, "routes"),
		Proxy:     "komizo-proxy",
		Network:   "edge",
	}
	if err := os.MkdirAll(cfg.RoutesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func writeTestPreview(t *testing.T, cfg PreviewUpConfig, app string, pr int, lastUsed time.Time) PreviewRecord {
	t.Helper()
	rec := PreviewRecord{
		V: 1, App: app, PR: pr, Project: PreviewProject(app, pr),
		DBName: PreviewDBName(app, pr), GatePort: 20000 + pr,
		Images: []string{"ghcr.io/you/web:pr"}, CreatedAt: lastUsed, LastUsed: lastUsed,
		RouteFile: "_preview-" + PreviewProject(app, pr) + ".caddy",
	}
	if err := writePreviewRecord(cfg.Root, rec); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfg.RoutesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(previewDir(cfg.Root, rec.Project), "compose.yml"), []byte("services: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return rec
}

// ISOLATION, database side: up creates exactly one database, named for the
// app and the PR, inside the app's postgres container -- and nothing else is
// created, dropped or named. Never a shared schema, never prod data.
func TestPreviewUpCreatesOnlyItsOwnDatabase(t *testing.T) {
	f := &fakeDocker{}
	cfg := previewTestConfig(t)
	rec, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12, []string{"ghcr.io/you/web:pr-12"}, previewNow)
	if err != nil {
		t.Fatal(err)
	}
	if rec.DBName != "gdam_pr_12" {
		t.Fatalf("db name %q is not the preview-derived one", rec.DBName)
	}
	created := f.matching("psql", "CREATE DATABASE")
	if len(created) != 1 || !strings.Contains(strings.Join(created[0], " "), "CREATE DATABASE gdam_pr_12") {
		t.Fatalf("the create-database call is not exactly the preview's own: %v", created)
	}
	for _, c := range f.calls {
		j := strings.Join(c, " ")
		if strings.Contains(j, "DROP DATABASE") || strings.Contains(j, "gdam_production") || strings.Contains(j, "ALTER ") {
			t.Fatalf("a statement reached for something that is not the preview's database: %v", c)
		}
	}
}

// And down drops exactly that database and nothing else.
func TestPreviewDownDropsOnlyItsOwnDatabase(t *testing.T) {
	f := &fakeDocker{}
	cfg := previewTestConfig(t)
	rec := writeTestPreview(t, cfg, "gdam", 12, previewNow.Add(-time.Hour))
	if err := os.MkdirAll(cfg.RoutesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.RoutesDir, rec.RouteFile), []byte("route\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := PreviewDown(context.Background(), f.run, cfg, rec); err != nil {
		t.Fatal(err)
	}
	dropped := f.matching("psql", "DROP DATABASE")
	if len(dropped) != 1 || !strings.Contains(strings.Join(dropped[0], " "), "DROP DATABASE IF EXISTS gdam_pr_12") {
		t.Fatalf("the drop call is not exactly the preview's own: %v", dropped)
	}
	if _, err := os.Stat(previewDir(cfg.Root, rec.Project)); !os.IsNotExist(err) {
		t.Error("the preview's state directory survived down")
	}
}

// ROUTE DISCIPLINE: write, validate in the proxy, reload -- and on a failed
// validation the previous file set is restored and no reload happens.
func TestPreviewRouteDiscipline(t *testing.T) {
	t.Run("write validate reload in order", func(t *testing.T) {
		f := &fakeDocker{}
		dir := t.TempDir()
		if err := ApplyPreviewRoute(context.Background(), f.run, "komizo-proxy", dir, "_preview-x.caddy", "route\n"); err != nil {
			t.Fatal(err)
		}
		var order []string
		for _, c := range f.calls {
			order = append(order, c[3])
		}
		if len(order) != 2 || order[0] != "validate" || order[1] != "reload" {
			t.Fatalf("validate-then-reload order = %v", order)
		}
		if got, _ := os.ReadFile(filepath.Join(dir, "_preview-x.caddy")); string(got) != "route\n" {
			t.Fatalf("the route file is not what was written: %q", got)
		}
	})

	t.Run("a failed validation restores and never reloads", func(t *testing.T) {
		f := &fakeDocker{validateErr: fmt.Errorf("on-demand TLS cannot be enabled without a permission module")}
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "_preview-x.caddy"), []byte("previous\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		err := ApplyPreviewRoute(context.Background(), f.run, "komizo-proxy", dir, "_preview-x.caddy", "broken\n")
		if err == nil {
			t.Fatal("a broken combined config was applied")
		}
		if got, _ := os.ReadFile(filepath.Join(dir, "_preview-x.caddy")); string(got) != "previous\n" {
			t.Fatalf("the previous route was not restored: %q", got)
		}
		for _, c := range f.calls {
			if len(c) > 3 && c[3] == "reload" {
				t.Fatal("the proxy reloaded a config that failed validation")
			}
		}
	})

	t.Run("removal has the same discipline", func(t *testing.T) {
		f := &fakeDocker{validateErr: fmt.Errorf("broken")}
		dir := t.TempDir()
		path := filepath.Join(dir, "_preview-x.caddy")
		if err := os.WriteFile(path, []byte("route\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		err := RemovePreviewRoute(context.Background(), f.run, "komizo-proxy", dir, "_preview-x.caddy")
		if err == nil {
			t.Fatal("a broken post-removal config was accepted")
		}
		if got, _ := os.ReadFile(path); string(got) != "route\n" {
			t.Fatalf("the removed route was not restored: %q", got)
		}
	})
}

// TLS-ASK SCOPING: the gate approves pr-<N> and pr-<N>-api under the preview
// domain, and refuses everything else -- apex, other subdomains, other
// domains, lookalikes.
func TestPreviewAskAllow(t *testing.T) {
	const domain = "preview.gdam.dev"
	for host, want := range map[string]bool{
		"pr-1.preview.gdam.dev":          true,
		"pr-123.preview.gdam.dev":        true,
		"pr-12-api.preview.gdam.dev":     true,
		"PR-12.preview.gdam.dev":         true,  // hostnames are case-insensitive
		"preview.gdam.dev":               false, // the apex is not a preview
		"www.preview.gdam.dev":           false,
		"pr-x.preview.gdam.dev":          false, // not a number
		"pr-1-x.preview.gdam.dev":        false,
		"pr-1-dev.preview.gdam.dev":      false,
		"gdam.dev":                       false,
		"app.gdam.dev":                   false,
		"pr-1.preview.gdam.dev.evil.com": false,
		"pr-1.preview.gdam.devv":         false,
		"":                               false,
	} {
		if got := PreviewAskAllow(host, domain); got != want {
			t.Errorf("PreviewAskAllow(%q) = %v, want %v", host, got, want)
		}
	}
	if PreviewAskAllow("pr-1.preview.gdam.dev", "") {
		t.Error("an empty domain approved a hostname")
	}
}

// THE REAPER'S REFUSAL: gc acts only on previews it has state records for,
// and every docker call it makes is derived from those records -- no app
// project comes down, no app route is removed, nothing without a record is
// touched.
func TestTheReaperNeverTouchesNonPreviewResources(t *testing.T) {
	f := &fakeDocker{}
	cfg := previewTestConfig(t)
	expired := writeTestPreview(t, cfg, "gdam", 7, previewNow.Add(-100*time.Hour))
	live := writeTestPreview(t, cfg, "gdam", 8, previewNow.Add(-time.Hour))
	reap, err := PreviewGC(context.Background(), f.run, cfg, previewNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(reap.Reaped) != 1 || reap.Reaped[0] != expired.Project || reap.Kept != 1 {
		t.Fatalf("reap = %+v, want only the expired preview reaped", reap)
	}
	for _, c := range f.calls {
		j := strings.Join(c, " ")
		// The ONLY compose-down allowed is the expired preview's project.
		if strings.Contains(j, "compose") && strings.Contains(j, "down") && !strings.Contains(j, expired.Project) {
			t.Fatalf("the reaper took down something that is not the expired preview: %v", c)
		}
		if strings.Contains(j, live.Project) && strings.Contains(j, "down") {
			t.Fatalf("the reaper took down a live preview: %v", c)
		}
		if strings.Contains(j, "image rm") || strings.Contains(j, "volume") || strings.Contains(j, "container rm") {
			t.Fatalf("the reaper reached beyond previews: %v", c)
		}
	}
	if _, err := os.Stat(previewDir(cfg.Root, live.Project)); err != nil {
		t.Error("the live preview's state was reaped")
	}
}

// Max-N is a ceiling: over it, the least-recently-used goes, one at a time.
func TestPreviewGCEvictsLeastRecentlyUsedOverTheCeiling(t *testing.T) {
	f := &fakeDocker{}
	cfg := previewTestConfig(t)
	cfg.Knob.Max = 2
	writeTestPreview(t, cfg, "gdam", 1, previewNow.Add(-3*time.Hour))
	writeTestPreview(t, cfg, "gdam", 2, previewNow.Add(-2*time.Hour))
	writeTestPreview(t, cfg, "gdam", 3, previewNow.Add(-time.Hour))
	reap, err := PreviewGC(context.Background(), f.run, cfg, previewNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(reap.Reaped) != 1 || reap.Reaped[0] != "gdam-pr-1" || reap.Kept != 2 {
		t.Fatalf("reap = %+v, want the oldest evicted and two kept", reap)
	}
}

// A quiet pass says so.
func TestPreviewGCQuietWhenNothingToReap(t *testing.T) {
	f := &fakeDocker{}
	cfg := previewTestConfig(t)
	writeTestPreview(t, cfg, "gdam", 1, previewNow.Add(-time.Hour))
	reap, err := PreviewGC(context.Background(), f.run, cfg, previewNow)
	if err != nil {
		t.Fatal(err)
	}
	if reap.Note != "nothing to reap" || len(reap.Reaped) != 0 || reap.Kept != 1 {
		t.Errorf("reap = %+v, want the quiet line", reap)
	}
	if len(f.matching("compose")) != 0 {
		t.Errorf("a quiet reap touched docker: %v", f.calls)
	}
}

// FLOORS INTERPLAY: below the floor, up refuses cleanly -- no database, no
// compose, no route.
func TestPreviewUpRefusesBelowTheFloor(t *testing.T) {
	f := &fakeDocker{}
	cfg := previewTestConfig(t)
	cfg.FloorsBody = "DISK_AVAILABLE_FLOOR_BYTES=2147483648\nMEM_AVAILABLE_FLOOR_BYTES=524288000\n"
	cfg.ReportJSON = []byte(`{"system":{"mem":{"available":100},"disks":[{"available":100}]}}`)
	_, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12, []string{"ghcr.io/you/web:pr-12"}, previewNow)
	if err == nil || !strings.Contains(err.Error(), "capacity floors") {
		t.Fatalf("up below the floor = %v, want a floors refusal", err)
	}
	if len(f.calls) != 0 {
		t.Errorf("a refused up touched docker: %v", f.calls)
	}
}

// Above the floor but below twice it, up proceeds -- the warning is the
// deploy wrapper's job to print; the check must not refuse.
func TestPreviewUpProceedsBelowTwiceTheFloor(t *testing.T) {
	f := &fakeDocker{}
	cfg := previewTestConfig(t)
	cfg.FloorsBody = "MEM_AVAILABLE_FLOOR_BYTES=100\n"
	cfg.ReportJSON = []byte(`{"system":{"mem":{"available":150},"disks":[{"available":150}]}}`)
	if _, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12, []string{"ghcr.io/you/web:pr-12"}, previewNow); err != nil {
		t.Fatalf("up inside the warning band = %v, want it to proceed", err)
	}
}

// Max-N on the way IN: at the ceiling, the least-recently-used preview is
// evicted before the new one arrives.
func TestPreviewUpEvictsLeastRecentlyUsedAtTheCeiling(t *testing.T) {
	f := &fakeDocker{}
	cfg := previewTestConfig(t)
	cfg.Knob.Max = 1
	old := writeTestPreview(t, cfg, "gdam", 1, previewNow.Add(-time.Hour))
	if err := os.MkdirAll(cfg.RoutesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.RoutesDir, old.RouteFile), []byte("route\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 2, []string{"ghcr.io/you/web:pr-2"}, previewNow); err != nil {
		t.Fatal(err)
	}
	if len(f.matching("compose", "-p", "gdam-pr-1", "down")) != 1 {
		t.Errorf("the oldest preview was not evicted: %v", f.calls)
	}
	if _, err := os.Stat(previewDir(cfg.Root, "gdam-pr-2")); err != nil {
		t.Error("the new preview was not created")
	}
}

// The compose file: every service capped, the gate on both networks, the rest
// on the app's network only, the preview's database named in the environment.
func TestPreviewComposeCapsNetworksAndEnvironment(t *testing.T) {
	cfg := previewTestConfig(t)
	rec := PreviewRecord{
		V: 1, App: "gdam", PR: 12, Project: "gdam-pr-12", DBName: "gdam_pr_12",
		Images: []string{"ghcr.io/you/web:pr-12", "ghcr.io/you/api:pr-12"}, RouteFile: "_preview-gdam-pr-12.caddy",
	}
	compose := previewCompose(rec, cfg.Knob, "edge")
	for _, want := range []string{
		"mem_limit: 512m", "cpus: 0.75",
		"container_name: gdam-pr-12-gate",
		"DB_NAME: gdam_pr_12", "PGDATABASE: gdam_pr_12",
		"BASE_URL: https://pr-12.preview.gdam.dev",
		"name: edge", "name: gdam_default",
	} {
		if !strings.Contains(compose, want) {
			t.Errorf("compose is missing %q:\n%s", want, compose)
		}
	}
}

// The route file: both hostnames, to the gate, and nothing else.
func TestPreviewRouteContent(t *testing.T) {
	cfg := previewTestConfig(t)
	rec := PreviewRecord{V: 1, App: "gdam", PR: 12, Project: "gdam-pr-12", RouteFile: "_preview-gdam-pr-12.caddy"}
	route := previewRoute(rec, cfg.Knob)
	if !strings.Contains(route, "pr-12.preview.gdam.dev, pr-12-api.preview.gdam.dev {") {
		t.Errorf("route is missing the hostnames:\n%s", route)
	}
	if !strings.Contains(route, "reverse_proxy gdam-pr-12-gate:80") {
		t.Errorf("route is missing the upstream:\n%s", route)
	}
}

// Names are the whole isolation story: the derivations, and what is refused.
func TestPreviewNamesAndRefusals(t *testing.T) {
	if got := PreviewDBName("gdam-be", 3); got != "gdam_be_pr_3" {
		t.Errorf("PreviewDBName hyphen handling = %q", got)
	}
	for _, bad := range []struct {
		app string
		pr  int
	}{
		{"Gdam", 1}, {"gd am", 1}, {"gdam", 0}, {"gdam", -3}, {"", 1},
	} {
		if err := validatePreviewArgs(bad.app, bad.pr); err == nil {
			t.Errorf("validatePreviewArgs(%q, %d) passed", bad.app, bad.pr)
		}
	}
	if err := validatePreviewArgs("gdam", 12); err != nil {
		t.Errorf("validatePreviewArgs(gdam, 12) = %v", err)
	}
}

// The record round-trips, and ListPreviews is oldest-last-use first.
func TestPreviewRecordRoundTripAndOrdering(t *testing.T) {
	cfg := previewTestConfig(t)
	writeTestPreview(t, cfg, "gdam", 1, previewNow.Add(-time.Hour))
	writeTestPreview(t, cfg, "gdam", 2, previewNow.Add(-3*time.Hour))
	writeTestPreview(t, cfg, "gdam", 3, previewNow.Add(-2*time.Hour))
	got, err := ListPreviews(cfg.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].PR != 2 || got[1].PR != 3 || got[2].PR != 1 {
		t.Fatalf("ListPreviews order = %v, want oldest-last-use first", got)
	}
}

// The knob: defaults, written values, non-numeric values named in the note.
func TestPreviewKnob(t *testing.T) {
	knob, note := ParsePreviewKnob("")
	if knob.Domain != PreviewDomainDefault || knob.TTL != PreviewTTLDefault || knob.Max != PreviewMaxDefault || note != "" {
		t.Errorf("empty knob = %+v, %q, want pure defaults", knob, note)
	}
	knob, note = ParsePreviewKnob("TTL_HOURS=48\nMAX_PREVIEWS=2\nDOMAIN=preview.other.dev\n")
	if knob.TTL != 48*time.Hour || knob.Max != 2 || knob.Domain != "preview.other.dev" || note != "" {
		t.Errorf("written knob = %+v, %q", knob, note)
	}
	knob, note = ParsePreviewKnob("TTL_HOURS=soon\n")
	if knob.TTL != PreviewTTLDefault || !strings.Contains(note, "soon") {
		t.Errorf("non-numeric knob = %+v, %q, want the default and the note naming the value", knob, note)
	}
}
