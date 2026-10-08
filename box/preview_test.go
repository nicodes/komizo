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

// The preview contract, pinned as tests. A preview is a GUEST: it gets its
// own project, database, route and ports, and it may never touch production
// data, another preview's things, or the proxy's other routes. The gates for
// the whole program live here.

var previewNow = time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)

// fakeDocker records argv and answers the handful of calls a lifecycle makes.
type fakeDocker struct {
	calls          [][]string
	stdins         []string // parallel to calls: what each call was fed on stdin
	validateErr    error
	psqlErr        error
	composeUpErr   error
	psOut          string            // what ps answers (default: a tagged postgres)
	inspectAnswers map[string]string // Config.Image per container name
	envAnswers     map[string]string // Config.Env per container name
	netAnswers     map[string]string // NetworkSettings.Networks names per container name
	previewDBDown  bool              // komizo's own preview postgres is not running
}

func (f *fakeDocker) run(_ context.Context, stdin string, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{}, args...))
	f.stdins = append(f.stdins, stdin)
	switch args[0] {
	case "ps":
		if f.psOut != "" {
			return f.psOut, nil
		}
		return "gdam-db-1\tpostgres:16\n", nil
	case "compose":
		if args[len(args)-1] == "-d" && f.composeUpErr != nil {
			return "", f.composeUpErr
		}
		return "", nil
	case "inspect":
		format := ""
		if len(args) > 3 {
			format = args[3]
		}
		if strings.Contains(format, "Config.Env") {
			if f.envAnswers != nil {
				return f.envAnswers[args[1]], nil
			}
			return "", nil
		}
		if strings.Contains(format, "State.Running") {
			if args[1] == PreviewDBContainer && f.previewDBDown {
				return "false", nil
			}
			return "true", nil
		}
		if strings.Contains(format, "NetworkSettings") {
			if f.netAnswers != nil {
				return f.netAnswers[args[1]], nil
			}
			return "gdam_default\n", nil // on appnet only; dedupes away in the render
		}
		if f.inspectAnswers != nil {
			return f.inspectAnswers[args[1]], nil
		}
		return "", nil
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
	for i, c := range f.calls {
		j := strings.Join(c, " ")
		ok := true
		for _, w := range want {
			if !strings.Contains(j, w) {
				ok = false
			}
		}
		if ok {
			out = append(out, append(c, "\x00"+f.stdins[i]))
		}
	}
	return out
}

// stdinOf returns the stdin recorded for the i-th call matching the wants,
// or fails the test when there is not exactly one.
func (f *fakeDocker) stdinOf(t *testing.T, want ...string) string {
	t.Helper()
	var found []string
	for i, c := range f.calls {
		j := strings.Join(c, " ")
		ok := true
		for _, w := range want {
			if !strings.Contains(j, w) {
				ok = false
			}
		}
		if ok {
			found = append(found, f.stdins[i])
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected exactly one call matching %v, found %d (%v)", want, len(found), f.calls)
	}
	return found[0]
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
		Images: []string{"ghcr.io/you/web:pr", "ghcr.io/you/api:pr"}, CreatedAt: lastUsed, LastUsed: lastUsed,
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
// app and the PR, inside KOMIZO'S OWN postgres server -- and nothing else is
// created, dropped or named. Never a shared schema, never prod data.
func TestPreviewUpCreatesOnlyItsOwnDatabase(t *testing.T) {
	f := &fakeDocker{}
	cfg := previewTestConfig(t)
	rec, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12, []string{"ghcr.io/you/web:pr-12", "ghcr.io/you/api:pr-12"}, previewNow)
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
		// Up drops its OWN leftovers before creating them (see the reclaim
		// in PreviewUp); any other name in a DROP is the bug this guards.
		if strings.Contains(j, "DROP DATABASE") && !strings.Contains(j, "DROP DATABASE IF EXISTS gdam_pr_12 ") {
			t.Fatalf("a drop named something that is not the preview's database: %v", c)
		}
		if strings.Contains(j, "gdam_production") || strings.Contains(j, "ALTER ") {
			t.Fatalf("a statement reached for something that is not the preview's database: %v", c)
		}
	}
}

// Re-running up must work. A preview's database and role are named for its
// own app and PR, so an earlier attempt that died after creating them left
// litter that belongs to nobody else -- and up used to refuse on it forever
// ("database gdam_pr_158 already exists"), which no re-run and no operator
// acting through CI could clear.
func TestPreviewUpReclaimsItsOwnLeftovers(t *testing.T) {
	f := &fakeDocker{}
	cfg := previewTestConfig(t)
	if _, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12, []string{"ghcr.io/you/web:pr-12", "ghcr.io/you/api:pr-12"}, previewNow); err != nil {
		t.Fatal(err)
	}
	dropped, created, droppedRole := -1, -1, -1
	for i, c := range f.calls {
		j := strings.Join(c, " ") + "\x00" + f.stdins[i]
		switch {
		case strings.Contains(j, "DROP DATABASE IF EXISTS gdam_pr_12 WITH (FORCE)"):
			dropped = i
		case strings.Contains(j, "DROP ROLE IF EXISTS gdam_pr_12;"):
			droppedRole = i
		case strings.Contains(j, "CREATE DATABASE gdam_pr_12"):
			created = i
		}
	}
	if dropped < 0 {
		t.Fatalf("up did not reclaim a possible leftover database: %v", f.calls)
	}
	// FORCE matters: the state to clean up is the one with the failed
	// attempt's containers still holding sessions, which a plain drop
	// reports and walks away from.
	if droppedRole < 0 || droppedRole < dropped {
		t.Fatalf("the role must be dropped after its database, not before: drop=%d role=%d", dropped, droppedRole)
	}
	if created < 0 || created < droppedRole {
		t.Fatalf("the reclaim must precede the create: drop=%d role=%d create=%d", dropped, droppedRole, created)
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

// And the compose carries the connection: the preview's OWN role and
// password, so a preview can touch only its own database.
func TestPreviewComposeCarriesTheOwnerRole(t *testing.T) {
	cfg := previewTestConfig(t)
	rec := PreviewRecord{
		V: 1, App: "gdam", PR: 12, Project: "gdam-pr-12", DBName: "gdam_pr_12",
		DBPassword: "abc123", Images: []string{"ghcr.io/you/web:pr-12"}, RouteFile: "_preview-gdam-pr-12.caddy",
	}
	compose := previewCompose(rec, cfg.Knob, "edge", false, "")
	for _, want := range []string{"PGUSER: gdam_pr_12", "PGPASSWORD: abc123", "PGDATABASE: gdam_pr_12"} {
		if !strings.Contains(compose, want) {
			t.Errorf("compose is missing %q:\n%s", want, compose)
		}
	}
}

// Down drops the role too, against komizo's own server.
func TestPreviewDownDropsTheRole(t *testing.T) {
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
	dropStdin := f.stdinOf(t, "psql", "-i", "-U postgres", "-d postgres")
	if !strings.Contains(dropStdin, "DROP ROLE IF EXISTS gdam_pr_12;") {
		t.Errorf("the role drop did not reach psql via stdin: %q", dropStdin)
	}
	// The superuser is komizo's, in komizo's container. The app's postgres
	// is never named, connected to, or asked anything.
	for _, c := range f.calls {
		if c[0] == "exec" && strings.Contains(strings.Join(c, " "), "psql") && !contains(c, PreviewDBContainer) {
			t.Errorf("a drop ran somewhere other than komizo's server: %v", c)
		}
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// F1 (SECURITY): the owner role's password is a credential, and credentials
// are never marshalled -- `preview up` and `preview ls` print this record as
// JSON, and a credential on stdout is a credential in somebody's scrollback.
// The state file keeps it, 600 and root-owned, which is the only place it
// may exist.
func TestPreviewPasswordIsNeverMarshalledToStdout(t *testing.T) {
	rec := PreviewRecord{V: 1, App: "gdam", PR: 12, Project: "gdam-pr-12", DBName: "gdam_pr_12", DBPassword: "the-password-value"}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "the-password-value") {
		t.Errorf("the password was marshalled into the record's JSON: %s", b)
	}
	if strings.Contains(string(b), "db_password") {
		t.Errorf("the password's key was marshalled into the record's JSON: %s", b)
	}
}

// F2 (critical): up persists the state -- preview.env at the expected path,
// 600-root, with the recorded keys -- and ls reads it back. The box smoke
// found up writing NO state at all (a relative path when the root is the
// box's), which orphaned every resource it created.
func TestPreviewUpPersistsStateWhereDownCanFindIt(t *testing.T) {
	f := &fakeDocker{}
	cfg := previewTestConfig(t)
	rec, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12, []string{"ghcr.io/you/web:pr-12", "ghcr.io/you/api:pr-12"}, previewNow)
	if err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(previewDir(cfg.Root, "gdam-pr-12"), "preview.env")
	info, err := os.Stat(envPath)
	if err != nil {
		t.Fatalf("preview.env was not written at the expected path: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("preview.env is %v, not 0600", info.Mode().Perm())
	}
	body, _ := os.ReadFile(envPath)
	for _, want := range []string{"APP=gdam", "PR=12", "PROJECT=gdam-pr-12", "DB_NAME=gdam_pr_12",
		"DB_PASSWORD=" + rec.DBPassword, "ROUTE_FILE=_preview-gdam-pr-12.caddy"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("preview.env is missing %q:\n%s", want, body)
		}
	}
	// F3: ls reads the persisted state.
	listed, err := ListPreviews(cfg.Root)
	if err != nil || len(listed) != 1 || listed[0].DBPassword != rec.DBPassword {
		t.Fatalf("ListPreviews = %+v, %v -- the persisted preview is not readable back", listed, err)
	}
}

// F2, the other half: a failure after state is written rolls back BOTH the
// state and the created resources. No orphans, no ghost records.
func TestPreviewFailureRollsBackResourcesAndState(t *testing.T) {
	f := &fakeDocker{composeUpErr: fmt.Errorf("no such image")}
	cfg := previewTestConfig(t)
	_, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12, []string{"ghcr.io/you/web:pr-12", "ghcr.io/you/api:pr-12"}, previewNow)
	if err == nil {
		t.Fatal("a failed compose up succeeded")
	}
	if _, statErr := os.Stat(previewDir(cfg.Root, "gdam-pr-12")); !os.IsNotExist(statErr) {
		t.Error("the state directory survived a failed up")
	}
	if got := f.matching("psql", "DROP DATABASE IF EXISTS gdam_pr_12"); len(got) == 0 {
		t.Error("the rollback did not drop the database -- the failure is an orphan")
	}
	// The role drop travels on stdin (psql's :'var' path), not in argv.
	var droppedRole bool
	for i, c := range f.calls {
		if strings.Contains(strings.Join(c, " "), "psql") && strings.Contains(f.stdins[i], "DROP ROLE IF EXISTS gdam_pr_12") {
			droppedRole = true
		}
	}
	if !droppedRole {
		t.Error("the rollback did not drop the role -- the failure is an orphan")
	}
	if got := f.matching("compose", "-p", "gdam-pr-12", "down"); len(got) == 0 {
		t.Error("the rollback did not take the project down")
	}
	if listed, _ := ListPreviews(cfg.Root); len(listed) != 0 {
		t.Errorf("a ghost record survived the rollback: %+v", listed)
	}
}

// F4 (design): the gate port answers, on loopback ONLY -- the direct HTTP
// entry from the box itself, never from the network. The public way in is
// the proxy route, with TLS.
func TestPreviewComposePublishesTheGatePortOnLoopbackOnly(t *testing.T) {
	cfg := previewTestConfig(t)
	rec := PreviewRecord{
		V: 1, App: "gdam", PR: 12, Project: "gdam-pr-12", DBName: "gdam_pr_12",
		DBPassword: "abc123", GatePort: 20005,
		Images: []string{"ghcr.io/you/web:pr-12"}, RouteFile: "_preview-gdam-pr-12.caddy",
	}
	compose := previewCompose(rec, cfg.Knob, "edge", false, "")
	if !strings.Contains(compose, `"127.0.0.1:20005:80"`) {
		t.Errorf("the gate port is not published on loopback:\n%s", compose)
	}
	if strings.Contains(compose, `"20005:80"`) {
		t.Errorf("the gate port is published on every interface:\n%s", compose)
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
	_, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12, []string{"ghcr.io/you/web:pr-12", "ghcr.io/you/api:pr-12"}, previewNow)
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
	if _, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12, []string{"ghcr.io/you/web:pr-12", "ghcr.io/you/api:pr-12"}, previewNow); err != nil {
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

// The compose file: every service capped, every service on the shared
// network and nothing else, the preview's database named in the environment.
func TestPreviewComposeCapsNetworksAndEnvironment(t *testing.T) {
	cfg := previewTestConfig(t)
	rec := PreviewRecord{
		V: 1, App: "gdam", PR: 12, Project: "gdam-pr-12", DBName: "gdam_pr_12",
		Images: []string{"ghcr.io/you/web:pr-12", "ghcr.io/you/api:pr-12"}, RouteFile: "_preview-gdam-pr-12.caddy",
	}
	compose := previewCompose(rec, cfg.Knob, "edge", false, "")
	for _, want := range []string{
		"mem_limit: 512m", "cpus: 0.75",
		"container_name: gdam-pr-12-gate",
		"DB_NAME: gdam_pr_12", "PGDATABASE: gdam_pr_12",
		"BASE_URL: https://pr-12.preview.gdam.dev",
		"name: edge",
	} {
		if !strings.Contains(compose, want) {
			t.Errorf("compose is missing %q:\n%s", want, compose)
		}
	}
	if strings.Contains(compose, "gdam_default") || strings.Contains(compose, "appnet") {
		t.Errorf("the preview joined the app's production network:\n%s", compose)
	}
}

// The route file: both hostnames, to the gate, and nothing else.
func TestPreviewRouteContent(t *testing.T) {
	cfg := previewTestConfig(t)
	rec := PreviewRecord{V: 1, App: "gdam", PR: 12, Project: "gdam-pr-12", RouteFile: "_preview-gdam-pr-12.caddy", Images: []string{"gate:pr-12", "api:pr-12"}}
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

// --- per-app preview domains -----------------------------------------------------

// KNOB PARSE + RESOLUTION CHAIN, byte-exact with the composite's mirror:
// get("DOMAIN."+app) → get("DOMAIN") → PreviewDomainDefault, using the
// existing get() (CutPrefix key+"=", Trim `\r \t` only, first-match-wins,
// empty-value falls through). Quotes are NOT stripped. Unknown app is
// never an error.
func TestPreviewKnobPerAppDomainChain(t *testing.T) {
	knob, note := ParsePreviewKnob("DOMAIN=preview.gdam.dev\nDOMAIN.avior=preview.avior.studio\nDOMAIN.biome=preview.biome.example\nTTL_HOURS=48\n")
	if note != "" {
		t.Errorf("a clean per-app knob was noted: %q", note)
	}
	if knob.Domain != "preview.gdam.dev" {
		t.Errorf("bare DOMAIN = %q, want the default", knob.Domain)
	}
	if got := knob.DomainFor("avior"); got != "preview.avior.studio" {
		t.Errorf("DomainFor(avior) = %q", got)
	}
	if got := knob.DomainFor("biome"); got != "preview.biome.example" {
		t.Errorf("DomainFor(biome) = %q", got)
	}
	if knob.TTL != 48*time.Hour {
		t.Errorf("an unrelated key was disturbed: TTL = %v", knob.TTL)
	}

	// Unknown app → default, never a refusal.
	if got := knob.DomainFor("never-heard-of-it"); got != "preview.gdam.dev" {
		t.Errorf("DomainFor(unknown) = %q, want the default", got)
	}

	// Empty DOMAIN.<app>= falls through to bare DOMAIN.
	emptyApp, _ := ParsePreviewKnob("DOMAIN=preview.gdam.dev\nDOMAIN.avior=\n")
	if got := emptyApp.DomainFor("avior"); got != "preview.gdam.dev" {
		t.Errorf("empty DOMAIN.avior= = %q, want the bare DOMAIN", got)
	}

	// Empty bare DOMAIN= falls through to the compiled default.
	emptyBare, _ := ParsePreviewKnob("DOMAIN=\n")
	if emptyBare.Domain != PreviewDomainDefault || emptyBare.DomainFor("gdam") != PreviewDomainDefault {
		t.Errorf("empty DOMAIN= = Domain %q DomainFor %q, want %q", emptyBare.Domain, emptyBare.DomainFor("gdam"), PreviewDomainDefault)
	}

	// First-wins on both keys.
	firstApp, _ := ParsePreviewKnob("DOMAIN.avior=first.example\nDOMAIN.avior=second.example\nDOMAIN=preview.gdam.dev\n")
	if got := firstApp.DomainFor("avior"); got != "first.example" {
		t.Errorf("first-wins DOMAIN.avior = %q, want first.example", got)
	}
	firstBare, _ := ParsePreviewKnob("DOMAIN=first.example\nDOMAIN=second.example\n")
	if firstBare.Domain != "first.example" || firstBare.DomainFor("gdam") != "first.example" {
		t.Errorf("first-wins DOMAIN = Domain %q DomainFor %q, want first.example", firstBare.Domain, firstBare.DomainFor("gdam"))
	}

	// Unquoted value used verbatim -- quotes are NOT stripped.
	quoted, _ := ParsePreviewKnob("DOMAIN.avior=\"preview.avior.studio\"\nDOMAIN=preview.gdam.dev\n")
	if got := quoted.DomainFor("avior"); got != `"preview.avior.studio"` {
		t.Errorf("quoted value was stripped: %q", got)
	}
	verbatim, _ := ParsePreviewKnob("DOMAIN.avior=preview.avior.studio\n")
	if got := verbatim.DomainFor("avior"); got != "preview.avior.studio" {
		t.Errorf("unquoted value = %q", got)
	}

	// Case-sensitive keys; bare DOMAIN does not match DOMAIN.<app>.
	cased, _ := ParsePreviewKnob("DOMAIN.Avior=preview.AVIOR\nDOMAIN.avior=preview.avior.studio\nDOMAIN=preview.gdam.dev\n")
	if got := cased.DomainFor("avior"); got != "preview.avior.studio" {
		t.Errorf("DomainFor(avior) mixed-case = %q", got)
	}
	if got := cased.DomainFor("Avior"); got != "preview.AVIOR" {
		t.Errorf("DomainFor(Avior) mixed-case = %q", got)
	}

	// BACKWARD COMPAT: a knob with only a bare DOMAIN -- gdam's box today --
	// resolves every app to that domain, exactly as before.
	gdam, _ := ParsePreviewKnob("DOMAIN=preview.gdam.dev\n")
	if gdam.Domain != "preview.gdam.dev" || gdam.DomainFor("avior") != "preview.gdam.dev" || gdam.DomainFor("gdam") != "preview.gdam.dev" {
		t.Errorf("a bare-DOMAIN knob changed: Domain=%q avior=%q gdam=%q", gdam.Domain, gdam.DomainFor("avior"), gdam.DomainFor("gdam"))
	}
	if got := gdam.Domains(); len(got) != 1 || got[0] != "preview.gdam.dev" {
		t.Errorf("a bare-DOMAIN knob's ask union = %v, want exactly the default", got)
	}

	// The ask's union: the default first, the configured domains sorted.
	domains := knob.Domains()
	if len(domains) != 3 || domains[0] != "preview.gdam.dev" || domains[1] != "preview.avior.studio" || domains[2] != "preview.biome.example" {
		t.Errorf("Domains() = %v, want default first then sorted", domains)
	}
}

// ROUTE + COLLISION-FREE: the route names pr-<N> and pr-<N>-api under the
// APP'S domain, and two apps with different DOMAIN.<app> keys get different
// hosts for the same PR number.
func TestPreviewRouteUsesTheAppsOwnDomain(t *testing.T) {
	knob, _ := ParsePreviewKnob("DOMAIN=preview.gdam.dev\nDOMAIN.avior=preview.avior.studio\n")
	avior := previewRoute(PreviewRecord{V: 1, App: "avior", PR: 3, Project: "avior-pr-3", RouteFile: "_preview-avior-pr-3.caddy", Images: []string{"gate:pr-3", "api:pr-3"}}, knob)
	if !strings.Contains(avior, "pr-3.preview.avior.studio, pr-3-api.preview.avior.studio {") {
		t.Errorf("the route does not name the app's own domain:\n%s", avior)
	}
	gdam := previewRoute(PreviewRecord{V: 1, App: "gdam", PR: 3, Project: "gdam-pr-3", RouteFile: "_preview-gdam-pr-3.caddy", Images: []string{"gate:pr-3", "api:pr-3"}}, knob)
	if !strings.Contains(gdam, "pr-3.preview.gdam.dev, pr-3-api.preview.gdam.dev {") {
		t.Errorf("the default app's route changed:\n%s", gdam)
	}
	if strings.Contains(gdam, "avior.studio") || strings.Contains(avior, "gdam.dev") {
		t.Errorf("two apps' preview hosts collided for the same PR:\n%s\n%s", avior, gdam)
	}
}

// --- the stack.env seam --------------------------------------------------------

// STACK.ENV (a): absent, the render is exactly what it always was -- no
// env_file, no mention of stack.env anywhere in the compose.
func TestPreviewComposeWithoutStackEnvIsUnchanged(t *testing.T) {
	cfg := previewTestConfig(t)
	rec := PreviewRecord{
		V: 1, App: "gdam", PR: 12, Project: "gdam-pr-12", DBName: "gdam_pr_12",
		Images: []string{"ghcr.io/you/web:pr-12", "ghcr.io/you/api:pr-12"}, RouteFile: "_preview-gdam-pr-12.caddy",
	}
	compose := previewCompose(rec, cfg.Knob, "edge", false, "")
	if strings.Contains(compose, "env_file") || strings.Contains(compose, "stack.env") {
		t.Errorf("an absent stack.env changed the render:\n%s", compose)
	}
}

// STACK.ENV (b): present, the API services get `env_file: - stack.env` --
// RELATIVE, because compose resolves a relative env_file against the compose
// file's own directory (the preview's state directory, where both files
// live), so the reference survives a project-directory override -- and the
// gate does NOT: it keys off BASE_URL, already passed via environment:, and
// a product-writable file gets no say in the routed entrypoint.
func TestPreviewComposeEnvFilesStackEnvIntoAPIServicesOnly(t *testing.T) {
	cfg := previewTestConfig(t)
	rec := PreviewRecord{
		V: 1, App: "gdam", PR: 12, Project: "gdam-pr-12", DBName: "gdam_pr_12",
		Images:    []string{"ghcr.io/you/web:pr-12", "ghcr.io/you/api:pr-12", "ghcr.io/you/worker:pr-12"},
		RouteFile: "_preview-gdam-pr-12.caddy",
	}
	compose := previewCompose(rec, cfg.Knob, "edge", true, "")
	if n := strings.Count(compose, "    env_file:\n      - stack.env\n"); n != 2 {
		t.Errorf("env_file: - stack.env appears %d times, want exactly the 2 API services:\n%s", n, compose)
	}
	if strings.Contains(compose, "env_file: stack.env") || strings.Contains(compose, filepath.Join(cfg.Root, "previews")) {
		t.Errorf("the env_file is not the pinned RELATIVE form:\n%s", compose)
	}
	gate := compose[:strings.Index(compose, "  api:")]
	if strings.Contains(gate, "env_file") || strings.Contains(gate, "stack.env") {
		t.Errorf("the gate got the product-writable env_file:\n%s", gate)
	}
}

// STACK.ENV (a, lifecycle half): no stack.env on disk, up writes a compose
// with no env_file and the up path is unchanged.
func TestPreviewUpWithoutStackEnvRendersNoEnvFile(t *testing.T) {
	f := &fakeDocker{}
	cfg := previewTestConfig(t)
	if _, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12, []string{"ghcr.io/you/web:pr-12", "ghcr.io/you/api:pr-12"}, previewNow); err != nil {
		t.Fatal(err)
	}
	compose, err := os.ReadFile(filepath.Join(previewDir(cfg.Root, "gdam-pr-12"), "compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(compose), "env_file") || strings.Contains(string(compose), "stack.env") {
		t.Errorf("up without a stack.env rendered one:\n%s", compose)
	}
}

// STACK.ENV (c) and (d): the product pre-creates the state directory and
// writes stack.env (0600) BEFORE up; up must not fail on the pre-existing
// directory, must not clobber the file, and the file's CONTENTS -- a
// sentinel secret value -- must never appear in the compose, the JSON
// record up prints, or anything a docker call is told. Only the path
// reference is rendered.
func TestPreviewUpLeavesAPreExistingStackEnvUntouchedAndUnechoed(t *testing.T) {
	f := &fakeDocker{}
	cfg := previewTestConfig(t)
	dir := previewDir(cfg.Root, "gdam-pr-12")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	const sentinel = "SENTINEL-SECRET-VALUE-7f3a9c-never-echoed"
	stackBody := "SENTRY_DSN=" + sentinel + "\n"
	if err := os.WriteFile(filepath.Join(dir, "stack.env"), []byte(stackBody), 0o600); err != nil {
		t.Fatal(err)
	}
	rec, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12, []string{"ghcr.io/you/web:pr-12", "ghcr.io/you/api:pr-12"}, previewNow)
	if err != nil {
		t.Fatalf("up on a pre-created state directory failed: %v", err)
	}
	// (d) Unclobbered, byte for byte.
	got, err := os.ReadFile(filepath.Join(dir, "stack.env"))
	if err != nil {
		t.Fatal("up removed the pre-existing stack.env")
	}
	if string(got) != stackBody {
		t.Errorf("up clobbered stack.env: got %q, want %q", got, stackBody)
	}
	// The compose references the path...
	compose, err := os.ReadFile(filepath.Join(dir, "compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(compose), "    env_file:\n      - stack.env\n") {
		t.Errorf("the compose does not env_file the stack.env:\n%s", compose)
	}
	// (c) ...and the VALUE is nowhere: not in the compose, not in the JSON
	// record up prints, not in any docker argv or stdin.
	if strings.Contains(string(compose), sentinel) {
		t.Errorf("the sentinel value leaked into compose.yml:\n%s", compose)
	}
	printed, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(printed), sentinel) {
		t.Errorf("the sentinel value leaked into the up record's JSON: %s", printed)
	}
	for i, c := range f.calls {
		if strings.Contains(strings.Join(c, " ")+"\x00"+f.stdins[i], sentinel) {
			t.Errorf("the sentinel value leaked into a docker call: %v (stdin %q)", c, f.stdins[i])
		}
	}
}

// STACK.ENV (e): down removes the state directory, and stack.env goes with
// it -- the credential file does not outlive the preview.
func TestPreviewDownRemovesStackEnvWithTheStateDir(t *testing.T) {
	f := &fakeDocker{}
	cfg := previewTestConfig(t)
	rec := writeTestPreview(t, cfg, "gdam", 12, previewNow)
	dir := previewDir(cfg.Root, rec.Project)
	if err := os.WriteFile(filepath.Join(dir, "stack.env"), []byte("SENTRY_DSN=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PreviewDown(context.Background(), f.run, cfg, rec); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("the state directory (and its stack.env) survived down: %v", err)
	}
}

// --- the database reachability seam -------------------------------------------------

// RUNTIME_DATABASE_URL (1) and (3): the API services get the derived DSN --
// postgres://<role>:<pw>@komizo-previews:5432/<db>, role and db the
// preview's own -- because products fail-closed-require it and ignore the
// PG* vars (which stay). The DSN carries the DB password, a credential: it
// is NEVER on the gate (the gate routes HTTP, it does not touch the
// database) and never in the JSON record up prints.
func TestPreviewComposeRendersRuntimeDatabaseURLIntoAPIServicesOnly(t *testing.T) {
	cfg := previewTestConfig(t)
	rec := PreviewRecord{
		V: 1, App: "gdam", PR: 12, Project: "gdam-pr-12", DBName: "gdam_pr_12",
		DBPassword: "abc123",
		Images:     []string{"ghcr.io/you/web:pr-12", "ghcr.io/you/api:pr-12", "ghcr.io/you/worker:pr-12"},
		RouteFile:  "_preview-gdam-pr-12.caddy",
	}
	compose := previewCompose(rec, cfg.Knob, "edge", false, PreviewDBContainer)
	const dsn = "RUNTIME_DATABASE_URL: postgres://gdam_pr_12:abc123@komizo-previews:5432/gdam_pr_12"
	if n := strings.Count(compose, dsn); n != 2 {
		t.Errorf("the DSN appears %d times, want exactly the 2 API services:\n%s", n, compose)
	}
	gate := compose[:strings.Index(compose, "  api:")]
	if strings.Contains(gate, "RUNTIME_DATABASE_URL") || strings.Contains(gate, "postgres://") {
		t.Errorf("the DSN leaked onto the gate:\n%s", gate)
	}
	printed, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(printed), "postgres://") || strings.Contains(string(printed), "RUNTIME_DATABASE_URL") {
		t.Errorf("the DSN leaked into the up record's JSON: %s", printed)
	}
}

// NETWORKS: one network, the shared one, for every service -- and NEVER
// the app's <app>_default.
//
// Everything a preview must reach is on it: the proxy finds the gate, the
// gate finds the API, the API finds komizo's preview postgres. The app's
// own network was needed only while the preview's database lived inside the
// app's postgres container, and joining a product's production network to
// serve a pull request is the same invasiveness in a different costume.
//
// It was also a hard failure for any product that has no such network. A
// gate-only product's stack is one container on the shared network, so
// compose creates no <app>_default at all and every preview of one died at
// "network ctcalc_default declared as external, but could not be found" --
// which is how this was found, on the host, after the database half was
// already fixed.
func TestPreviewComposeJoinsTheSharedNetworkAndNothingElse(t *testing.T) {
	cfg := previewTestConfig(t)
	for _, tc := range []struct {
		name   string
		images []string
	}{
		{"api product", []string{"ghcr.io/you/web:pr-12", "ghcr.io/you/api:pr-12"}},
		{"gate only", []string{"ghcr.io/you/web:pr-12"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := PreviewRecord{
				V: 1, App: "gdam", PR: 12, Project: "gdam-pr-12", DBName: "gdam_pr_12",
				Images:    tc.images,
				RouteFile: "_preview-gdam-pr-12.caddy",
			}
			compose := previewCompose(rec, cfg.Knob, "edge", false, PreviewDBContainer)
			if n := strings.Count(compose, "    networks:\n      - shared\n"); n != len(tc.images) {
				t.Errorf("%d of %d services join shared alone:\n%s", n, len(tc.images), compose)
			}
			// Exactly one external network is declared. A second would mean
			// komizo went looking at the app's stack again.
			if n := strings.Count(compose, "external: true"); n != 1 {
				t.Errorf("%d external networks declared, want exactly shared:\n%s", n, compose)
			}
			for _, unwanted := range []string{"appnet", "gdam_default"} {
				if strings.Contains(compose, unwanted) {
					t.Errorf("the preview references %s:\n%s", unwanted, compose)
				}
			}
		})
	}
}

// A WRITABLE /tmp, for every service.
//
// The fleet's images are scratch or distroless and run as an unprivileged
// uid. Their production compose files all mount a tmpfs at /tmp; the
// preview mounted nothing, so the process saw the image's own /tmp --
// root-owned and 0755, because COPY of a directory copies its CONTENTS and
// creates the destination fresh with the default mode, so a Dockerfile's
// `chmod 1777` on the source never arrives in the image.
//
// cazper's preview API crash-looped on exactly that, and said only "the
// store is unreachable" -- its error mapper deliberately keeps filesystem
// paths out of logs, so the real cause (EACCES on MkdirAll) was invisible
// until the image was unpacked by hand.
//
// mode=1777 is named EXPLICITLY. Docker's default for a tmpfs is 1777
// only when the mountpoint does not say otherwise -- it inherits the mode
// of the directory in the image, so a scratch image whose /tmp is 0755
// root-owned gets a 0755 root-owned tmpfs and the unprivileged uid still
// cannot write. That is exactly what cazper's image has, and leaving the
// mode off did not fix its crash loop.
//
// A uid is still never named: 1777 is /tmp's own convention rather than a
// guess about which user the image runs as.
func TestPreviewComposeGivesEveryServiceAWritableTmp(t *testing.T) {
	cfg := previewTestConfig(t)
	rec := PreviewRecord{
		V: 1, App: "cazper", PR: 12, Project: "cazper-pr-12", DBName: "cazper_pr_12",
		Images:    []string{"ghcr.io/you/gate:pr-12", "ghcr.io/you/api:pr-12", "ghcr.io/you/worker:pr-12"},
		RouteFile: "_preview-cazper-pr-12.caddy",
	}
	compose := previewCompose(rec, cfg.Knob, "edge", false, PreviewDBContainer)
	if n := strings.Count(compose, "    tmpfs:\n      - /tmp:rw,noexec,nosuid,size=64m,mode=1777\n"); n != 3 {
		t.Errorf("%d of 3 services got a writable /tmp:\n%s", n, compose)
	}
	// The mode is not optional: without it the tmpfs inherits the image's
	// /tmp mode, which for a scratch image is 0755 root-owned.
	if !strings.Contains(compose, "mode=1777") {
		t.Errorf("the tmpfs does not force mode=1777:\n%s", compose)
	}
	// No uid pinned: a uid here would be a guess about the image.
	if strings.Contains(compose, "uid=") || strings.Contains(compose, "gid=") {
		t.Errorf("the tmpfs names a uid, which assumes the image's user:\n%s", compose)
	}
}

// A RE-UP KEEPS ITS OWN GATE PORT.
//
// Up runs on every push to the PR, and this preview's own record is in the
// list the allocator reads. Counting it as taken moved the preview to a new
// port on every push -- churn at best, and at worst the number it moved to
// was one another preview already held:
//
//	Bind for 127.0.0.1:20001 failed: port is already allocated
//
// which is what castledrop did when it and prizm deployed together.
func TestPreviewUpKeepsItsOwnGatePortAcrossReUps(t *testing.T) {
	cfg := previewTestConfig(t)
	f := &fakeDocker{}
	first, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12,
		[]string{"ghcr.io/you/web:pr-12"}, previewNow)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		again, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12,
			[]string{"ghcr.io/you/web:pr-12"}, previewNow)
		if err != nil {
			t.Fatal(err)
		}
		if again.GatePort != first.GatePort {
			t.Fatalf("re-up %d moved the gate port from %d to %d", i+1, first.GatePort, again.GatePort)
		}
	}
}

// And a DIFFERENT preview never gets a port one already holds.
func TestPreviewUpNeverReusesAnotherPreviewsGatePort(t *testing.T) {
	cfg := previewTestConfig(t)
	f := &fakeDocker{}
	seen := map[int]string{}
	for _, p := range []struct {
		app string
		pr  int
	}{{"gdam", 1}, {"termcade", 2}, {"castledrop", 3}, {"prizm", 4}} {
		rec, err := PreviewUp(context.Background(), f.run, cfg, p.app, p.pr,
			[]string{"ghcr.io/you/web:pr"}, previewNow)
		if err != nil {
			t.Fatal(err)
		}
		if other, clash := seen[rec.GatePort]; clash {
			t.Fatalf("%s got port %d, already held by %s", rec.Project, rec.GatePort, other)
		}
		seen[rec.GatePort] = rec.Project
	}
	// Re-upping the first must still not collide with the three after it.
	rec, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 1,
		[]string{"ghcr.io/you/web:pr"}, previewNow)
	if err != nil {
		t.Fatal(err)
	}
	if seen[rec.GatePort] != rec.Project {
		t.Errorf("a re-up took port %d, held by %s", rec.GatePort, seen[rec.GatePort])
	}
}

// ISOLATION BETWEEN PREVIEWS: every preview on a host now shares one
// server, so "its own database" has to be something postgres enforces
// rather than something komizo is careful about. A new database grants
// CONNECT to PUBLIC by default -- which here is every other preview's role
// -- so up revokes it and grants it back to the owner alone.
func TestPreviewUpRevokesPublicConnectOnItsDatabase(t *testing.T) {
	f := &fakeDocker{}
	cfg := previewTestConfig(t)
	rec, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12,
		[]string{"ghcr.io/you/web:pr-12", "ghcr.io/you/api:pr-12"}, previewNow)
	if err != nil {
		t.Fatal(err)
	}
	created, revoked := -1, -1
	for i := range f.calls {
		j := strings.Join(f.calls[i], " ") + "\x00" + f.stdins[i]
		if strings.Contains(j, "CREATE DATABASE "+rec.DBName) {
			created = i
		}
		if strings.Contains(j, "REVOKE CONNECT ON DATABASE "+rec.DBName+" FROM PUBLIC;") &&
			strings.Contains(j, "GRANT CONNECT ON DATABASE "+rec.DBName+" TO "+rec.DBName+";") {
			revoked = i
		}
	}
	if revoked < 0 {
		t.Fatalf("PUBLIC can still connect to this preview's database: %v", f.calls)
	}
	if created < 0 || revoked < created {
		t.Errorf("the revoke must follow the create: create=%d revoke=%d", created, revoked)
	}
}

// NON-INVASIVENESS, the whole point: a preview up never inspects, names or
// connects to anything belonging to the app. The app's project is not
// listed, its containers are not inspected, and every psql call goes to
// komizo's own server.
func TestPreviewUpNeverTouchesTheAppsOwnContainers(t *testing.T) {
	f := &fakeDocker{}
	cfg := previewTestConfig(t)
	if _, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12,
		[]string{"ghcr.io/you/web:pr-12", "ghcr.io/you/api:pr-12"}, previewNow); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		joined := strings.Join(c, " ")
		if c[0] == "ps" && strings.Contains(joined, "com.docker.compose.project=gdam") {
			t.Errorf("up listed the app's own project: %v", c)
		}
		if c[0] == "inspect" && c[1] == "gdam-db-1" {
			t.Errorf("up inspected the app's database container: %v", c)
		}
		if c[0] == "exec" && (c[2] == "psql" || c[2] == "pg_isready") && c[1] != PreviewDBContainer {
			t.Errorf("a database call went somewhere other than komizo's server: %v", c)
		}
	}
}

// A host whose komizo-previews server was never provisioned refuses with an
// instruction, rather than failing somewhere inside psql.
func TestPreviewUpRefusesWhenKomizosDatabaseServerIsMissing(t *testing.T) {
	f := &fakeDocker{previewDBDown: true}
	cfg := previewTestConfig(t)
	_, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12,
		[]string{"ghcr.io/you/web:pr-12", "ghcr.io/you/api:pr-12"}, previewNow)
	if err == nil {
		t.Fatal("a missing preview database server was accepted")
	}
	if !strings.Contains(err.Error(), PreviewDBContainer) || !strings.Contains(err.Error(), "komizo init") {
		t.Errorf("the refusal does not say what to do: %v", err)
	}
}

// GATE-ONLY products -- ctcalc, tonesplit, castledrop, prizm: one static
// container, no API, and therefore NO DATABASE AT ALL. No role, no
// database, no credentials in the compose file, and nothing for teardown to
// drop. This is the case the old design could not express: it refused with
// "no postgres container is running in ctcalc's project".
func TestPreviewUpCreatesNoDatabaseForAGateOnlyProduct(t *testing.T) {
	f := &fakeDocker{}
	cfg := previewTestConfig(t)
	rec, err := PreviewUp(context.Background(), f.run, cfg, "ctcalc", 7,
		[]string{"ghcr.io/you/gate:pr-7"}, previewNow)
	if err != nil {
		t.Fatalf("a gate-only preview was refused: %v", err)
	}
	if rec.DBName != "" || rec.DBPassword != "" {
		t.Errorf("a gate-only preview was given a database: %+v", rec)
	}
	for _, c := range f.calls {
		if c[0] == "exec" && len(c) > 2 && (c[2] == "psql" || c[2] == "pg_isready") {
			t.Errorf("a gate-only preview talked to postgres: %v", c)
		}
	}
	compose, err := os.ReadFile(filepath.Join(previewDir(cfg.Root, "ctcalc-pr-7"), "compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{"PGPASSWORD", "PGUSER", "DB_NAME", "RUNTIME_DATABASE_URL", "postgres://"} {
		if strings.Contains(string(compose), unwanted) {
			t.Errorf("a gate-only preview's compose mentions %s:\n%s", unwanted, string(compose))
		}
	}
	route, err := os.ReadFile(filepath.Join(cfg.RoutesDir, rec.RouteFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(route), "pr-7.preview.gdam.dev {") {
		t.Errorf("gate hostname missing: %s", route)
	}
	if strings.Contains(string(route), "-api.") {
		t.Errorf("static preview requested an unused API certificate: %s", route)
	}
	// Teardown has nothing to drop, and must not invent something.
	f.calls = nil
	if err := PreviewDown(context.Background(), f.run, cfg, rec); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if c[0] == "exec" && len(c) > 2 && c[2] == "psql" {
			t.Errorf("teardown dropped a database a gate-only preview never had: %v", c)
		}
	}
}

// Teardown drops the preview's role and database from KOMIZO'S server, and
// names nothing of the app's.
func TestPreviewDownDropsFromKomizosOwnServer(t *testing.T) {
	f := &fakeDocker{}
	cfg := previewTestConfig(t)
	rec, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12,
		[]string{"ghcr.io/you/web:pr-12", "ghcr.io/you/api:pr-12"}, previewNow)
	if err != nil {
		t.Fatal(err)
	}
	f.calls = nil
	if err := PreviewDown(context.Background(), f.run, cfg, rec); err != nil {
		t.Fatal(err)
	}
	var dropped bool
	for _, c := range f.calls {
		if c[0] == "exec" && len(c) > 2 && c[2] == "psql" {
			if c[1] != PreviewDBContainer {
				t.Errorf("teardown dropped against %s, not komizo's server: %v", c[1], c)
			}
			dropped = true
		}
	}
	if !dropped {
		t.Error("teardown never dropped the preview database")
	}
}
