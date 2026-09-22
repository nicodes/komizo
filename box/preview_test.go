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

// The discovery's three ways to know a postgres, pinned. Products pin
// postgres by digest, and docker ps's Image column for a digest-pulled image
// shows only the short digest -- no "postgres" substring -- so a discovery
// that reads only that column never sees it. Found by the preview smoke on
// avior.studio, whose gdam-postgres-1 runs postgres@sha256:....
func TestPreviewDiscoveryFindsDigestPulledPostgres(t *testing.T) {
	f := &fakeDocker{
		psOut:          "gdam-postgres-1\t4ef4dbc939d6b2a1c0f9e8d7c6b5a4\n",
		inspectAnswers: map[string]string{"gdam-postgres-1": "postgres@sha256:4ef4dbc939d6b2a1c0f9e8d7c6b5a4"},
	}
	cfg := previewTestConfig(t)
	if _, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12, []string{"ghcr.io/you/web:pr-12"}, previewNow); err != nil {
		t.Fatalf("a digest-pulled postgres was not discovered: %v", err)
	}
	created := f.matching("psql", "CREATE DATABASE gdam_pr_12")
	if len(created) != 1 || !strings.Contains(strings.Join(created[0], " "), "gdam-postgres-1") {
		t.Fatalf("the create did not run against the digest-pulled container: %v", created)
	}
}

// A non-postgres container is still not one, on every one of the three
// signals -- ps column, Config.Image, name.
func TestPreviewDiscoveryRefusesANonPostgresContainer(t *testing.T) {
	f := &fakeDocker{
		psOut:          "gdam-redis-1\tredis:7\n",
		inspectAnswers: map[string]string{"gdam-redis-1": "redis:7"},
	}
	cfg := previewTestConfig(t)
	_, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12, []string{"ghcr.io/you/web:pr-12"}, previewNow)
	if err == nil || !strings.Contains(err.Error(), "no postgres container") {
		t.Fatalf("a redis container was discovered as postgres: %v", err)
	}
	for _, c := range f.calls {
		if strings.Contains(strings.Join(c, " "), "psql") {
			t.Fatalf("psql ran against a container that is not postgres: %v", c)
		}
	}
}

// The common case stays cheap: a tagged postgres is discovered from the ps
// Image column alone, and no Config.Image is ever inspected. (The container
// environment read for POSTGRES_USER is a different question, asked of every
// container the creation runs against.)
func TestPreviewDiscoveryFastPathSkipsInspect(t *testing.T) {
	f := &fakeDocker{} // default ps answer is a tagged postgres
	cfg := previewTestConfig(t)
	if _, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12, []string{"ghcr.io/you/web:pr-12"}, previewNow); err != nil {
		t.Fatal(err)
	}
	if got := f.matching("inspect", "Config.Image"); len(got) != 0 {
		t.Errorf("the fast path inspected Config.Image anyway: %v", got)
	}
}

// And when neither image field says postgres, the container's own name is the
// last word -- compose's <project>-postgres-1 -- with the psql call after
// discovery as the final proof.
func TestPreviewDiscoveryFallsBackToTheContainerName(t *testing.T) {
	f := &fakeDocker{
		psOut:          "gdam-postgres-1\tcustom-sidecar:1\n",
		inspectAnswers: map[string]string{"gdam-postgres-1": "custom-sidecar:1"},
	}
	cfg := previewTestConfig(t)
	if _, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12, []string{"ghcr.io/you/web:pr-12"}, previewNow); err != nil {
		t.Fatalf("a postgres named by compose was not discovered: %v", err)
	}
	if got := f.matching("psql", "CREATE DATABASE gdam_pr_12"); len(got) != 1 {
		t.Errorf("the create did not run against the name-matched container: %v", got)
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

// The connecting role: a container with a custom POSTGRES_USER (and no
// 'postgres' role at all) is connected to as THAT, never as 'postgres' --
// the third integration gap the avior.studio smoke found, where
// gdam-postgres-1's superuser is gdam_migrator and no 'postgres' role exists.
func TestPreviewCreatesItsDatabaseAsTheContainersOwnSuperuser(t *testing.T) {
	f := &fakeDocker{envAnswers: map[string]string{
		"gdam-db-1": "POSTGRES_USER=gdam_migrator\nPOSTGRES_DB=gdam\n",
	}}
	cfg := previewTestConfig(t)
	rec, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12, []string{"ghcr.io/you/web:pr-12"}, previewNow)
	if err != nil {
		t.Fatal(err)
	}
	if rec.DBPassword == "" {
		t.Fatal("no owner-role password was generated and recorded")
	}
	for _, c := range f.calls {
		j := strings.Join(c, " ")
		if strings.Contains(j, "psql") && strings.Contains(j, "-U postgres") {
			t.Fatalf("connected as the hardcoded 'postgres' role, which does not exist here: %v", c)
		}
	}
	// The role statement reaches psql via STDIN (docker exec -i, no -c),
	// because psql substitutes :'var' on lines it reads from stdin and NOT on
	// -c arguments -- the fourth gap, verified on gdam-postgres-1 (psql 18.6).
	// The password travels as the 'pw' variable in argv and NEVER inside the
	// SQL text.
	roleStdin := f.stdinOf(t, "psql", "-i", "-U gdam_migrator", "-d gdam", "-v", "pw="+rec.DBPassword)
	if !strings.Contains(roleStdin, "CREATE ROLE gdam_pr_12 LOGIN PASSWORD :'pw';") {
		t.Errorf("the role statement did not reach psql via stdin with the variable intact: %q", roleStdin)
	}
	if strings.Contains(roleStdin, rec.DBPassword) {
		t.Errorf("the password was interpolated into the SQL text: %q", roleStdin)
	}
	for _, c := range f.calls {
		j := strings.Join(c, " ")
		if strings.Contains(j, "CREATE ROLE") && strings.Contains(j, "-c") {
			t.Errorf("the role statement went through -c, where :'pw' is not substituted: %v", c)
		}
	}
	dbCalls := f.matching("psql", "-U gdam_migrator", "CREATE DATABASE gdam_pr_12 OWNER gdam_pr_12")
	if len(dbCalls) != 1 {
		t.Fatalf("the database was not created as gdam_migrator with the owner set: %v", dbCalls)
	}
}

// The stock container still works: no POSTGRES_USER in its env, and the
// default 'postgres' role is what connects.
func TestPreviewCreatesItsDatabaseAsPostgresOnAStockContainer(t *testing.T) {
	f := &fakeDocker{envAnswers: map[string]string{"gdam-db-1": "OTHER_VAR=1\n"}}
	cfg := previewTestConfig(t)
	if _, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12, []string{"ghcr.io/you/web:pr-12"}, previewNow); err != nil {
		t.Fatal(err)
	}
	if got := f.matching("psql", "-U postgres", "CREATE DATABASE gdam_pr_12"); len(got) != 1 {
		t.Errorf("the stock container was not connected to as postgres: %v", got)
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
	compose := previewCompose(rec, cfg.Knob, "edge", false, "", nil)
	for _, want := range []string{"PGUSER: gdam_pr_12", "PGPASSWORD: abc123", "PGDATABASE: gdam_pr_12"} {
		if !strings.Contains(compose, want) {
			t.Errorf("compose is missing %q:\n%s", want, compose)
		}
	}
}

// Down drops the role too, with the same discovered connection.
func TestPreviewDownDropsTheRole(t *testing.T) {
	f := &fakeDocker{envAnswers: map[string]string{
		"gdam-db-1": "POSTGRES_USER=gdam_migrator\nPOSTGRES_DB=gdam\n",
	}}
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
	dropStdin := f.stdinOf(t, "psql", "-i", "-U gdam_migrator", "-d gdam")
	if !strings.Contains(dropStdin, "DROP ROLE IF EXISTS gdam_pr_12;") {
		t.Errorf("the role drop did not reach psql via stdin: %q", dropStdin)
	}
	for _, c := range f.calls {
		if strings.Contains(strings.Join(c, " "), "-U postgres") {
			t.Errorf("connected as the hardcoded 'postgres' role: %v", c)
		}
	}
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
	rec, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12, []string{"ghcr.io/you/web:pr-12"}, previewNow)
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
	_, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12, []string{"ghcr.io/you/web:pr-12"}, previewNow)
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
	compose := previewCompose(rec, cfg.Knob, "edge", false, "", nil)
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
	compose := previewCompose(rec, cfg.Knob, "edge", false, "", nil)
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

// --- the stack.env seam --------------------------------------------------------

// STACK.ENV (a): absent, the render is exactly what it always was -- no
// env_file, no mention of stack.env anywhere in the compose.
func TestPreviewComposeWithoutStackEnvIsUnchanged(t *testing.T) {
	cfg := previewTestConfig(t)
	rec := PreviewRecord{
		V: 1, App: "gdam", PR: 12, Project: "gdam-pr-12", DBName: "gdam_pr_12",
		Images: []string{"ghcr.io/you/web:pr-12", "ghcr.io/you/api:pr-12"}, RouteFile: "_preview-gdam-pr-12.caddy",
	}
	compose := previewCompose(rec, cfg.Knob, "edge", false, "", nil)
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
	compose := previewCompose(rec, cfg.Knob, "edge", true, "", nil)
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
// postgres://<role>:<pw>@<db-container-name>:5432/<db>, role and db the
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
	compose := previewCompose(rec, cfg.Knob, "edge", false, "gdam-db-1", []string{"gdam_database"})
	const dsn = "RUNTIME_DATABASE_URL: postgres://gdam_pr_12:abc123@gdam-db-1:5432/gdam_pr_12"
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

// DB NETWORKS (2): the API services join the DB container's networks IN
// ADDITION to appnet -- an app's postgres may live on a different network
// than <app>_default -- and the extra networks are declared external with
// their stable names. The gate's networks stay [shared, appnet], and the
// appnet network itself is never duplicated.
func TestPreviewComposeWiresTheAPIIntoTheDBNetworks(t *testing.T) {
	cfg := previewTestConfig(t)
	rec := PreviewRecord{
		V: 1, App: "gdam", PR: 12, Project: "gdam-pr-12", DBName: "gdam_pr_12",
		Images:    []string{"ghcr.io/you/web:pr-12", "ghcr.io/you/api:pr-12"},
		RouteFile: "_preview-gdam-pr-12.caddy",
	}
	compose := previewCompose(rec, cfg.Knob, "edge", false, "gdam-db-1", []string{"gdam_database", "gdam_default"})
	// gdam_default IS appnet -- discovered but already joined, so it is
	// never duplicated; gdam_database is the extra, joined and declared.
	api := compose[strings.Index(compose, "  api:"):strings.Index(compose, "\nnetworks:")]
	if !strings.Contains(api, "    networks:\n      - appnet\n      - gdam_database") {
		t.Errorf("the api service does not join appnet + the DB's network:\n%s", api)
	}
	if strings.Contains(api, "gdam_default") {
		t.Errorf("appnet's own network was duplicated onto the api service:\n%s", api)
	}
	if !strings.Contains(compose, "  gdam_database:\n    external: true\n    name: gdam_database\n") {
		t.Errorf("the DB's network is not declared external with its stable name:\n%s", compose)
	}
	gate := compose[:strings.Index(compose, "  api:")]
	if !strings.Contains(gate, "    networks:\n      - shared\n      - appnet\n") {
		t.Errorf("the gate's networks changed:\n%s", gate)
	}
	if strings.Contains(gate, "gdam_database") {
		t.Errorf("the gate joined the DB's network:\n%s", gate)
	}
}

// DISCOVERY (4), lifecycle: the DB container on a non-<app>_default network
// is discovered, its networks are read by inspect, and the api service is
// wired into them -- generic, nothing hardcoded to one app.
func TestPreviewUpWiresTheAPIIntoTheDiscoveredDBNetworks(t *testing.T) {
	f := &fakeDocker{
		envAnswers: map[string]string{"gdam-db-1": "POSTGRES_USER=gdam_migrator\nPOSTGRES_DB=gdam\n"},
		netAnswers: map[string]string{"gdam-db-1": "gdam_database\n"},
	}
	cfg := previewTestConfig(t)
	rec, err := PreviewUp(context.Background(), f.run, cfg, "gdam", 12, []string{"ghcr.io/you/web:pr-12", "ghcr.io/you/api:pr-12"}, previewNow)
	if err != nil {
		t.Fatal(err)
	}
	// The discovery asked the container for its networks.
	if got := f.matching("inspect", "gdam-db-1", "NetworkSettings.Networks"); len(got) != 1 {
		t.Fatalf("the DB container's networks were not discovered by inspect: %v", f.calls)
	}
	compose, err := os.ReadFile(filepath.Join(previewDir(cfg.Root, "gdam-pr-12"), "compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"      RUNTIME_DATABASE_URL: postgres://gdam_pr_12:" + rec.DBPassword + "@gdam-db-1:5432/gdam_pr_12\n",
		"    networks:\n      - appnet\n      - gdam_database\n",
		"  gdam_database:\n    external: true\n    name: gdam_database\n",
	} {
		if !strings.Contains(string(compose), want) {
			t.Errorf("the rendered compose is missing %q:\n%s", want, string(compose))
		}
	}
	// (3), the lifecycle half: the DSN went nowhere but the compose file --
	// no docker argv or stdin ever carried it.
	dsn := "postgres://gdam_pr_12:" + rec.DBPassword + "@gdam-db-1:5432/gdam_pr_12"
	for i, c := range f.calls {
		if strings.Contains(strings.Join(c, " ")+"\x00"+f.stdins[i], dsn) {
			t.Errorf("the DSN leaked into a docker call: %v (stdin %q)", c, f.stdins[i])
		}
	}
}

// DISCOVERY, the parsing: names are read one per line, sorted, blanks
// dropped; a container on no networks is an error, not a silent preview
// whose API can never reach its database.
func TestPreviewDBNetworksParsing(t *testing.T) {
	f := &fakeDocker{netAnswers: map[string]string{"db": "zeta\n\nalpha\n"}}
	nets, err := previewDBNetworks(context.Background(), f.run, "db")
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 2 || nets[0] != "alpha" || nets[1] != "zeta" {
		t.Errorf("networks = %v, want [alpha zeta]", nets)
	}
	empty := &fakeDocker{netAnswers: map[string]string{"db": "\n"}}
	if _, err := previewDBNetworks(context.Background(), empty.run, "db"); err == nil {
		t.Error("a container on no networks was accepted")
	}
}
