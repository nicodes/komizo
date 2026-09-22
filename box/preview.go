package box

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Ephemeral PR-preview environments -- the platform half.
//
// A preview is an ISOLATED compose project per pull request, its own
// containers, its own database, its own route, its own ports. Everything a
// preview owns is derived from exactly two values -- the app name and the PR
// number -- and nothing it owns is ever shared with production or with
// another preview. The derivations live here, once, so the up path, the down
// path, the reaper and the tests all mean the same names.
//
// What a preview may NEVER touch, stated here because the contract tests pin
// each one:
//
//	PROD DATA. The per-preview database lives inside the app's existing
//	postgres container, but it is a NEW database named for the PR, created on
//	up and dropped on down. No schema is shared, no production database is
//	read, written or named by any statement this file issues.
//
//	NON-PREVIEW RESOURCES. The reaper and the down path act only on previews
//	they have a state record for, in the previews directory -- never on an
//	app, a container, an image or a route they did not derive from that
//	record.
//
//	THE PROXY'S OTHER ROUTES. Route files are added and removed with the same
//	write-then-validate-then-reload discipline as every other route change:
//	the combined config is validated IN the proxy container before a reload,
//	and a failed validation puts the previous file set back.

// PreviewsDir is where preview state lives: one directory per preview, beside
// the app records and equally root-owned.
const PreviewsDir = StateDir + "/previews"

// PreviewKnobPath is the operator's tuning file. Komizo never creates it; the
// defaults below are the conservative answer.
const PreviewKnobPath = "/etc/komizo/preview"

// PreviewStackEnvFile is the stack-env seam: a product that needs its stack
// configuration in its previews writes this file (0600 root) into the
// preview's state directory BEFORE `preview up`, and up env_files it into the
// preview's api services. Komizo never creates, writes, reads or logs it --
// the compose file carries the reference, never a value.
const PreviewStackEnvFile = "stack.env"

// Preview defaults.
const (
	PreviewDomainDefault    = "preview.gdam.dev"
	PreviewTTLDefault       = 72 * time.Hour
	PreviewMaxDefault       = 5
	PreviewMemLimitDefault  = "512m"
	PreviewCPULimitDefault  = "0.75"
	PreviewAskPortDefault   = 8487
	PreviewPortRangeDefault = "20000-21000"
)

// PreviewKnob is the parsed knob file.
type PreviewKnob struct {
	Domain    string
	TTL       time.Duration
	Max       int
	MemLimit  string
	CPULimit  string
	AskPort   int
	PortRange string
}

// ParsePreviewKnob reads the key=value knob. Missing keys are defaults; a
// non-numeric value is that key's default with the value named in the note.
func ParsePreviewKnob(body string) (PreviewKnob, string) {
	k := PreviewKnob{
		Domain: PreviewDomainDefault, TTL: PreviewTTLDefault, Max: PreviewMaxDefault,
		MemLimit: PreviewMemLimitDefault, CPULimit: PreviewCPULimitDefault,
		AskPort: PreviewAskPortDefault, PortRange: PreviewPortRangeDefault,
	}
	get := func(key string) string {
		for _, ln := range strings.Split(body, "\n") {
			if v, ok := strings.CutPrefix(ln, key+"="); ok {
				return strings.Trim(v, "\r \t")
			}
		}
		return ""
	}
	var bad []string
	if v := get("DOMAIN"); v != "" {
		k.Domain = v
	}
	if v := get("TTL_HOURS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			k.TTL = time.Duration(n) * time.Hour
		} else {
			bad = append(bad, "TTL_HOURS="+v)
		}
	}
	if v := get("MAX_PREVIEWS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			k.Max = n
		} else {
			bad = append(bad, "MAX_PREVIEWS="+v)
		}
	}
	if v := get("MEM_LIMIT"); v != "" {
		k.MemLimit = v
	}
	if v := get("CPU_LIMIT"); v != "" {
		k.CPULimit = v
	}
	if v := get("ASK_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 65535 {
			k.AskPort = n
		} else {
			bad = append(bad, "ASK_PORT="+v)
		}
	}
	note := ""
	if len(bad) > 0 {
		note = "ignoring non-numeric preview knob values, using defaults for them: " + strings.Join(bad, ", ")
	}
	return k, note
}

// ReadPreviewKnob reads the knob file; absent is the defaults.
func ReadPreviewKnob(path string) (PreviewKnob, string) {
	b, err := os.ReadFile(path)
	if err != nil {
		k, _ := ParsePreviewKnob("")
		if os.IsNotExist(err) {
			return k, ""
		}
		return k, "could not read " + path + ", using defaults: " + err.Error()
	}
	return ParsePreviewKnob(string(b))
}

// --- names: the one place every derivation lives ------------------------------

var (
	previewAppChars = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	previewPRDigits = regexp.MustCompile(`^[0-9]+$`)
)

// PreviewProject is the compose project name: <app>-pr-<N>. Also the state
// directory name, because one name per preview is how nothing collides.
func PreviewProject(app string, pr int) string {
	return fmt.Sprintf("%s-pr-%d", app, pr)
}

// PreviewDBName is the per-preview database, <app>_pr_<N>, inside the app's
// postgres container. Charset-checked against postgres's unquoted-identifier
// rule: an app name with a hyphen becomes an underscore here, so the name is
// always a bare identifier and never needs quoting -- a quoted identifier in
// generated SQL is an injection vector invited.
func PreviewDBName(app string, pr int) string {
	return fmt.Sprintf("%s_pr_%d", strings.ReplaceAll(app, "-", "_"), pr)
}

// PreviewHost is the web route, pr-<N>.<domain>; the API is <host>-api.
func PreviewHost(pr int, domain string) string {
	return fmt.Sprintf("pr-%d.%s", pr, domain)
}

// validatePreviewArgs refuses what the derivations cannot safely hold. The PR
// is digits and the app is the app-name charset, so every derived name is
// safe to interpolate into SQL, a route file, a compose file and a hostname.
func validatePreviewArgs(app string, pr int) error {
	if !previewAppChars.MatchString(app) {
		return fmt.Errorf("app name %q is not letters, digits or hyphens starting with a letter", app)
	}
	if pr < 1 || !previewPRDigits.MatchString(strconv.Itoa(pr)) {
		return fmt.Errorf("PR number %d is not a positive integer", pr)
	}
	return nil
}

// --- the per-preview state record ----------------------------------------------

// PreviewRecord is one preview's state file, key=value like the app records.
type PreviewRecord struct {
	V       int    `json:"v"`
	App     string `json:"app"`
	PR      int    `json:"pr"`
	Project string `json:"project"`
	DBName  string `json:"db_name"`
	// DBPassword is the per-preview owner role's password, recorded 600-root
	// and injected into the preview's compose environment. The preview
	// connects as its own role, which can touch only its own database.
	//
	// json:"-" -- it is a credential, and credentials are never marshalled:
	// `preview up` and `preview ls` print this record as JSON, and a
	// credential on stdout is a credential in somebody's scrollback. The
	// state file keeps it, 600 and root-owned, which is the only place it
	// may exist.
	DBPassword string    `json:"-"`
	GatePort   int       `json:"gate_port"`
	Images     []string  `json:"images"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsed   time.Time `json:"last_used"`
	RouteFile  string    `json:"route_file"`
}

func previewDir(root, project string) string { return filepath.Join(previewDirRoot(root), project) }

// writePreviewRecord stores the record as key=value lines.
func writePreviewRecord(root string, r PreviewRecord) error {
	dir := previewDir(root, r.Project)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "V=%d\nAPP=%s\nPR=%d\nPROJECT=%s\nDB_NAME=%s\nDB_PASSWORD=%s\nGATE_PORT=%d\nIMAGES=%s\nCREATED_AT=%s\nLAST_USED=%s\nROUTE_FILE=%s\n",
		1, r.App, r.PR, r.Project, r.DBName, r.DBPassword, r.GatePort,
		strings.Join(r.Images, ","),
		r.CreatedAt.UTC().Format(time.RFC3339), r.LastUsed.UTC().Format(time.RFC3339), r.RouteFile)
	return os.WriteFile(filepath.Join(dir, "preview.env"), []byte(b.String()), 0o600)
}

// readPreviewRecord parses one back. Unknown keys are ignored; a malformed
// file is an error, because a record that cannot be read must not become a
// preview the reaper cannot see.
func readPreviewRecord(dir string) (PreviewRecord, error) {
	b, err := os.ReadFile(filepath.Join(dir, "preview.env"))
	if err != nil {
		return PreviewRecord{}, err
	}
	kv := map[string]string{}
	for _, ln := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(ln, "="); ok {
			kv[k] = v
		}
	}
	var r PreviewRecord
	r.V, _ = strconv.Atoi(kv["V"])
	r.App, r.Project, r.DBName, r.RouteFile = kv["APP"], kv["PROJECT"], kv["DB_NAME"], kv["ROUTE_FILE"]
	r.DBPassword = kv["DB_PASSWORD"]
	r.PR, _ = strconv.Atoi(kv["PR"])
	r.GatePort, _ = strconv.Atoi(kv["GATE_PORT"])
	if kv["IMAGES"] != "" {
		r.Images = strings.Split(kv["IMAGES"], ",")
	}
	r.CreatedAt, _ = time.Parse(time.RFC3339, kv["CREATED_AT"])
	r.LastUsed, _ = time.Parse(time.RFC3339, kv["LAST_USED"])
	if r.App == "" || r.Project == "" || r.PR == 0 {
		return PreviewRecord{}, fmt.Errorf("%s is not a readable preview record", dir)
	}
	return r, nil
}

// ListPreviews reads every record under the previews root, oldest last-use
// first -- the reaper's and ls's shared reading.
func ListPreviews(root string) ([]PreviewRecord, error) {
	entries, err := os.ReadDir(previewDirRoot(root))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []PreviewRecord
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		r, err := readPreviewRecord(filepath.Join(previewDirRoot(root), e.Name()))
		if err != nil {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastUsed.Before(out[j].LastUsed) })
	return out, nil
}

func previewDirRoot(root string) string {
	if root == "" {
		return PreviewsDir
	}
	return filepath.Join(root, "previews")
}

// --- capacity floors, read the same way the deploy wrapper reads them ----------

// PreviewFloors is the parsed /etc/komizo/deploy-floors.
type PreviewFloors struct {
	DiskBytes int64
	MemBytes  int64
}

// ParsePreviewFloors parses the floors file. An unreadable file or a
// non-numeric value is an error -- fail-LOUD, exactly as the deploy wrapper
// does: a floor that cannot be read is not a floor.
func ParsePreviewFloors(body string) (PreviewFloors, bool, error) {
	var f PreviewFloors
	var present bool
	get := func(key string) string {
		for _, ln := range strings.Split(body, "\n") {
			if v, ok := strings.CutPrefix(ln, key+"="); ok {
				return strings.Trim(v, "\r \t")
			}
		}
		return ""
	}
	if v := get("DISK_AVAILABLE_FLOOR_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return f, false, fmt.Errorf("deploy-floors has a non-numeric DISK_AVAILABLE_FLOOR_BYTES")
		}
		f.DiskBytes, present = n, true
	}
	if v := get("MEM_AVAILABLE_FLOOR_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return f, false, fmt.Errorf("deploy-floors has a non-numeric MEM_AVAILABLE_FLOOR_BYTES")
		}
		f.MemBytes, present = f.MemBytes+n, true
	}
	return f, present, nil
}

// PreviewCheckFloors applies the floors to report.json the way the deploy
// wrapper does: refuse below the floor, warn below twice it. An empty floors
// file means no floor -- fail-open, because that is the wrapper's rule and a
// preview must not be stricter than a deploy.
func PreviewCheckFloors(f PreviewFloors, present bool, report []byte) (refuse string, warns []string, err error) {
	if !present {
		return "", nil, nil
	}
	if len(report) == 0 {
		return "", nil, fmt.Errorf("floors are set but report.json is missing or unreadable")
	}
	var rep struct {
		System struct {
			Mem *struct {
				Available int64 `json:"available"`
			} `json:"mem"`
			Disks []struct {
				Available int64 `json:"available"`
			} `json:"disks"`
		} `json:"system"`
	}
	if err := json.Unmarshal(report, &rep); err != nil {
		return "", nil, fmt.Errorf("floors are set but report.json is not readable: %w", err)
	}
	if f.MemBytes > 0 {
		if rep.System.Mem == nil {
			return "", nil, fmt.Errorf("floors are set but report.json lacks available fields")
		}
		if a := rep.System.Mem.Available; a < f.MemBytes {
			return fmt.Sprintf("mem available %d bytes is below floor %d bytes", a, f.MemBytes), nil, nil
		} else if a < 2*f.MemBytes {
			warns = append(warns, fmt.Sprintf("mem available %d bytes is below twice the floor %d bytes", a, f.MemBytes))
		}
	}
	if f.DiskBytes > 0 {
		if len(rep.System.Disks) == 0 {
			return "", nil, fmt.Errorf("floors are set but report.json lacks available fields")
		}
		lo := rep.System.Disks[0].Available
		for _, d := range rep.System.Disks {
			if d.Available < lo {
				lo = d.Available
			}
		}
		if lo < f.DiskBytes {
			return fmt.Sprintf("disk available %d bytes is below floor %d bytes", lo, f.DiskBytes), nil, nil
		} else if lo < 2*f.DiskBytes {
			warns = append(warns, fmt.Sprintf("disk available %d bytes is below twice the floor %d bytes", lo, f.DiskBytes))
		}
	}
	return "", warns, nil
}

// --- the compose file and the route file ---------------------------------------

// previewCompose renders the preview's compose.yml. The first image is the
// gate -- the one the proxy routes to -- and joins the shared network by its
// project-scoped alias; every service is capped, because a preview is a guest
// on a box that also feeds people.
//
// envFile is the stack-env seam: the calling product may write
// <previewDir>/stack.env (0600 root) BEFORE up, and up passes its absolute
// path here. Non-empty, it is referenced as env_file on every non-gate
// service -- the product's stack configuration follows its code into the
// preview without komizo ever reading, copying or logging a value. Empty, no
// env_file appears and a zero-config preview stays zero-config. The gate
// never gets it: the gate keys off BASE_URL, which is already passed via
// environment:, and environment: overrides env_file in compose -- the
// preview-derived values (PGPASSWORD et al.) always win.
func previewCompose(r PreviewRecord, k PreviewKnob, network, envFile string) string {
	var b strings.Builder
	b.WriteString("# Written by komizo preview. Re-run `komizo preview up` to change it.\n")
	fmt.Fprintf(&b, "# Preview of %s PR #%d. Own project, own database (%s), own route.\nservices:\n", r.App, r.PR, r.DBName)
	for i, image := range r.Images {
		name := image[strings.LastIndex(image, "/")+1:]
		if j := strings.Index(name, ":"); j >= 0 {
			name = name[:j]
		}
		if i == 0 {
			name = "gate"
		}
		fmt.Fprintf(&b, "  %s:\n    image: %s\n    mem_limit: %s\n    cpus: %s\n    restart: unless-stopped\n", name, image, k.MemLimit, k.CPULimit)
		if i == 0 {
			fmt.Fprintf(&b, "    container_name: %s-gate\n    environment:\n", r.Project)
			fmt.Fprintf(&b, "      PREVIEW: \"1\"\n      PR: \"%d\"\n      DB_NAME: %s\n      PGDATABASE: %s\n      PGUSER: %s\n      PGPASSWORD: %s\n      BASE_URL: https://%s\n", r.PR, r.DBName, r.DBName, r.DBName, r.DBPassword, PreviewHost(r.PR, k.Domain))
			// The gate port, LOOPBACK only: the direct HTTP entry to the
			// preview from the box itself, never from the network -- the
			// public way in is the proxy route, with TLS. Publishing on all
			// interfaces would put every preview one port-scan away from the
			// internet.
			b.WriteString("    ports:\n")
			fmt.Fprintf(&b, "      - \"127.0.0.1:%d:80\"\n", r.GatePort)
			b.WriteString("    networks:\n      - shared\n      - appnet\n")
		} else {
			if envFile != "" {
				fmt.Fprintf(&b, "    env_file:\n      - %s\n", envFile)
			}
			fmt.Fprintf(&b, "    environment:\n      PREVIEW: \"1\"\n      PR: \"%d\"\n      DB_NAME: %s\n      PGDATABASE: %s\n      PGUSER: %s\n      PGPASSWORD: %s\n", r.PR, r.DBName, r.DBName, r.DBName, r.DBPassword)
			b.WriteString("    networks:\n      - appnet\n")
		}
	}
	fmt.Fprintf(&b, "networks:\n  shared:\n    external: true\n    name: %s\n  appnet:\n    external: true\n    name: %s_default\n", network, r.App)
	return b.String()
}

// previewRoute renders the route file: the two hostnames, both to the gate.
// Content is deliberately thinner than an app's route -- the discipline that
// matters (write, validate, reload, restore on failure) is in
// ApplyPreviewRoute, not in what the file says.
func previewRoute(r PreviewRecord, k PreviewKnob) string {
	return fmt.Sprintf(`# Written by komizo preview. %s PR #%d -- removed by 'komizo preview down'.
%s, %s {
	reverse_proxy %s-gate:80
}
`, r.App, r.PR, PreviewHost(r.PR, k.Domain), fmt.Sprintf("pr-%d-api.%s", r.PR, k.Domain), r.Project)
}

// ApplyPreviewRoute writes a route with the same discipline as every other
// route change on this box: write, validate the COMBINED config inside the
// proxy container, restore the previous file set on failure, reload on
// success. The previous content of the file (if any) is held for the restore.
func ApplyPreviewRoute(ctx context.Context, run previewRun, proxy, routesDir, file, content string) error {
	path := filepath.Join(routesDir, file)
	previous, _ := os.ReadFile(path)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return err
	}
	if _, err := run(ctx, "", "exec", proxy, "caddy", "validate", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"); err != nil {
		// Put the previous state back and do NOT reload: the proxy keeps
		// serving what it had, and the failure is reported with the broken
		// file already gone.
		if previous == nil {
			_ = os.Remove(path)
		} else {
			_ = os.WriteFile(path, previous, 0o644)
		}
		return fmt.Errorf("the combined proxy config does not validate with the new route -- left as it was: %w", err)
	}
	if _, err := run(ctx, "", "exec", proxy, "caddy", "reload", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"); err != nil {
		return fmt.Errorf("the route validates but the proxy did not reload: %w", err)
	}
	return nil
}

// RemovePreviewRoute takes a route out with the same discipline: remove,
// validate, restore on failure, reload on success.
func RemovePreviewRoute(ctx context.Context, run previewRun, proxy, routesDir, file string) error {
	path := filepath.Join(routesDir, file)
	previous, err := os.ReadFile(path)
	if err != nil {
		return nil // absent is already the desired state
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	if _, err := run(ctx, "", "exec", proxy, "caddy", "validate", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"); err != nil {
		_ = os.WriteFile(path, previous, 0o644)
		return fmt.Errorf("removing the route broke the combined config -- restored: %w", err)
	}
	if _, err := run(ctx, "", "exec", proxy, "caddy", "reload", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"); err != nil {
		return fmt.Errorf("the route is gone but the proxy did not reload: %w", err)
	}
	return nil
}

// --- the database, inside the app's postgres container ---------------------------

// findAppDBContainer names the running postgres container in the app's
// compose project. The app record is not asked: the container is the fact,
// and asking a file what runs is how yesterday's truth becomes today's
// mistake.
//
// THREE WAYS TO KNOW, in order, because products pin postgres by digest and
// docker ps's Image column for a digest-pulled image shows only the short
// digest -- no "postgres" substring anywhere:
//
//  1. the ps Image column (the cheap, common case, matched on "postgres");
//  2. the container's Config.Image, asked of docker inspect -- the ORIGINAL
//     reference, which for a digest pull is postgres@sha256:... and carries
//     the name the column lost;
//  3. the container's own NAME (compose's <project>-postgres-1).
//
// The psql call after discovery is the final proof: a container that matched
// on name and is not postgres fails there, loudly, with nothing created.
func findAppDBContainer(ctx context.Context, run previewRun, psOut, app string) (string, error) {
	type candidate struct{ name, image string }
	var candidates []candidate
	for _, ln := range strings.Split(psOut, "\n") {
		f := strings.Split(strings.TrimRight(ln, "\r"), "\t")
		if len(f) >= 2 && f[0] != "" {
			candidates = append(candidates, candidate{f[0], f[1]})
		}
	}
	for _, c := range candidates {
		if strings.Contains(c.image, "postgres") {
			return c.name, nil
		}
	}
	for _, c := range candidates {
		out, err := run(ctx, "", "inspect", c.name, "--format", "{{.Config.Image}}")
		if err == nil && strings.Contains(out, "postgres") {
			return c.name, nil
		}
	}
	for _, c := range candidates {
		if strings.Contains(c.name, "postgres") {
			return c.name, nil
		}
	}
	return "", fmt.Errorf("no postgres container is running in %s's project -- a preview needs the app's database to put its own beside", app)
}

// previewDBEnv reads the container's POSTGRES_USER and POSTGRES_DB from its
// environment, the superuser and the database to connect to. The stock image
// answers postgres/postgres and needs neither set; a product that names its
// own superuser is connected to as THAT, and the hardcoded 'postgres' never
// appears. An env that cannot be read is an error rather than a guess.
func previewDBEnv(ctx context.Context, run previewRun, container string) (string, string, error) {
	out, err := run(ctx, "", "inspect", container, "--format", "{{range .Config.Env}}{{println .}}{{end}}")
	if err != nil {
		return "", "", fmt.Errorf("could not read %s's environment: %w", container, err)
	}
	user, db := "postgres", "postgres"
	for _, ln := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(ln, "POSTGRES_USER="); ok && v != "" {
			user = v
		}
		if v, ok := strings.CutPrefix(ln, "POSTGRES_DB="); ok && v != "" {
			db = v
		}
	}
	return user, db, nil
}

// previewNewPassword generates the per-preview role's password: 24 random hex
// characters, recorded in the preview's state file (600, root-owned) and
// injected into its compose environment. The role exists so a preview
// connects as something that can touch ONLY its own database.
func previewNewPassword() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing on a linux box is a panic-grade environment
		// problem, not something a preview can work around.
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return hex.EncodeToString(b)
}

// --- the ask matcher --------------------------------------------------------------

// previewAskPattern is what the on-demand-TLS gate approves: pr-<digits> and
// pr-<digits>-api under the preview domain, and nothing else. The #132 guard
// -- routes that need on-demand issuance with no ask module -- is untouched;
// this decides, hostname by hostname, who may cause a certificate to exist.
func PreviewAskAllow(host, domain string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" || !strings.HasSuffix(host, "."+domain) {
		return false
	}
	sub := strings.TrimSuffix(host, "."+domain)
	if strings.HasPrefix(sub, "pr-") {
		rest := strings.TrimPrefix(sub, "pr-")
		rest = strings.TrimSuffix(rest, "-api")
		return previewPRDigits.MatchString(rest)
	}
	return false
}

// --- the lifecycle ---------------------------------------------------------------

// previewRun is the docker runner the preview lifecycle uses. stdin feeds
// the statements psql must hear from a pipe -- psql performs :'var'
// substitution on lines it reads from STDIN and NOT on -c arguments (psql
// 18.6, verified on gdam-postgres-1), so the role's password travels as the
// 'pw' variable and never inside SQL text.
type previewRun func(ctx context.Context, stdin string, args ...string) (string, error)

// previewSQL runs one psql statement read from STDIN via docker exec -i, as
// the container's own superuser. Used for every statement that carries a
// variable psql must substitute; -c statements (no variables) keep the
// simpler form.
func previewSQL(ctx context.Context, run previewRun, container, user, db, sql string, args ...string) error {
	argv := append([]string{"exec", "-i", container, "psql", "-U", user, "-d", db}, args...)
	_, err := run(ctx, sql+"\n", argv...)
	return err
}

// PreviewUpConfig is what an up needs. Run is the docker runner; everything
// else is paths and the knob, so a test drives the whole lifecycle with
// fakes and a temp root.
type PreviewUpConfig struct {
	Knob       PreviewKnob
	Root       string // previews state root ("" = the box's)
	RoutesDir  string
	Proxy      string
	Network    string
	FloorsBody string
	ReportJSON []byte
}

// PreviewUp brings a preview up: validate, floors, evict if full, database,
// state, compose, route. Each step before the compose up leaves nothing
// behind on failure; the route is the last thing to change, and it carries
// its own restore.
func PreviewUp(ctx context.Context, run previewRun, cfg PreviewUpConfig, app string, pr int, images []string, now time.Time) (PreviewRecord, error) {
	var zero PreviewRecord
	if err := validatePreviewArgs(app, pr); err != nil {
		return zero, err
	}
	if len(images) == 0 {
		return zero, fmt.Errorf("no images given -- a preview is images and nothing else")
	}
	for _, image := range images {
		if !onlyCharsPreview(image, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.:/_@=-") {
			return zero, fmt.Errorf("image %q contains characters that are not valid in an image reference", image)
		}
	}
	floors, present, err := ParsePreviewFloors(cfg.FloorsBody)
	if err != nil {
		return zero, err
	}
	if refuse, _, err := PreviewCheckFloors(floors, present, cfg.ReportJSON); err != nil {
		return zero, err
	} else if refuse != "" {
		return zero, fmt.Errorf("preview up refused by the capacity floors: %s", refuse)
	}

	project := PreviewProject(app, pr)
	rec := PreviewRecord{
		V: 1, App: app, PR: pr, Project: project,
		DBName:    PreviewDBName(app, pr),
		Images:    images,
		CreatedAt: now, LastUsed: now,
		RouteFile: "_preview-" + project + ".caddy",
	}
	// The password is generated NOW, before the state file is written, so
	// the record on disk carries it from the start -- a preview.env without
	// it is a preview that cannot be taken down cleanly.
	rec.DBPassword = previewNewPassword()

	// Evict BEFORE adding, so max-N is a ceiling and not a target to exceed
	// and come back under: the least-recently-used preview goes first.
	existing, err := ListPreviews(cfg.Root)
	if err != nil {
		return zero, err
	}
	var have bool
	for _, e := range existing {
		if e.Project == project {
			have = true
		}
	}
	if !have && len(existing) >= cfg.Knob.Max {
		if err := PreviewDown(ctx, run, cfg, existing[0]); err != nil {
			return zero, fmt.Errorf("evicting %s to stay within %d previews: %w", existing[0].Project, cfg.Knob.Max, err)
		}
	}

	// The gate port: first free in the range, state-derived. Recorded rather
	// than probed -- the state file is what keeps two previews from being
	// handed the same one.
	lo, hi := 20000, 21000
	if cfg.Knob.PortRange != "" {
		_, _ = fmt.Sscanf(cfg.Knob.PortRange, "%d-%d", &lo, &hi)
	}
	used := map[int]bool{}
	for _, e := range existing {
		used[e.GatePort] = true
	}
	for rec.GatePort = lo; rec.GatePort <= hi && used[rec.GatePort]; rec.GatePort++ {
	}
	if rec.GatePort > hi {
		return zero, fmt.Errorf("no free gate ports in %d-%d", lo, hi)
	}

	// STATE FIRST. The record and its compose file exist before anything is
	// created, and everything after this point rolls back BOTH -- a failure
	// must never leave resources without state (an orphan nothing can reap)
	// or state without resources (a record the reaper would chase forever).
	// The state dir may ALREADY exist: a product that uses the stack-env
	// seam pre-creates it and writes stack.env before up. MkdirAll tolerates
	// that, nothing here writes stack.env, and the env_file reference below
	// appears only if the file exists at render time.
	if err := writePreviewRecord(cfg.Root, rec); err != nil {
		return zero, err
	}
	composePath := filepath.Join(previewDir(cfg.Root, project), "compose.yml")
	envFile := ""
	stackEnv := filepath.Join(previewDir(cfg.Root, project), PreviewStackEnvFile)
	if _, err := os.Stat(stackEnv); err == nil {
		envFile = stackEnv
	}
	if err := os.WriteFile(composePath, []byte(previewCompose(rec, cfg.Knob, cfg.Network, envFile)), 0o600); err != nil {
		return zero, err
	}
	rollback := func(dbContainer, dbUser, dbDB string, created bool) {
		_, _ = run(ctx, "", "compose", "-p", project, "-f", composePath, "down", "-v")
		if created && dbContainer != "" {
			_, _ = run(ctx, "", "exec", dbContainer, "psql", "-U", dbUser, "-d", dbDB, "-c",
				"DROP DATABASE IF EXISTS "+rec.DBName)
			_ = previewSQL(ctx, run, dbContainer, dbUser, dbDB,
				"DROP ROLE IF EXISTS "+rec.DBName+";")
		}
		_ = os.Remove(filepath.Join(cfg.RoutesDir, rec.RouteFile))
		_ = os.RemoveAll(previewDir(cfg.Root, project))
	}

	// The database, before anything runs: the app's postgres container, a new
	// role and database named for the PR, owned by that role, and nothing
	// else touched.
	psOut, err := run(ctx, "", "ps", "--filter", "label=com.docker.compose.project="+app,
		"--format", "{{.Names}}\t{{.Image}}")
	if err != nil {
		rollback("", "", "", false)
		return zero, fmt.Errorf("could not look for the app's postgres: %w", err)
	}
	dbContainer, err := findAppDBContainer(ctx, run, psOut, app)
	if err != nil {
		rollback("", "", "", false)
		return zero, err
	}
	// Connect as the container's OWN superuser -- POSTGRES_USER from its
	// environment, never a hardcoded 'postgres': products that set a custom
	// one (gdam_migrator, for example) have no 'postgres' role at all, and
	// connecting with it is the failure the avior.studio smoke found.
	dbUser, dbDB, err := previewDBEnv(ctx, run, dbContainer)
	if err != nil {
		rollback("", "", "", false)
		return zero, err
	}
	if err := previewSQL(ctx, run, dbContainer, dbUser, dbDB,
		"CREATE ROLE "+rec.DBName+" LOGIN PASSWORD :'pw';",
		"-v", "pw="+rec.DBPassword); err != nil {
		rollback(dbContainer, dbUser, dbDB, false)
		return zero, fmt.Errorf("could not create the preview role %s in %s: %w", rec.DBName, dbContainer, err)
	}
	if _, err := run(ctx, "", "exec", dbContainer, "psql", "-U", dbUser, "-d", dbDB, "-c",
		"CREATE DATABASE "+rec.DBName+" OWNER "+rec.DBName); err != nil {
		rollback(dbContainer, dbUser, dbDB, false)
		return zero, fmt.Errorf("could not create the preview database %s in %s: %w", rec.DBName, dbContainer, err)
	}

	if _, err := run(ctx, "", "compose", "-p", project, "-f", composePath, "up", "-d"); err != nil {
		rollback(dbContainer, dbUser, dbDB, true)
		return zero, fmt.Errorf("the preview project did not come up: %w", err)
	}
	if err := ApplyPreviewRoute(ctx, run, cfg.Proxy, cfg.RoutesDir, rec.RouteFile, previewRoute(rec, cfg.Knob)); err != nil {
		rollback(dbContainer, dbUser, dbDB, true)
		return zero, err
	}
	return rec, nil
}

// PreviewDown takes a preview down, exactly: project down, ITS database
// dropped, ITS route removed with the validate discipline, ITS state
// directory gone. Nothing else is named.
func PreviewDown(ctx context.Context, run previewRun, cfg PreviewUpConfig, rec PreviewRecord) error {
	composeFile := filepath.Join(previewDir(cfg.Root, rec.Project), "compose.yml")
	if _, err := run(ctx, "", "compose", "-p", rec.Project, "-f", composeFile, "down", "-v"); err != nil {
		// A missing project is already down; anything else is reported.
		if _, statErr := os.Stat(composeFile); statErr == nil {
			return fmt.Errorf("could not take the preview project down: %w", err)
		}
	}
	if rec.DBName != "" {
		psOut, err := run(ctx, "", "ps", "--filter", "label=com.docker.compose.project="+rec.App,
			"--format", "{{.Names}}\t{{.Image}}")
		if err == nil {
			if dbContainer, derr := findAppDBContainer(ctx, run, psOut, rec.App); derr == nil {
				dbUser, dbDB, derr := previewDBEnv(ctx, run, dbContainer)
				if derr != nil {
					return fmt.Errorf("could not read %s's environment to drop the preview database cleanly: %w", dbContainer, derr)
				}
				if _, err := run(ctx, "", "exec", dbContainer, "psql", "-U", dbUser, "-d", dbDB, "-c",
					"DROP DATABASE IF EXISTS "+rec.DBName); err != nil {
					return fmt.Errorf("could not drop the preview database %s: %w", rec.DBName, err)
				}
				if err := previewSQL(ctx, run, dbContainer, dbUser, dbDB,
					"DROP ROLE IF EXISTS "+rec.DBName+";"); err != nil {
					return fmt.Errorf("could not drop the preview role %s: %w", rec.DBName, err)
				}
			}
		}
	}
	if err := RemovePreviewRoute(ctx, run, cfg.Proxy, cfg.RoutesDir, rec.RouteFile); err != nil {
		return err
	}
	return os.RemoveAll(previewDir(cfg.Root, rec.Project))
}

// PreviewReap is what a gc pass did, written to the served directory so the
// report -- and komizo ui -- can show it. Same shape as the disk sweep's
// record, for the same reason: a reaper that says nothing is
// indistinguishable from one that never ran.
type PreviewReap struct {
	V      int       `json:"v"`
	At     time.Time `json:"at"`
	Reaped []string  `json:"reaped"`
	Kept   int       `json:"kept"`
	Note   string    `json:"note,omitempty"`
}

// PreviewReapPath is where the record lives.
func PreviewReapPath() string { return ServedDir + "/preview-reap.json" }

// PreviewGC applies the TTL and the max-N ceiling, reaping ONLY previews it
// has state records for. It never looks at anything else: no app, no
// container, no image, no route that is not derived from a record in the
// previews directory. That is the reaper's refusal, and the contract test
// pins it.
func PreviewGC(ctx context.Context, run previewRun, cfg PreviewUpConfig, now time.Time) (PreviewReap, error) {
	reap := PreviewReap{V: 1, At: now}
	existing, err := ListPreviews(cfg.Root)
	if err != nil {
		return reap, err
	}
	// TTL first: expired previews go, oldest last-use first (the list is
	// sorted that way).
	var live []PreviewRecord
	for _, rec := range existing {
		if now.Sub(rec.LastUsed) > cfg.Knob.TTL {
			if err := PreviewDown(ctx, run, cfg, rec); err != nil {
				reap.Note = joinNotePreview(reap.Note, fmt.Sprintf("could not reap %s (kept): %v", rec.Project, err))
				live = append(live, rec)
				continue
			}
			reap.Reaped = append(reap.Reaped, rec.Project)
			continue
		}
		live = append(live, rec)
	}
	// Then the ceiling: still too many, the least-recently-used goes.
	for len(live) > cfg.Knob.Max {
		if err := PreviewDown(ctx, run, cfg, live[0]); err != nil {
			reap.Note = joinNotePreview(reap.Note, fmt.Sprintf("could not evict %s (kept): %v", live[0].Project, err))
			break
		}
		reap.Reaped = append(reap.Reaped, live[0].Project)
		live = live[1:]
	}
	reap.Kept = len(live)
	if len(reap.Reaped) == 0 && reap.Note == "" {
		reap.Note = "nothing to reap"
	}
	return reap, nil
}

// WritePreviewReap leaves the gc record where the probe reads it.
func WritePreviewReap(path string, r PreviewReap) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// ReadPreviewReap reads it back; absent is a box that has never reaped.
func ReadPreviewReap(path string) (PreviewReap, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return PreviewReap{}, false
	}
	var r PreviewReap
	if err := json.Unmarshal(b, &r); err != nil {
		return PreviewReap{}, false
	}
	return r, true
}

func joinNotePreview(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

func onlyCharsPreview(s, chars string) bool {
	for _, r := range s {
		if !strings.ContainsRune(chars, r) {
			return false
		}
	}
	return len(s) > 0
}
