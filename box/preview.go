package box

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
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

// PreviewDBContainer is komizo's OWN postgres, one per box, and the only
// database a preview ever touches.
//
// It used to create its role and database inside the APP's postgres --
// superuser DDL against the server holding production data, on every PR
// opened and every PR closed. The containment was careful and the blast
// radius was still production's database. komizo is supposed to be
// non-invasive: it owns what it created and nothing else, which is why
// a stop is recorded in the app's own record and why sweep pins its argv
// to make "never touches a volume" provable. The preview database was the
// one place that reached inside.
//
// Owning the server also removes an accidental requirement. The old path
// had to FIND the app's postgres, so a product without one -- a gate-only
// static site -- could not have a preview at all, failing with "no postgres
// container is running". Nothing about a static site needs a database, and
// now nothing asks it for one.
//
// Parity is kept by pinning the same image every product pins, so a preview
// runs the engine production runs.
const (
	PreviewDBContainer   = "komizo-previews"
	PreviewDBSuperuser   = "postgres"
	PreviewDBMaintenance = "postgres"
)

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
	// SharedDomain opts this host into flat, app-qualified preview names.
	SharedDomain      string
	Domain            string
	TTL               time.Duration
	Max               int
	MemLimit          string
	CPULimit          string
	ProductionReserve int64
	DatabaseReserve   int64
	MemoryBudget      int64
	InvalidBudget     bool
	AskPort           int
	PortRange         string
	// body is the raw knob, so DomainFor reuses the same lookup that
	// ParsePreviewKnob used -- there is one get, not two parsers that
	// could drift.
	body string
}

// ParsePreviewKnob reads the key=value knob. Missing keys are defaults; a
// non-numeric value is that key's default with the value named in the note.
func ParsePreviewKnob(body string) (PreviewKnob, string) {
	k := PreviewKnob{
		Domain: PreviewDomainDefault, TTL: PreviewTTLDefault, Max: PreviewMaxDefault,
		MemLimit: PreviewMemLimitDefault, CPULimit: PreviewCPULimitDefault,
		AskPort: PreviewAskPortDefault, PortRange: PreviewPortRangeDefault,
		body: body, SharedDomain: previewKnobGet(body, "SHARED_DOMAIN"),
	}
	get := func(key string) string { return previewKnobGet(body, key) }
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
		if _, err := previewMemoryBytes(v); err == nil {
			k.MemLimit = v
		} else {
			bad = append(bad, "MEM_LIMIT="+v)
		}
	}
	if v := get("CPU_LIMIT"); v != "" {
		if validPreviewCPU(v) {
			k.CPULimit = v
		} else {
			bad = append(bad, "CPU_LIMIT="+v)
		}
	}
	if v := get("MEM_BUDGET"); v != "" {
		var err error
		k.MemoryBudget, err = previewMemoryBytes(v)
		k.InvalidBudget = err != nil
		if err != nil {
			bad = append(bad, "MEM_BUDGET="+v)
		}
	}
	for key, target := range map[string]*int64{"PRODUCTION_RESERVE": &k.ProductionReserve, "DB_MEM_LIMIT": &k.DatabaseReserve} {
		if value := get(key); value != "" {
			parsed, err := previewMemoryBytes(value)
			if err != nil {
				k.InvalidBudget = true
				bad = append(bad, key+"="+value)
			} else {
				*target = parsed
			}
		}
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
		note = "invalid preview knob values (invalid MEM_BUDGET refuses up; other invalid limits use bounded defaults): " + strings.Join(bad, ", ")
	}
	return k, note
}

var previewMemoryPattern = regexp.MustCompile(`(?i)^([1-9][0-9]*)([kmgt]?)(?:b)?$`)

// App limits override the host default; Revik may also size its six services
// separately. Admission and Compose use this same lookup so the recorded
// reservation is the sum of enforceable limits, including migration startup.
func previewServiceMemory(k PreviewKnob, app, service string) string {
	if service != "" {
		if value := previewKnobGet(k.body, "MEM_LIMIT."+app+"."+service); value != "" {
			return value
		}
	}
	if value := previewKnobGet(k.body, "MEM_LIMIT."+app); value != "" {
		return value
	}
	return k.MemLimit
}

var revikPreviewServices = []string{"gate", "api", "godot-api", "postgres", "redis", "migrate"}

func previewMemoryReservation(k PreviewKnob, app string, images int) (int64, error) {
	services := []string{""}
	if app == "fieldsofrevik" {
		services = revikPreviewServices
	}
	var reserved int64
	for _, service := range services {
		memory, err := previewMemoryBytes(previewServiceMemory(k, app, service))
		if err != nil {
			return 0, fmt.Errorf("preview up refused: invalid memory limit for %s %s", app, service)
		}
		reserved += memory
	}
	if app != "fieldsofrevik" {
		reserved *= int64(images)
	}
	return reserved, nil
}

var previewCPUPattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)?$`)

func previewMemoryBytes(value string) (int64, error) {
	parts := previewMemoryPattern.FindStringSubmatch(value)
	if parts == nil {
		return 0, fmt.Errorf("memory must be positive bytes or k/m/g units")
	}
	number, err := strconv.ParseUint(parts[1], 10, 64)
	multiplier := uint64(1)
	for i := strings.Index("kmgt", strings.ToLower(parts[2])); parts[2] != "" && i >= 0; i-- {
		multiplier *= 1024
	}
	if err != nil || number > (64<<30)/multiplier || number*multiplier < 6<<20 {
		return 0, fmt.Errorf("memory must be between 6 MiB and 64 GiB")
	}
	return int64(number * multiplier), nil
}

func validPreviewCPU(value string) bool {
	number, err := strconv.ParseFloat(value, 64)
	return previewCPUPattern.MatchString(value) && err == nil && number > 0 && number <= 64
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

// previewKnobGet is the knob's one lookup: first line whose prefix is
// key+"=", value trimmed of CR and spaces/tabs only -- quotes are not
// stripped, so an unquoted value is used verbatim. First match wins;
// empty after trim is "not set" and the caller falls through. Bare
// "DOMAIN" does not match "DOMAIN.<app>" (CutPrefix on key+"=").
func previewKnobGet(body, key string) string {
	for _, ln := range strings.Split(body, "\n") {
		if v, ok := strings.CutPrefix(ln, key+"="); ok {
			return strings.Trim(v, "\r \t")
		}
	}
	return ""
}

// DomainFor is the per-app resolution chain, exactly:
// SHARED_DOMAIN.<app> / SHARED_DOMAIN take priority when enabled; otherwise
// get("DOMAIN."+app) → get("DOMAIN") → PreviewDomainDefault.
// An empty DOMAIN.<app>= falls through to the bare DOMAIN; an empty
// DOMAIN= falls through to the compiled default. An unknown app is
// NEVER refused -- a product without its own key previews on the
// default, exactly as before per-app keys existed.
func (k PreviewKnob) DomainFor(app string) string {
	if domain := k.PathDomainFor(app); domain != "" {
		return domain
	}
	if shared := k.SharedDomainFor(app); shared != "" {
		return shared
	}
	return k.legacyDomainFor(app)
}

func (k PreviewKnob) legacyDomainFor(app string) string {
	if v := previewKnobGet(k.body, "DOMAIN."+app); v != "" {
		return v
	}
	if v := previewKnobGet(k.body, "DOMAIN"); v != "" {
		return v
	}
	return PreviewDomainDefault
}

// Domains preserves legacy TLS authorization during migration: the default
// and nonempty DOMAIN.<app> values, deduped and sorted after the default.
// Shared-domain names are authorized separately by SharedAskAllow.
func (k PreviewKnob) Domains() []string {
	def := k.Domain
	if def == "" {
		def = PreviewDomainDefault
	}
	out := []string{def}
	seen := map[string]bool{def: true}
	var rest []string
	for _, ln := range strings.Split(k.body, "\n") {
		tail, ok := strings.CutPrefix(ln, "DOMAIN.")
		if !ok {
			continue
		}
		app, _, ok := strings.Cut(tail, "=")
		if !ok || app == "" {
			continue
		}
		d := previewKnobGet(k.body, "DOMAIN."+app)
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		rest = append(rest, d)
	}
	sort.Strings(rest)
	return append(out, rest...)
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
	V        int    `json:"v"`
	App      string `json:"app"`
	PR       int    `json:"pr"`
	Project  string `json:"project"`
	Host     string `json:"host,omitempty"`
	APIHost  string `json:"api_host"`
	BasePath string `json:"base_path,omitempty"`
	DBName   string `json:"db_name"`
	// DBPassword is the per-preview owner role's password, recorded 600-root
	// and injected into the preview's compose environment. The preview
	// connects as its own role, which can touch only its own database.
	//
	// json:"-" -- it is a credential, and credentials are never marshalled:
	// `preview up` and `preview ls` print this record as JSON, and a
	// credential on stdout is a credential in somebody's scrollback. The
	// state file keeps it, 600 and root-owned, which is the only place it
	// may exist.
	DBPassword          string    `json:"-"`
	GatePort            int       `json:"gate_port"`
	Images              []string  `json:"images"`
	CreatedAt           time.Time `json:"created_at"`
	LastUsed            time.Time `json:"last_used"`
	RouteFile           string    `json:"route_file"`
	MemoryReservedBytes int64     `json:"memory_reserved_bytes,omitempty"`
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
	fmt.Fprintf(&b, "HOST=%s\nAPI_HOST=%s\nBASE_PATH=%s\n", r.Host, r.APIHost, r.BasePath)
	fmt.Fprintf(&b, "MEMORY_RESERVED_BYTES=%d\n", r.MemoryReservedBytes)
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
	r.Host, r.APIHost, r.BasePath = kv["HOST"], kv["API_HOST"], kv["BASE_PATH"]
	r.PR, _ = strconv.Atoi(kv["PR"])
	r.GatePort, _ = strconv.Atoi(kv["GATE_PORT"])
	if value := kv["MEMORY_RESERVED_BYTES"]; value != "" {
		r.MemoryReservedBytes, err = strconv.ParseInt(value, 10, 64)
		if err != nil || r.MemoryReservedBytes < 0 {
			return r, fmt.Errorf("invalid preview memory reservation")
		}
	}
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
		directory := filepath.Join(previewDirRoot(root), e.Name())
		r, err := readPreviewRecord(directory)
		if err != nil {
			if os.IsNotExist(err) {
				// stack.env can be staged before first up. An existing Compose
				// stack without readable state must not vanish from admission/GC.
				if _, composeErr := os.Stat(filepath.Join(directory, "compose.yml")); os.IsNotExist(composeErr) {
					continue
				}
			}
			return nil, fmt.Errorf("preview inventory contains unreadable state: %w", err)
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
// stackEnv is whether the preview's state directory holds a stack.env written
// by the calling product BEFORE up. When it does, every API (non-gate)
// service gets `env_file: - stack.env` -- RELATIVE, because compose resolves
// a relative env_file against the compose file's own directory, and both
// files live in the preview's state directory, so the reference survives any
// project-directory override. The gate does NOT get it: the gate keys off
// BASE_URL, which it already receives via environment:, and a product-
// writable file must not get a say in the routed entrypoint. The file's
// existence is all this function is told -- its contents are never read,
// rendered or logged, only the path reference is written.
//
// dbEndpoint is the discovered NAME of the app's postgres container and
// dbNetworks its networks. The API services get a derived
// RUNTIME_DATABASE_URL -- postgres://<role>:<pw>@<dbEndpoint>:5432/<db>,
// role and db both the preview's own -- because products fail-closed-require
// a DSN and ignore the PG* vars (which stay: harmless, and other apps read
// them). Docker DNS resolves container names on user-defined networks, so
// once the API shares the DB's network it reaches postgres by name. The DSN
// carries the DB password, a credential: it lands ONLY in the API services'
// environment, never on the gate (the gate routes HTTP, it does not touch
// the database) and never on stdout -- the same discipline as DBPassword's
// json:"-". The API services join the DB's networks IN ADDITION to appnet:
// an app's postgres may live on a different network than <app>_default, and
// joining is reachability only -- the preview role can already touch only
// its own database, so no data access widens. The gate's networks stay
// [shared, appnet].
// previewDBEnvLines renders the database half of a service's environment,
// and nothing at all when the preview has no database. A gate-only preview
// used to be handed DB_NAME, PGUSER and PGPASSWORD with empty values --
// credentials for a database that does not exist, which is worse than
// absent: an app that reads PGUSER cannot tell "no database here" from
// "database misconfigured".
func previewDBEnvLines(r PreviewRecord) string {
	if r.DBName == "" {
		return ""
	}
	return fmt.Sprintf("      DB_NAME: %s\n      PGDATABASE: %s\n      PGUSER: %s\n      PGPASSWORD: %s\n",
		r.DBName, r.DBName, r.DBName, r.DBPassword)
}

// Components named renderer or runtime are credential-free private services.
// This is a generic component contract, independent of application names.
func previewRuntimeRole(image string) string {
	name := image[strings.LastIndex(image, "/")+1:]
	name, _, _ = strings.Cut(name, "@")
	name, _, _ = strings.Cut(name, ":")
	for _, role := range []string{"renderer", "runtime"} {
		if name == role || strings.HasSuffix(name, "-"+role) {
			return role
		}
	}
	return ""
}
func previewHasRuntime(images []string) bool {
	if len(images) < 2 {
		return false
	}
	for _, image := range images[1:] {
		if previewRuntimeRole(image) != "" {
			return true
		}
	}
	return false
}
func previewImagesMemoryReservation(k PreviewKnob, app string, images []string) (int64, error) {
	if len(images) == 0 {
		return 0, fmt.Errorf("no preview images")
	}
	reserved, err := previewMemoryReservation(k, app, len(images))
	if err != nil || app == "fieldsofrevik" {
		return reserved, err
	}
	base, err := previewMemoryBytes(previewServiceMemory(k, app, ""))
	if err != nil {
		return 0, err
	}
	for _, image := range images[1:] {
		role := previewRuntimeRole(image)
		if role == "" {
			continue
		}
		limit, err := previewMemoryBytes(previewServiceMemory(k, app, role))
		if err != nil {
			return 0, fmt.Errorf("invalid private runtime memory limit: %w", err)
		}
		reserved += limit - base
	}
	return reserved, nil
}

func previewCompose(r PreviewRecord, k PreviewKnob, network string, stackEnv bool, dbEndpoint string) string {
	if r.App == "fieldsofrevik" {
		return revikPreviewCompose(r, k, network)
	}
	var b strings.Builder
	b.WriteString("# Written by komizo preview. Re-run `komizo preview up` to change it.\n")
	if r.DBName != "" {
		fmt.Fprintf(&b, "# Preview of %s PR #%d. Own project, own database (%s), own route.\nservices:\n", r.App, r.PR, r.DBName)
	} else {
		fmt.Fprintf(&b, "# Preview of %s PR #%d. Own project, own route. Gate only -- no database.\nservices:\n", r.App, r.PR)
	}
	for i, image := range r.Images {
		name := image[strings.LastIndex(image, "/")+1:]
		if j := strings.Index(name, ":"); j >= 0 {
			name = name[:j]
		}
		if i == 0 {
			name = r.Project + "-gate"
		}
		role := ""
		if i > 0 {
			role = previewRuntimeRole(image)
		}
		limit := previewServiceMemory(k, r.App, role)
		fmt.Fprintf(&b, "  %s:\n    image: %s\n    mem_limit: %s\n    memswap_limit: %s\n    cpu_shares: 128\n    cpus: %s\n    restart: unless-stopped\n", name, image, limit, limit, k.CPULimit)
		// A writable /tmp, because the fleet's images are scratch or
		// distroless and run as an unprivileged uid.
		//
		// Their production compose files all mount a tmpfs here; the
		// preview mounted nothing, so the process saw the image's own /tmp
		// -- root-owned and 0755, because COPY of a directory copies its
		// CONTENTS and creates the destination fresh with default mode, so
		// a Dockerfile's `chmod 1777` on the source never arrives. cazper's
		// preview API crash-looped on exactly that, reported as "the store
		// is unreachable" because its error mapper refuses to put a
		// filesystem path in a log.
		//
		// mode=1777 EXPLICITLY. Docker's documented default for a tmpfs is
		// 1777, but only when the mountpoint does not say otherwise: it
		// INHERITS THE MODE OF THE DIRECTORY IN THE IMAGE. A scratch image
		// whose /tmp is 0755 root-owned -- which is what a Dockerfile's
		// `COPY --from=build /out/tmp /tmp` produces, because COPY of a
		// directory copies its contents and creates the destination fresh
		// -- gets a tmpfs that is still 0755 root-owned, and the
		// unprivileged uid still cannot write to it.
		//
		// Proven on the box: busybox with /tmp chmod 755, run as 65534,
		// gives "mkdir: can't create directory '/tmp/x': Permission
		// denied" with this flag absent and succeeds with it present.
		//
		// 1777 is /tmp's own convention, not a guess about the image, so
		// this still asks no product which user it runs as.
		b.WriteString("    tmpfs:\n      - /tmp:rw,noexec,nosuid,size=64m,mode=1777\n")
		if i == 0 {
			fmt.Fprintf(&b, "    container_name: %s-gate\n    environment:\n", r.Project)
			fmt.Fprintf(&b, "      PREVIEW: \"1\"\n      PR: \"%d\"\n", r.PR)

			fmt.Fprintf(&b, "      BASE_URL: https://%s%s\n      PREVIEW_HOST: %s\n      PREVIEW_API_HOST: %s\n      PREVIEW_BASE_PATH: %q\n", r.WebHost(k), r.BasePath, r.WebHost(k), r.PublicAPIHost(k), r.BasePath)
			// The gate port, LOOPBACK only: the direct HTTP entry to the
			// preview from the box itself, never from the network -- the
			// public way in is the proxy route, with TLS. Publishing on all
			// interfaces would put every preview one port-scan away from the
			// internet.
			b.WriteString("    ports:\n")
			fmt.Fprintf(&b, "      - \"127.0.0.1:%d:80\"\n", r.GatePort)
			b.WriteString("    networks:\n      - shared\n")
			if len(r.Images) > 1 {
				b.WriteString("      - backend\n")
			}
		} else if role != "" {
			b.WriteString("    read_only: true\n    cap_drop: [ALL]\n    security_opt: [no-new-privileges:true]\n    init: true\n    pids_limit: 128\n    networks:\n      - runtime\n")
		} else {
			fmt.Fprintf(&b, "    environment:\n      PREVIEW: \"1\"\n      PR: \"%d\"\n", r.PR)
			b.WriteString(previewDBEnvLines(r))
			if dbEndpoint != "" {
				fmt.Fprintf(&b, "      RUNTIME_DATABASE_URL: postgres://%s:%s@%s:5432/%s\n", r.DBName, r.DBPassword, dbEndpoint, r.DBName)
			}
			if stackEnv {
				b.WriteString("    env_file:\n      - stack.env\n")
			}
			b.WriteString("    networks:\n      - backend\n")
			if previewHasRuntime(r.Images) {
				b.WriteString("      - runtime\n")
			}
		}
	}
	// ONE network, the shared one, and never the app's <app>_default.
	//
	// Everything a preview has to reach is on it: the proxy finds the gate,
	// the gate finds the API, and the API finds komizo's preview postgres.
	// The app's own network was needed only while the preview's database
	// lived inside the app's postgres container, and joining a product's
	// production network to serve a pull request is the same invasiveness
	// in a different costume.
	//
	// It was also a hard failure for any product that has no such network.
	// A gate-only product's stack is a single container on the shared
	// network and compose creates no <app>_default at all, so every preview
	// of one died at:
	//
	//	network ctcalc_default declared as external, but could not be found
	fmt.Fprintf(&b, "networks:\n  shared:\n    external: true\n    name: %s\n", network)
	if len(r.Images) > 1 {
		fmt.Fprintf(&b, "  backend:\n    external: true\n    name: %s-backend\n", r.Project)
	}
	if previewHasRuntime(r.Images) {
		fmt.Fprintf(&b, "  runtime:\n    name: %s-runtime\n    internal: true\n", r.Project)
	}
	return b.String()
}

// previewRoute exposes the gate and, only for a multi-image stack, its API.
// Avoid issuing a second certificate for static, gate-only previews.
func previewRoute(r PreviewRecord, k PreviewKnob) string {
	hosts := r.WebHost(k)
	if len(r.Images) > 1 {
		hosts += ", " + r.PublicAPIHost(k)
	}
	return fmt.Sprintf(`# Written by komizo preview. %s PR #%d -- removed by 'komizo preview down'.
%s {
	reverse_proxy %s-gate:80
}
`, r.App, r.PR, hosts, r.Project)
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

// --- the database, inside komizo's own postgres server ---------------------------

// ensurePreviewDBReady proves komizo's own postgres server is up and taking
// connections before anything is created in it.
//
// This server belongs to komizo, not to any product. Previously a preview
// put its role and database inside THE APP'S production postgres container,
// discovered by inspecting the app's project -- which meant komizo reached
// into a product's running stack as superuser to serve a pull request. The
// containment was careful, but the blast radius was production's database
// server, and a product with no database could not have a preview at all:
//
//	no postgres container is running in ctcalc's project
//	-- a preview needs the app's database to put its own beside
//
// One server per host, on the shared network, is both narrower and more
// general: nothing of the app's is inspected, named or connected to, and a
// gate-only product needs no database to be previewable.
//
// Provisioning is komizo init's job (see scripts/alpine-init.sh). Here we
// only check, because a preview that creates infrastructure on demand is a
// preview that can leave a half-built host behind when it fails.
func ensurePreviewDBReady(ctx context.Context, run previewRun) error {
	out, err := run(ctx, "", "inspect", PreviewDBContainer, "--format", "{{.State.Running}}")
	if err != nil || strings.TrimSpace(out) != "true" {
		return fmt.Errorf("komizo's preview database server (%s) is not running -- run komizo init on this host to provision it", PreviewDBContainer)
	}
	// Running is not the same as accepting connections: the container comes
	// back before postgres finishes recovery, and a CREATE ROLE issued in
	// that window fails with a message about the socket rather than about
	// the preview. Ask postgres itself, briefly.
	var last error
	for i := 0; i < 30; i++ {
		if _, err := run(ctx, "", "exec", PreviewDBContainer, "pg_isready", "-U", PreviewDBSuperuser, "-d", PreviewDBMaintenance); err == nil {
			return nil
		} else {
			last = err
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("komizo's preview database server (%s) is running but never accepted connections: %w", PreviewDBContainer, last)
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
// dropPreviewDB removes ONE preview's database and role and nothing else.
// Both are named for the app and PR they belong to, so the name is the
// authorisation: no other preview, and nothing of the app's own, can answer
// to it.
//
// WITH (FORCE) because the state this has to clean up is precisely the one
// with connections still open -- an attempt that died between creating the
// database and bringing the project down leaves preview containers holding
// sessions, and a plain DROP DATABASE just reports that and leaves the
// database behind. That is how gdam_pr_158 became an orphan no re-run could
// get past.
func dropPreviewDB(ctx context.Context, run previewRun, container, user, db, name string) error {
	if name == "" {
		return nil
	}
	if _, err := run(ctx, "", "exec", container, "psql", "-U", user, "-d", db, "-c",
		"DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
		return fmt.Errorf("could not drop the preview database %s: %w", name, err)
	}
	// After its database is gone the role owns nothing, so this cannot fail
	// for dependency reasons.
	if err := previewSQL(ctx, run, container, user, db, "DROP ROLE IF EXISTS "+name+";"); err != nil {
		return fmt.Errorf("could not drop the preview role %s: %w", name, err)
	}
	return nil
}

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
	ReportPath string
}

// PreviewUp brings a preview up: validate, floors, evict if full, database,
// state, compose, route. Each step before the compose up leaves nothing
// behind on failure; the route is the last thing to change, and it carries
// its own restore.
var revikPreviewSeedPattern = regexp.MustCompile(`^[a-f0-9]{24}$`)

func PreviewUp(ctx context.Context, run previewRun, cfg PreviewUpConfig, app string, pr int, images []string, now time.Time) (result PreviewRecord, resultErr error) {
	var zero PreviewRecord
	ctx, releaseOperation, err := previewOperation(ctx, cfg.Root)
	if err != nil {
		return zero, err
	}
	defer releaseOperation()
	if cfg.ReportPath != "" {
		cfg.ReportJSON, err = os.ReadFile(cfg.ReportPath)
		if err != nil {
			return zero, fmt.Errorf("cannot read current capacity report: %w", err)
		}
		if err := previewReportFresh(cfg.ReportJSON, time.Now()); err != nil {
			return zero, err
		}
	}
	if cfg.Knob.InvalidBudget {
		return zero, fmt.Errorf("preview up refused: invalid capacity reservation")
	}
	_, err = previewMemoryBytes(cfg.Knob.MemLimit)
	if err != nil || !validPreviewCPU(cfg.Knob.CPULimit) {
		return zero, fmt.Errorf("preview up requires positive bounded memory and CPU limits")
	}
	target, err := ResolvePreview(cfg.Knob, app, pr, len(images) > 1)
	if err != nil {
		return zero, err
	}
	if len(images) == 0 || len(images) > 16 {
		return zero, fmt.Errorf("no images given -- a preview is images and nothing else")
	}
	for _, image := range images {
		if !onlyCharsPreview(image, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.:/_@=-") {
			return zero, fmt.Errorf("image %q contains characters that are not valid in an image reference", image)
		}
	}
	if app == "fieldsofrevik" {
		if err := validateRevikPreviewImages(images); err != nil {
			return zero, err
		}
		if err := validateRevikPreviewAuth(filepath.Join(previewDir(cfg.Root, PreviewProject(app, pr)), "stack.env")); err != nil {
			return zero, err
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
		Images:    images,
		CreatedAt: now, LastUsed: now,
		RouteFile: "_preview-" + project + ".caddy",
	}
	rec.MemoryReservedBytes, err = previewImagesMemoryReservation(cfg.Knob, app, images)
	if err != nil {
		return zero, err
	}
	rec.Host, rec.APIHost, rec.BasePath = target.Host, target.APIHost, target.BasePath
	if rec.BasePath != "" {
		rec.RouteFile = fmt.Sprintf("_preview-pr-%d.%s.route", pr, app)
	}
	// A gate-only product -- one static container, no API -- gets NO
	// database: nothing in it can open a connection, and a database created
	// for a preview that will never connect is the invasiveness this whole
	// change exists to remove. An empty DBName is also what tells teardown
	// there is nothing to drop.
	if len(images) > 1 && app != "fieldsofrevik" {
		rec.DBName = PreviewDBName(app, pr)
		// The password is generated NOW, before the state file is written,
		// so the record on disk carries it from the start -- a preview.env
		// without it is a preview that cannot be taken down cleanly.
		rec.DBPassword = previewNewPassword()
	}
	if app == "fieldsofrevik" {
		// A private seed, never exposed to containers or JSON. The profile
		// derives distinct role passwords; its database lives in its own
		// Compose volume, so DBName stays empty and shared DB cleanup is skipped.
		rec.DBPassword = previewNewPassword()
	}

	// ONE preview at a time on this host, for the window that reads the
	// other previews' ports and writes this one's.
	//
	// The gate port is chosen as "first free according to state", so two ups
	// running at once both read the same state, both pick the same number,
	// and the second container dies on
	//
	//	Bind for 127.0.0.1:20001 failed: port is already allocated
	//
	// which is what castledrop did when it and prizm deployed together.
	// Admission, eviction and port assignment must hold the same lock. Failure
	// to acquire it refuses up before any Docker, database or route mutation.
	unlock, err := lockPreviews(ctx, cfg.Root)
	if err != nil {
		return zero, err
	}
	defer unlock()

	// Evict BEFORE adding, so max-N is a ceiling and not a target to exceed
	// and come back under: the least-recently-used preview goes first.
	existing, err := ListPreviews(cfg.Root)
	if err != nil {
		return zero, err
	}
	if err := previewProductionReserve(cfg.Knob, cfg.ReportJSON); err != nil {
		return zero, err
	}
	if cfg.Knob.MemoryBudget > 0 {
		reserved := rec.MemoryReservedBytes
		for _, previous := range existing {
			if previous.Project == project {
				continue
			}
			if previous.MemoryReservedBytes <= 0 {
				return zero, fmt.Errorf("preview memory budget requires recorded reservations; drain or re-up legacy previews first")
			}
			if previous.MemoryReservedBytes > cfg.Knob.MemoryBudget || reserved > cfg.Knob.MemoryBudget-previous.MemoryReservedBytes {
				return zero, fmt.Errorf("preview up exceeds MEM_BUDGET; existing previews and production were preserved")
			}
			reserved += previous.MemoryReservedBytes
		}
		if reserved > cfg.Knob.MemoryBudget {
			return zero, fmt.Errorf("preview up exceeds MEM_BUDGET; existing previews and production were preserved")
		}
	}
	var have bool
	for _, e := range existing {
		if e.Project == project && e.BasePath != rec.BasePath {
			return zero, fmt.Errorf("remove this preview before changing between hostname and path routing")
		}
		if e.App == app && e.BasePath != "" && (e.Host != rec.Host || e.APIHost != rec.APIHost) {
			return zero, fmt.Errorf("drain the app's path previews before changing their hostnames")
		}
		if e.Project == project {
			have = true
			if app == "fieldsofrevik" {
				// Its private PostgreSQL volume survives a re-up. Credentials
				// initialized inside that volume must therefore survive too.
				// Shared-database previews recreate their role and keep their
				// existing fresh-password behavior.
				if e.App != app || e.PR != pr || !revikPreviewSeedPattern.MatchString(e.DBPassword) {
					return zero, fmt.Errorf("the existing private preview has no valid credential seed")
				}
				rec.DBPassword = e.DBPassword
			}
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
	// A RE-UP KEEPS ITS OWN PORT. Up is re-run constantly -- every push to
	// the PR -- and this preview's own record is in `existing`, so counting
	// it as taken moved the preview to a new port on every single push. That
	// is churn at best, and at worst it hands this preview the port another
	// one is already bound to.
	used := map[int]bool{}
	for _, e := range existing {
		if e.Project != project {
			used[e.GatePort] = true
		}
	}
	for _, e := range existing {
		if e.Project == project && e.GatePort >= lo && e.GatePort <= hi && !used[e.GatePort] {
			rec.GatePort = e.GatePort
		}
	}
	if rec.GatePort == 0 {
		for rec.GatePort = lo; rec.GatePort <= hi && used[rec.GatePort]; rec.GatePort++ {
		}
		if rec.GatePort > hi {
			return zero, fmt.Errorf("no free gate ports in %d-%d", lo, hi)
		}
	}

	// STATE FIRST. The record exists before anything is created, and
	// everything after this point rolls back BOTH -- a failure must never
	// leave resources without state (an orphan nothing can reap) or state
	// without resources (a record the reaper would chase forever). The
	// compose file is written after the read-only database discovery below
	// (it renders the discovered DB container's name and networks), still
	// before the first thing created.
	if err := writePreviewRecord(cfg.Root, rec); err != nil {
		return zero, err
	}
	composePath := filepath.Join(previewDir(cfg.Root, project), "compose.yml")
	// The OPTIONAL stack.env seam: the calling product may have pre-created
	// the state directory and written stack.env (0600, root) BEFORE up. Up
	// never creates, writes or reads that file -- writePreviewRecord's
	// MkdirAll leaves a pre-existing directory and its contents untouched --
	// and only its EXISTENCE is asked, so the compose render can reference
	// the path without the contents ever passing through komizo.
	_, stackEnvErr := os.Stat(filepath.Join(previewDir(cfg.Root, project), "stack.env"))
	defer func() {
		if resultErr != nil {
			if cleanupErr := PreviewDown(ctx, run, cfg, rec); cleanupErr != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("preview cleanup incomplete; state retained for retry: %w", cleanupErr))
			}
		}
	}()

	// The database, before anything runs: a new role and database named for
	// the PR, in KOMIZO'S OWN postgres, and nothing of the app's touched.
	//
	// Only when something other than the gate is going to ask for one. A
	// gate-only product is a single static container with nothing to
	// connect, and creating a database it will never open is exactly the
	// kind of thing this change exists to stop doing.
	needsDB := rec.DBName != ""
	dbEndpoint := ""
	if app != "fieldsofrevik" && len(images) > 1 {
		if err := ensurePreviewBackend(ctx, run, project, needsDB); err != nil {
			return zero, err
		}
	}
	if needsDB {
		if err := ensurePreviewDBReady(ctx, run); err != nil {
			return zero, err
		}
		dbEndpoint = PreviewDBContainer
		// Reclaim this preview's OWN leftovers before creating them. Up is
		// re-run constantly -- a new push to the PR, a re-run of a job that
		// went red for an unrelated reason -- and an attempt that failed
		// after the database existed used to poison every attempt after it:
		// "database gdam_pr_158 already exists", with nothing an operator
		// could do about it from CI. Only this app's and this PR's names are
		// touched.
		if err := dropPreviewDB(ctx, run, PreviewDBContainer, PreviewDBSuperuser, PreviewDBMaintenance, rec.DBName); err != nil {
			return zero, fmt.Errorf("could not reclaim a leftover preview database in %s: %w", PreviewDBContainer, err)
		}
		if err := previewSQL(ctx, run, PreviewDBContainer, PreviewDBSuperuser, PreviewDBMaintenance,
			"CREATE ROLE "+rec.DBName+" LOGIN PASSWORD :'pw';",
			"-v", "pw="+rec.DBPassword); err != nil {
			return zero, fmt.Errorf("could not create the preview role %s in %s: %w", rec.DBName, PreviewDBContainer, err)
		}
		if _, err := run(ctx, "", "exec", PreviewDBContainer, "psql", "-U", PreviewDBSuperuser, "-d", PreviewDBMaintenance, "-c",
			"CREATE DATABASE "+rec.DBName+" OWNER "+rec.DBName); err != nil {
			return zero, fmt.Errorf("could not create the preview database %s in %s: %w", rec.DBName, PreviewDBContainer, err)
		}
		// Every preview shares one server now, so "its own database" has to
		// mean something postgres enforces. By default CONNECT on a new
		// database is granted to PUBLIC -- which is every other preview's
		// role on this server. Revoke it and grant it back to the owner
		// alone, so a preview authenticating as itself can reach its own
		// database and no other.
		if err := previewSQL(ctx, run, PreviewDBContainer, PreviewDBSuperuser, PreviewDBMaintenance,
			"REVOKE CONNECT ON DATABASE "+rec.DBName+" FROM PUBLIC;\n"+
				"GRANT CONNECT ON DATABASE "+rec.DBName+" TO "+rec.DBName+";"); err != nil {
			return zero, fmt.Errorf("could not isolate the preview database %s from the other previews on %s: %w", rec.DBName, PreviewDBContainer, err)
		}
	}

	// The API reaches the preview database through its private backend.
	// Only its gateway joins the shared ingress network.
	// Compose cannot rename a service while preserving its explicit container
	// name: it tries to create the new service before removing the old orphan.
	// Stop/remove only this preview's legacy gate, without volumes, using its
	// previous Compose file before replacing it. Routes still name the same container.
	if prior, readErr := os.ReadFile(composePath); readErr == nil && strings.Contains(string(prior), "\n  gate:\n") {
		if _, err := run(ctx, "", "compose", "-p", project, "-f", composePath, "rm", "-s", "-f", "gate"); err != nil {
			return zero, fmt.Errorf("migrating this preview's gate alias: %w", err)
		}
	}
	ingress, err := ensurePreviewIngress(ctx, run, project, cfg.Proxy)
	if err != nil {
		return zero, err
	}
	body := previewCompose(rec, cfg.Knob, ingress, stackEnvErr == nil, dbEndpoint)
	if info, err := os.Lstat(filepath.Join(cfg.Root, "/etc/komizo/resources.json")); err == nil && info.Mode().IsRegular() {
		body = strings.ReplaceAll(body, "    restart: unless-stopped\n", "    cgroup_parent: /komizo-previews\n    restart: unless-stopped\n")
		body = strings.Replace(body, "\n  restart: unless-stopped\n", "\n  cgroup_parent: /komizo-previews\n  restart: unless-stopped\n", 1)
	}
	if err := os.WriteFile(composePath, []byte(body), 0o600); err != nil {
		return zero, err
	}

	if _, err := run(ctx, "", "compose", "-p", project, "-f", composePath, "up", "-d", "--remove-orphans"); err != nil {
		return zero, fmt.Errorf("the preview project did not come up: %w", err)
	}
	if err := applyPreviewRecordRoute(ctx, run, cfg, rec); err != nil {
		return zero, err
	}
	return rec, nil
}

// PreviewDown takes a preview down, exactly: project down, ITS database
// dropped, ITS route removed with the validate discipline, ITS state
// directory gone. Nothing else is named.
func PreviewDown(ctx context.Context, run previewRun, cfg PreviewUpConfig, rec PreviewRecord) error {
	ctx, release, err := previewOperation(ctx, cfg.Root)
	if err != nil {
		return err
	}
	defer release()
	composeFile := filepath.Join(previewDir(cfg.Root, rec.Project), "compose.yml")
	if _, err := run(ctx, "", "compose", "-p", rec.Project, "-f", composeFile, "down", "-v"); err != nil {
		// A missing project is already down; anything else is reported.
		if _, statErr := os.Stat(composeFile); statErr == nil {
			return fmt.Errorf("could not take the preview project down: %w", err)
		}
	}
	// A stopped shared database still retains its volume. Keep the cleanup
	// record until its role and database can actually be removed.
	if rec.DBName != "" {
		out, err := run(ctx, "", "inspect", PreviewDBContainer, "--format", "{{.State.Running}}")
		if err != nil || strings.TrimSpace(out) != "true" {
			return fmt.Errorf("preview database cleanup pending: shared server unavailable")
		}
		if err := dropPreviewDB(ctx, run, PreviewDBContainer, PreviewDBSuperuser, PreviewDBMaintenance, rec.DBName); err != nil {
			return err
		}
	}
	if err := RemovePreviewRoute(ctx, run, cfg.Proxy, cfg.RoutesDir, rec.RouteFile); err != nil {
		return err
	}
	if err := removePreviewIngress(ctx, run, rec.Project, cfg.Proxy); err != nil {
		return err
	}
	if rec.App != "fieldsofrevik" && len(rec.Images) > 1 {
		if err := removePreviewBackend(ctx, run, rec.Project, rec.DBName != ""); err != nil {
			return err
		}
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
	ctx, release, err := previewOperation(ctx, cfg.Root)
	if err != nil {
		return reap, err
	}
	defer release()
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

// lockPreviews serialises the allocate-and-record window of `preview up`
// across concurrent invocations on one host.
//
// Same discipline as lockRecord: /run, because a lock's correct lifetime is
// until reboot and a record's is not. A lock failure refuses the operation;
// running without exclusion would make both admission and port allocation false.
func lockPreviews(ctx context.Context, root string) (func(), error) {
	return lockHostFile(ctx, root, "previews.lock")
}

func lockHostFile(ctx context.Context, root, name string) (func(), error) {
	directory := RunDir
	if root != "" {
		directory = filepath.Join(root, "run")
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return nil, fmt.Errorf("preview lock directory unavailable: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(directory, name), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("preview lock unavailable: %w", err)
	}
	deadline := time.Now().Add(previewLockWait)
	for {
		if flockExclusiveNB(f.Fd()) {
			return func() {
				flockUnlock(f.Fd())
				_ = f.Close()
			}, nil
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("preview lock timed out; no preview mutation performed")
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// previewLockWait is longer than a record rewrite's because the window it
// guards includes an eviction, which takes a whole preview down.
const previewLockWait = 60 * time.Second
