package box

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Conservative disk hygiene for rootd, born of a deploy that started at ~114MB
// free and died at 0.
//
// What this removes: DANGLING images -- untagged, unreferenced layers -- older
// than the floor age, and nothing else. Docker accretes one per build, and on
// a box that deploys daily they are the difference between a disk that holds
// and a disk that fills.
//
// What this NEVER removes, in order of how much it matters that the order is
// kept:
//
//	TAGGED images. The deploy composite's self-prune owns product images; a
//	second pruner deciding which tagged images may go is how a rollback target
//	disappears. The tag check is a REFUSAL, not a filter, so it cannot be
//	lost to a change in how candidates are listed.
//
//	Container-referenced images, running OR stopped. A stopped container is a
//	restart away, and its image is the restart. docker image rm also refuses
//	these, which is the last line of defense rather than the first.
//
//	VOLUMES. There is no code path here that names one: the sweep lists
//	images, lists containers, and removes image IDs. A volume cannot be swept
//	because nothing in this file can address one.
//
//	Images referenced BY NAME in state or config the box reads -- the app
//	records and the compose files. A deploy image komizo knows about by name
//	is not garbage even if every container has moved on.

// SweepMinAgeDefault and SweepIntervalDefault are the conservative knobs when
// the operator has written none.
const (
	SweepMinAgeDefault   = 7 * 24 * time.Hour
	SweepIntervalDefault = 24 * time.Hour
)

// SweepKnobPath is where the operator tunes the sweep. Komizo never creates
// it, like the deploy floors: defaults above are the conservative answer, and
// the file only ever makes the sweep GENTLER in cadence or stricter in age --
// there is no key that widens what may be removed.
const SweepKnobPath = "/etc/komizo/disk-sweep"

// SweepKnob is the parsed knob file.
type SweepKnob struct {
	MinAge   time.Duration
	Interval time.Duration
	Disabled bool
}

// ParseSweepKnob reads the key=value knob. A missing file is the defaults; a
// non-numeric value is that KEY's default with a loud note in the record --
// this is hygiene, so a bad knob must not stop the report, but it must not be
// quiet either.
func ParseSweepKnob(body string) (knob SweepKnob, note string) {
	knob = SweepKnob{MinAge: SweepMinAgeDefault, Interval: SweepIntervalDefault}
	get := func(key string) string {
		for _, ln := range strings.Split(body, "\n") {
			if v, ok := strings.CutPrefix(ln, key+"="); ok {
				return strings.Trim(v, "\r \t")
			}
		}
		return ""
	}
	var bad []string
	if v := get("MIN_AGE_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			knob.MinAge = time.Duration(n) * 24 * time.Hour
		} else {
			bad = append(bad, "MIN_AGE_DAYS="+v)
		}
	}
	if v := get("INTERVAL_HOURS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			knob.Interval = time.Duration(n) * time.Hour
		} else {
			bad = append(bad, "INTERVAL_HOURS="+v)
		}
	}
	knob.Disabled = get("DISABLED") == "1"
	if len(bad) > 0 {
		note = "ignoring non-numeric knob values, using defaults for them: " + strings.Join(bad, ", ")
	}
	return knob, note
}

// SweepImage is one image as the sweep needs to know it.
type SweepImage struct {
	ID        string
	Repo      string
	Tag       string
	Created   time.Time
	SizeBytes int64
}

// SweepRecord is what a pass did, written where the serving account and the
// probe can read it -- the report surface, so `komizo ui` shows the sweep the
// same way it shows everything else the box did.
type SweepRecord struct {
	V              int       `json:"v"`
	At             time.Time `json:"at"`
	MinAgeDays     int       `json:"min_age_days"`
	Candidates     int       `json:"candidates"`
	Removed        int       `json:"removed"`
	Skipped        int       `json:"skipped"`
	ReclaimedBytes int64     `json:"reclaimed_bytes"`
	// Note is the quiet line: nothing swept, what the knob said, what a remove
	// refused. A sweep that did nothing says so, rather than being
	// indistinguishable from a sweep that never ran.
	Note string `json:"note,omitempty"`
}

func (r SweepRecord) Schema() int { return r.V }

// SweepPath is where the record lives, beside the history and metrics the
// serving account already reads.
func SweepPath() string { return ServedDir + "/sweep.json" }

// Sweep is one pass, with every effect injected so a test drives it with
// fakes: the images, the container references, the state names, and the
// remove. The DOCKER wiring below calls this; the refusals live here and
// nowhere else, so the contract tests pin the function that ships.
func Sweep(cfg SweepKnob, now time.Time, images []SweepImage, refs map[string]bool, stateNames []string, remove func(id string) error) SweepRecord {
	rec := SweepRecord{V: 1, At: now, MinAgeDays: int(cfg.MinAge / (24 * time.Hour))}
	if cfg.Disabled {
		rec.Note = "sweep disabled by " + SweepKnobPath
		return rec
	}
	inState := func(repo, tag string) bool {
		if repo == "" || repo == "<none>" {
			return false
		}
		// A name is repo:tag when there is a tag, the bare repo when there is
		// not -- an image pulled by digest has no tag, and the state file
		// still names it.
		name := repo
		if tag != "" && tag != "<none>" {
			name = repo + ":" + tag
		}
		for _, s := range stateNames {
			if strings.Contains(s, name) {
				return true
			}
		}
		return false
	}
	for _, img := range images {
		// The refusals, each a named sentence in case of doubt:
		//
		// TAGGED. Whatever the listing offered, the sweep's answer to a tag is
		// no. This is the refusal the deploy composite's self-prune depends on
		// being somebody else's job.
		if img.Tag != "" && img.Tag != "<none>" {
			continue
		}
		// REFERENCED by a container, running or stopped -- matched on the ID
		// and on the name the container was created from.
		if refs[img.ID] || (img.Repo != "" && img.Repo != "<none>" && refs[img.Repo+":"+img.Tag]) {
			rec.Skipped++
			continue
		}
		// NAMED in state or config the box reads.
		if inState(img.Repo, img.Tag) {
			rec.Skipped++
			continue
		}
		// YOUNG. The floor age exists so a layer something just stopped using
		// gets a week to be wanted again before it is called garbage.
		if now.Sub(img.Created) < cfg.MinAge {
			continue
		}
		rec.Candidates++
		if err := remove(img.ID); err != nil {
			rec.Skipped++
			rec.Note = joinNote(rec.Note, fmt.Sprintf("docker refused to remove %.12s (kept): %v", img.ID, err))
			continue
		}
		rec.Removed++
		rec.ReclaimedBytes += img.SizeBytes
	}
	if rec.Removed == 0 && rec.Note == "" {
		rec.Note = "nothing to sweep"
	}
	return rec
}

func joinNote(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

// --- the docker wiring -------------------------------------------------------

// parseImages reads `docker images --no-trunc --format` output, fields
// tab-separated as ID, repository, tag, created-at, size-in-bytes.
func parseImages(out string) []SweepImage {
	var images []SweepImage
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimRight(ln, "\r"), "\t")
		if len(f) < 5 || f[0] == "" {
			continue
		}
		created, err := time.Parse("2006-01-02 15:04:05 -0700 MST", f[3])
		if err != nil {
			continue
		}
		size, err := strconv.ParseInt(f[4], 10, 64)
		if err != nil {
			continue
		}
		images = append(images, SweepImage{ID: f[0], Repo: f[1], Tag: f[2], Created: created, SizeBytes: size})
	}
	return images
}

// parseRefs reads `docker ps -a --no-trunc --format {{.Image}}` output into
// the set of referenced image strings. A container shows the image as it was
// created from it -- the sha256 ID when the tag has moved or gone, which is
// exactly the dangling case.
func parseRefs(out string) map[string]bool {
	refs := map[string]bool{}
	for _, ln := range strings.Split(out, "\n") {
		if v := strings.TrimSpace(ln); v != "" {
			refs[v] = true
		}
	}
	return refs
}

// stateImageNames is every byte of the state and config the box reads that
// could name an image: the app records and the compose files. Grep-shaped
// rather than parsed -- the question is "does this name appear", and a parse
// that answers it differently per file is four chances to miss one.
func stateImageNames(appsDir, srvDir string) []string {
	var names []string
	for _, glob := range []string{filepath.Join(appsDir, "*.env"), filepath.Join(srvDir, "*", "compose.yml")} {
		files, _ := filepath.Glob(glob)
		for _, f := range files {
			if b, err := os.ReadFile(f); err == nil {
				names = append(names, string(b))
			}
		}
	}
	return names
}

// DockerSweep is the production path: one docker to ask, one to remove with.
// It only ever invokes "images", "ps" and "image rm" -- the contract test
// pins the argv, because "never touches a volume" is a claim about exactly
// this list.
func DockerSweep(ctx context.Context, cfg SweepKnob, appsDir, srvDir string, now time.Time, run func(ctx context.Context, args ...string) (string, error)) SweepRecord {
	out, err := run(ctx, "images", "--no-trunc", "--format",
		"{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.CreatedAt}}\t{{.Size}}")
	if err != nil {
		return SweepRecord{V: 1, At: now, MinAgeDays: int(cfg.MinAge / (24 * time.Hour)), Note: "could not list images (kept everything): " + err.Error()}
	}
	refs, err := run(ctx, "ps", "-a", "--no-trunc", "--format", "{{.Image}}")
	if err != nil {
		return SweepRecord{V: 1, At: now, MinAgeDays: int(cfg.MinAge / (24 * time.Hour)), Note: "could not list containers (kept everything): " + err.Error()}
	}
	return Sweep(cfg, now, parseImages(out), parseRefs(refs), stateImageNames(appsDir, srvDir),
		func(id string) error {
			_, err := run(ctx, "image", "rm", id)
			return err
		})
}

// ReadSweepKnob reads the knob file, treating a missing one as the defaults
// and an unreadable one as defaults-with-a-note -- a hygiene knob must never
// stop the report, and must never be quiet about being wrong either.
func ReadSweepKnob(path string) (SweepKnob, string) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			knob, _ := ParseSweepKnob("")
			return knob, ""
		}
		knob, _ := ParseSweepKnob("")
		return knob, "could not read " + path + ", using defaults: " + err.Error()
	}
	return ParseSweepKnob(string(b))
}

// WriteSweepRecord leaves the record where the probe and the serving account
// read it.
func WriteSweepRecord(path string, r SweepRecord) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// ReadSweepRecord reads it back; absent is not an error, it is a box that has
// never swept.
func ReadSweepRecord(path string) (SweepRecord, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return SweepRecord{}, false
	}
	var r SweepRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return SweepRecord{}, false
	}
	return r, true
}
