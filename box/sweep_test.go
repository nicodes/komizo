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

// The sweep runs as root on somebody's production box, so its contract is
// pinned here as refusals first and removal second. The four things that must
// NEVER be swept -- a tagged image, a container-referenced image, a volume,
// an image named in state -- each get their own test, because each protects a
// different outage.

var sweepNow = time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)

func sweepDays(n int) time.Time { return sweepNow.Add(-time.Duration(n) * 24 * time.Hour) }

func sweepCfg() SweepKnob {
	return SweepKnob{MinAge: SweepMinAgeDefault, Interval: SweepIntervalDefault}
}

// removed records what the fake remove was asked for.
type removed struct{ ids []string }

func (r *removed) fn(errOn ...string) func(id string) error {
	return func(id string) error {
		for _, e := range errOn {
			if id == e {
				return fmt.Errorf("cannot remove: still referenced")
			}
		}
		r.ids = append(r.ids, id)
		return nil
	}
}

func danglingOld(id string, days int) SweepImage {
	return SweepImage{ID: id, Repo: "<none>", Tag: "<none>", Created: sweepDays(days), SizeBytes: 1000}
}

// A TAGGED image is never swept, however old -- the deploy composite's
// self-prune owns product images, and a rollback target that disappeared
// under a deploy is the incident this entire shape exists to prevent.
func TestTheSweepNeverRemovesATaggedImage(t *testing.T) {
	rm := &removed{}
	rec := Sweep(sweepCfg(), sweepNow,
		[]SweepImage{
			{ID: "sha256:tagged", Repo: "ghcr.io/you/blog", Tag: "v1", Created: sweepDays(60), SizeBytes: 500},
			danglingOld("sha256:dangling", 30),
		},
		map[string]bool{}, nil, rm.fn())

	for _, id := range rm.ids {
		if id == "sha256:tagged" {
			t.Fatal("a tagged image was swept")
		}
	}
	if rec.Removed != 1 || rm.ids[0] != "sha256:dangling" {
		t.Errorf("removed %v (%d) -- only the dangling image should go", rm.ids, rec.Removed)
	}
}

// A container-referenced image is never swept, running OR stopped -- matched
// by ID (the dangling case, where the container shows the sha) and by name.
func TestTheSweepNeverRemovesWhatAContainerReferences(t *testing.T) {
	rm := &removed{}
	rec := Sweep(sweepCfg(), sweepNow,
		[]SweepImage{
			danglingOld("sha256:referenced-by-id", 30),
			{ID: "sha256:referenced-by-name", Repo: "<none>", Tag: "<none>", Created: sweepDays(30), SizeBytes: 1000},
			danglingOld("sha256:free", 30),
		},
		map[string]bool{
			"sha256:referenced-by-id":   true,
			"<none>:<none>":             false, // guard: a literal non-match does not shield anything
			"sha256:referenced-by-name": true,
		},
		nil, rm.fn())

	for _, id := range rm.ids {
		if strings.Contains(id, "referenced") {
			t.Fatalf("a container-referenced image was swept: %s", id)
		}
	}
	if rec.Removed != 1 || rm.ids[0] != "sha256:free" {
		t.Errorf("removed %v -- only the unreferenced dangling image should go", rm.ids)
	}
	if rec.Skipped != 2 {
		t.Errorf("skipped %d, want the two referenced images kept on the record", rec.Skipped)
	}
}

// A VOLUME is never swept because nothing in the sweep can address one: the
// production path's argv is pinned to images, ps and image rm. This is the
// test that would catch a "while you're in there, prune the volumes too".
func TestTheSweepNeverNamesAVolume(t *testing.T) {
	var argv [][]string
	run := func(ctx context.Context, args ...string) (string, error) {
		argv = append(argv, args)
		switch args[0] {
		case "images":
			return "sha256:dangling\t<none>\t<none>\t" + sweepDays(30).Format("2006-01-02 15:04:05 -0700 MST") + "\t1000\n", nil
		case "ps":
			return "", nil
		default:
			return "", nil
		}
	}
	rec := DockerSweep(context.Background(), sweepCfg(), t.TempDir(), t.TempDir(), sweepNow, run)
	if rec.Removed != 1 {
		t.Fatalf("the fixture dangling image was not swept: %+v", rec)
	}
	for _, args := range argv {
		for _, a := range args {
			if a == "volume" || a == "system" || a == "container" || a == "builder" {
				t.Fatalf("the sweep invoked docker %v -- it only ever lists images, lists containers and removes image IDs", args)
			}
		}
	}
}

// An image named in state or config the box reads is never swept, even
// dangling and old: the name check is the belt over the tag check's braces.
func TestTheSweepNeverRemovesWhatStateNames(t *testing.T) {
	rm := &removed{}
	rec := Sweep(sweepCfg(), sweepNow,
		[]SweepImage{
			{ID: "sha256:has-a-name", Repo: "ghcr.io/you/blog", Tag: "", Created: sweepDays(30), SizeBytes: 1000},
		},
		map[string]bool{},
		[]string{"APP_NAME=blog\nCONFIG_IMAGE=ghcr.io/you/blog\n", "services: {}\n"},
		rm.fn())

	if len(rm.ids) != 0 {
		t.Fatalf("an image named in state was swept: %v", rm.ids)
	}
	if rec.Removed != 0 || rec.Skipped != 1 {
		t.Errorf("record = %+v, want one skipped, nothing removed", rec)
	}
}

// The sweep itself: only dangling, old, unreferenced images go, the young
// stay, and the record says what happened and how much came back.
func TestTheSweepRemovesOnlyDanglingOldUnreferenced(t *testing.T) {
	rm := &removed{}
	rec := Sweep(sweepCfg(), sweepNow,
		[]SweepImage{
			danglingOld("sha256:old-1", 30),
			danglingOld("sha256:old-2", 8),
			danglingOld("sha256:young", 2),
		},
		map[string]bool{}, nil, rm.fn("sha256:old-2"))

	if rec.Removed != 1 || rec.Candidates != 2 || rec.Skipped != 1 {
		t.Errorf("record = %+v, want 2 candidates, 1 removed, 1 skipped (docker refused)", rec)
	}
	if rec.ReclaimedBytes != 1000 {
		t.Errorf("reclaimed %d, want the removed image's size", rec.ReclaimedBytes)
	}
	if !strings.Contains(rec.Note, "refused") {
		t.Errorf("the refusal docker gave is not on the record: %q", rec.Note)
	}
}

// A quiet pass is a quiet LINE, not silence: the record distinguishes "ran
// and found nothing" from "never ran".
func TestAQuietSweepSaysSo(t *testing.T) {
	rec := Sweep(sweepCfg(), sweepNow, nil, map[string]bool{}, nil, (&removed{}).fn())
	if rec.Note != "nothing to sweep" {
		t.Errorf("note = %q, want the quiet line", rec.Note)
	}
	if rec.Removed != 0 {
		t.Errorf("a quiet sweep removed %d", rec.Removed)
	}
}

// The knob: defaults when absent, values when written, non-numeric values
// fall back per-key with a loud note, and DISABLED short-circuits the pass
// with a note of its own.
func TestTheSweepKnob(t *testing.T) {
	knob, note := ParseSweepKnob("")
	if knob.MinAge != SweepMinAgeDefault || knob.Interval != SweepIntervalDefault || note != "" {
		t.Errorf("empty knob = %+v, %q, want pure defaults", knob, note)
	}

	knob, note = ParseSweepKnob("MIN_AGE_DAYS=14\nINTERVAL_HOURS=12\n")
	if knob.MinAge != 14*24*time.Hour || knob.Interval != 12*time.Hour || note != "" {
		t.Errorf("written knob = %+v, %q", knob, note)
	}

	knob, note = ParseSweepKnob("MIN_AGE_DAYS=soon\n")
	if knob.MinAge != SweepMinAgeDefault || !strings.Contains(note, "soon") {
		t.Errorf("non-numeric knob = %+v, %q, want the default and the note naming the value", knob, note)
	}

	knob, _ = ParseSweepKnob("DISABLED=1\n")
	rec := Sweep(knob, sweepNow,
		[]SweepImage{danglingOld("sha256:old", 30)}, map[string]bool{}, nil, (&removed{}).fn())
	if rec.Removed != 0 || !strings.Contains(rec.Note, "disabled") {
		t.Errorf("a disabled sweep = %+v", rec)
	}
}

// The record round-trips through the file the probe reads.
func TestTheSweepRecordRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sweep.json")
	want := SweepRecord{V: 1, At: sweepNow, MinAgeDays: 7, Candidates: 2, Removed: 1, ReclaimedBytes: 1000, Note: "kept one"}
	if err := WriteSweepRecord(path, want); err != nil {
		t.Fatal(err)
	}
	got, ok := ReadSweepRecord(path)
	if !ok {
		t.Fatal("the record did not read back")
	}
	if got.Removed != want.Removed || got.ReclaimedBytes != want.ReclaimedBytes || got.Note != want.Note {
		t.Errorf("read back %+v, wrote %+v", got, want)
	}
	if _, ok := ReadSweepRecord(filepath.Join(t.TempDir(), "absent.json")); ok {
		t.Error("an absent record read as present")
	}
}

// stateImageNames reads every byte of the state and config the check greps --
// asserted because a glob that stops matching turns the named-in-state
// refusal off silently.
func TestStateImageNamesReadsTheRecords(t *testing.T) {
	apps := t.TempDir()
	srv := t.TempDir()
	if err := os.WriteFile(filepath.Join(apps, "blog.env"), []byte("CONFIG_IMAGE=ghcr.io/you/blog\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(srv, "blog"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srv, "blog", "compose.yml"), []byte("image: x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	names := stateImageNames(apps, srv)
	if len(names) != 2 || !strings.Contains(names[0]+names[1], "ghcr.io/you/blog") {
		t.Errorf("stateImageNames = %v, want both files' bytes", names)
	}
}

// The listing parsers, against docker's own shapes.
func TestTheSweepParsers(t *testing.T) {
	images := parseImages("sha256:aaa\t<none>\t<none>\t2026-09-01 12:00:00 +0000 UTC\t1000\n" +
		"sha256:bbb\tghcr.io/you/blog\tv1\t2026-09-20 12:00:00 +0000 UTC\t2000\n")
	if len(images) != 2 || images[0].Repo != "<none>" || images[1].Tag != "v1" || images[1].SizeBytes != 2000 {
		t.Errorf("parseImages = %+v", images)
	}
	refs := parseRefs("sha256:aaa\nghcr.io/you/blog:v1\n\n")
	if !refs["sha256:aaa"] || !refs["ghcr.io/you/blog:v1"] || len(refs) != 2 {
		t.Errorf("parseRefs = %+v", refs)
	}
}
