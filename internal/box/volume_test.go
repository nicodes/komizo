package box

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A box with two apps, whose containers mount volumes the way compose reports
// them: one shared between two containers of the same app, one per app.
func volumeBox(t *testing.T) *fakeBox {
	f := newFakeBox(t)
	f.write("/var/lib/komizo/apps/blog.env", "APP_DIR=/srv/blog\n")
	f.write("/var/lib/komizo/apps/shop.env", "APP_DIR=/srv/shop\n")
	f.reply("info", "29.1.3").
		reply("--version", "Docker version 29.1.3").
		reply("ps -a --no-trunc", ps(
			"c1\tblog-api-1\trunning\tUp\tapi\timg\t/srv/blog",
			"c2\tblog-worker-1\trunning\tUp\tworker\timg\t/srv/blog",
			"c3\tshop-db-1\trunning\tUp\tdb\timg\t/srv/shop")).
		reply("inspect --format {{.Id}}", inspect(
			"c1\t2026-08-02T09:00:00Z\t0001-01-01T00:00:00Z\t0\t1\t\tblog_data=/v/blog_data ",
			"c2\t2026-08-02T09:00:00Z\t0001-01-01T00:00:00Z\t0\t2\t\tblog_data=/v/blog_data ",
			"c3\t2026-08-02T09:00:00Z\t0001-01-01T00:00:00Z\t0\t3\t\tshop_db=/v/shop_db "))
	return f
}

// fill writes n files of size bytes each under dir, and returns the directory.
func fill(t *testing.T, dir string, n, size int) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range n {
		p := filepath.Join(dir, string(rune('a'+i)))
		if err := os.WriteFile(p, make([]byte, size), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A volume shared by two containers is measured ONCE and attributed to both.
//
// Both halves matter. Walking it twice would double what is a slow measurement
// to begin with; counting it twice would tell somebody their app is using twice
// the disk it is, which is the kind of number that ends trust in the page.
func TestASharedVolumeIsWalkedOnceAndAttributedTwice(t *testing.T) {
	f := volumeBox(t)
	fill(t, filepath.Join(f.root, "/v/blog_data"), 4, 8192)
	fill(t, filepath.Join(f.root, "/v/shop_db"), 1, 8192)

	got := f.probe().Volumes(context.Background(), "")
	if len(got) != 3 {
		t.Fatalf("volumes = %+v, want 3 rows", got)
	}
	// Sorted, so this is blog/api, blog/worker, shop/db.
	if got[0].App != "blog" || got[0].Service != "api" || got[1].Service != "worker" {
		t.Fatalf("attribution = %+v", got)
	}
	if got[0].Bytes != got[1].Bytes {
		t.Errorf("the same volume measured twice differently: %d vs %d", got[0].Bytes, got[1].Bytes)
	}
	if got[0].Bytes < 4*8192 {
		t.Errorf("blog_data = %d bytes, want at least %d", got[0].Bytes, 4*8192)
	}
	if got[2].App != "shop" || got[2].Bytes >= got[0].Bytes {
		t.Errorf("shop should be the smaller one: %+v", got)
	}
}

func TestVolumesCanBeAskedForOneApp(t *testing.T) {
	f := volumeBox(t)
	fill(t, filepath.Join(f.root, "/v/blog_data"), 1, 4096)
	fill(t, filepath.Join(f.root, "/v/shop_db"), 1, 4096)

	got := f.probe().Volumes(context.Background(), "shop")
	if len(got) != 1 || got[0].App != "shop" {
		t.Errorf("volumes = %+v, want shop's only", got)
	}
}

// A volume whose host directory is gone reports nothing rather than zero.
//
// Zero is a measurement -- one saying the volume is empty -- and an empty
// volume and an unreadable one are different problems.
func TestAnUnreadableVolumeIsAbsentRatherThanZero(t *testing.T) {
	f := volumeBox(t)
	fill(t, filepath.Join(f.root, "/v/shop_db"), 1, 4096)
	// blog_data is never created.
	got := f.probe().Volumes(context.Background(), "")
	for _, v := range got {
		if v.Name == "blog_data" {
			t.Errorf("an unreadable volume was reported: %+v", v)
		}
	}
	if len(got) != 1 || got[0].Name != "shop_db" {
		t.Errorf("volumes = %+v, want shop_db only", got)
	}
}

// du counts a hard-linked file once. A tree of linked backups would otherwise
// report several times the space it actually costs.
func TestHardLinksAreCountedOnce(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, "a")
	if err := os.WriteFile(orig, make([]byte, 64<<10), 0o644); err != nil {
		t.Fatal(err)
	}
	before, ok := dirBytes(dir)
	if !ok {
		t.Fatal("could not measure the directory")
	}
	for i := range 5 {
		if err := os.Link(orig, filepath.Join(dir, "link"+string(rune('a'+i)))); err != nil {
			t.Skipf("hard links are not available here: %v", err)
		}
	}
	after, ok := dirBytes(dir)
	if !ok {
		t.Fatal("could not measure the directory")
	}
	if after != before {
		t.Errorf("five hard links changed the measurement: %d -> %d", before, after)
	}
}

// Blocks, not apparent size. A sparse file occupies almost nothing, and a
// volume that reads as larger than the disk holding it is the kind of number
// that makes somebody stop trusting the whole page.
func TestSparseFilesAreMeasuredByWhatTheyOccupy(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "sparse"))
	if err != nil {
		t.Fatal(err)
	}
	// A gigabyte of nothing.
	if err := f.Truncate(1 << 30); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()

	got, ok := dirBytes(dir)
	if !ok {
		t.Fatal("could not measure the directory")
	}
	if got > 1<<20 {
		t.Errorf("a sparse gigabyte measured %d bytes -- apparent size, not blocks", got)
	}
}

func TestMissingDirectoryIsNotAMeasurement(t *testing.T) {
	if _, ok := dirBytes(filepath.Join(t.TempDir(), "nope")); ok {
		t.Error("a directory that is not there should report no measurement")
	}
}
