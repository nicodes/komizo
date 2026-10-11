package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/nicodes/komizo/internal/workload"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestImmutableImageConfigurationMemoization(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "cache")
	image := "sha256:" + strings.Repeat("a", 64)
	digest := "sha256:" + strings.Repeat("b", 64)
	calls := 0
	owner := func(os.FileInfo) bool { return true }
	space := func(string) bool { return true }
	export := func(context.Context, string) (string, error) { calls++; return digest, nil }
	for i := 0; i < 2; i++ {
		actual, err := imageConfigDigest(context.Background(), root, directory, image, owner, space, export)
		if err != nil || actual != digest {
			t.Fatalf("%s: %v", actual, err)
		}
	}
	if calls != 1 {
		t.Fatalf("exported %d times", calls)
	}
	// Another immutable ID requires another local verification even if the
	// expected configuration hash would happen to be identical.
	_, err := imageConfigDigest(context.Background(), root, directory, "sha256:"+strings.Repeat("c", 64), owner, space, export)
	if err != nil || calls != 2 {
		t.Fatal("image identity was not part of the cache key", err)
	}
}
func TestImageConfigurationCacheCannotReplaceLocalVerification(t *testing.T) {
	for _, kind := range []string{"key", "mode", "link", "unknown", "duplicate", "owner"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			directory := filepath.Join(root, "cache")
			os.Mkdir(directory, 0700)
			image := "sha256:" + strings.Repeat("a", 64)
			path := filepath.Join(directory, strings.Repeat("a", 64)+".json")
			record := imageConfigRecord{Version: 1, Image: image, Config: "sha256:" + strings.Repeat("b", 64)}
			if kind == "key" {
				record.Image = "sha256:" + strings.Repeat("c", 64)
			}
			if err := workload.WritePrivateJSON(path, record); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "mode":
				os.Chmod(path, 0644)
			case "link":
				os.Remove(path)
				os.Symlink(filepath.Join(root, "foreign"), path)
			case "unknown":
				body, _ := os.ReadFile(path)
				os.WriteFile(path, []byte(strings.TrimSuffix(strings.TrimSpace(string(body)), "}")+`,"extra":true}`), 0600)
			case "duplicate":
				body, _ := os.ReadFile(path)
				os.WriteFile(path, []byte(strings.TrimSuffix(strings.TrimSpace(string(body)), "}")+`,"version":1}`), 0600)
			}
			owner := func(os.FileInfo) bool { return kind != "owner" }
			calls := 0
			_, err := imageConfigDigest(context.Background(), root, directory, image, owner, func(string) bool { return true }, func(context.Context, string) (string, error) { calls++; return record.Config, nil })
			if err == nil || calls != 0 {
				t.Fatal("untrusted cache was used or silently replaced", err, calls)
			}
		})
	}
}
func TestImageConfigurationCacheReservesSpaceAndNeverCachesFailedExport(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "cache")
	image := "sha256:" + strings.Repeat("a", 64)
	digest := "sha256:" + strings.Repeat("b", 64)
	owner := func(os.FileInfo) bool { return true }
	actual, err := imageConfigDigest(context.Background(), root, directory, image, owner, func(string) bool { return false }, func(context.Context, string) (string, error) { return digest, nil })
	if err != nil || actual != digest {
		t.Fatal(err)
	}
	if _, err := os.Lstat(directory); !os.IsNotExist(err) {
		t.Fatal("reserve refusal created metadata")
	}
	_, err = imageConfigDigest(context.Background(), root, directory, image, owner, func(string) bool { return true }, func(context.Context, string) (string, error) { return "", errors.New("owned export failed") })
	if err == nil {
		t.Fatal("failed export accepted")
	}
	if _, err := os.Lstat(directory); !os.IsNotExist(err) {
		t.Fatal("failed export created a cache")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = imageConfigDigest(ctx, root, directory, image, owner, func(string) bool { return true }, func(context.Context, string) (string, error) {
		t.Fatal("cancelled operation exported")
		return digest, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestImageConfigurationCacheBoundsConcurrentWriters(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "cache")
	owner := func(os.FileInfo) bool { return true }
	space := func(string) bool { return true }
	jobs := make(chan int)
	var group sync.WaitGroup
	errs := make(chan error, 270)
	for worker := 0; worker < 8; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for n := range jobs {
				image := fmt.Sprintf("sha256:%064x", n)
				_, err := imageConfigDigest(context.Background(), root, directory, image, owner, space, func(context.Context, string) (string, error) { return "sha256:" + strings.Repeat("b", 64), nil })
				if err != nil {
					errs <- err
				}
			}
		}()
	}
	for n := 1; n <= 270; n++ {
		jobs <- n
	}
	close(jobs)
	group.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != imageConfigCacheLimit {
		t.Fatalf("entries %d: %v", len(entries), err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || info.Mode().Perm() != 0600 || info.Size() > 512 {
			t.Fatal("cache exceeded its metadata bounds")
		}
	}
}

func TestImageConfigurationCacheWithRealDockerExport(t *testing.T) {
	if os.Getenv("KOMIZO_DOCKER_IMAGE_CACHE") != "1" {
		t.Skip("explicit disposable Docker fixture")
	}
	if os.Geteuid() != 0 {
		t.Skip("root ownership fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	body, err := exec.CommandContext(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", os.Getenv("KOMIZO_DOCKER_FIXTURE_IMAGE")).Output()
	if err != nil {
		t.Fatal(err)
	}
	image := strings.TrimSpace(string(body))
	root := t.TempDir()
	directory := filepath.Join(root, "cache")
	calls := 0
	export := func(ctx context.Context, image string) (string, error) {
		calls++
		return exportDockerConfigDigest(ctx, image)
	}
	first, err := imageConfigDigest(ctx, root, directory, image, workloadRootOwner, func(string) bool { return true }, export)
	if err != nil {
		t.Fatal(err)
	}
	second, err := imageConfigDigest(ctx, root, directory, image, workloadRootOwner, func(string) bool { return true }, export)
	if err != nil || second != first || calls != 1 {
		t.Fatalf("immutable export not memoized: %v, exports %d", err, calls)
	}
	t.Logf("real local immutable image export verified once: %s, configuration %s", image, first)
}
