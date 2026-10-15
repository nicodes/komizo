package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/internal/workload"
)

const imageConfigCacheDirectory = "/var/lib/komizo/image-configs"
const imageConfigCacheLimit = 256

type imageConfigRecord struct {
	Version int    `json:"version"`
	Image   string `json:"image"`
	Config  string `json:"config"`
}

func configDigestShape(value string) bool {
	return len(value) == 71 && strings.HasPrefix(value, "sha256:") && strings.Trim(value[7:], "0123456789abcdef") == ""
}

// Only a verified local export populates this cache. The immutable image ID
// remains its key; accepted source evidence and expected configuration hashes
// are still checked by BindRelease on every use.
func imageConfigDigest(ctx context.Context, root, directory, image string, owner func(os.FileInfo) bool, space func(string) bool, export func(context.Context, string) (string, error)) (string, error) {
	if !configDigestShape(image) {
		return "", errors.New("invalid immutable image identity")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	inspectDirectory := func() error {
		info, err := os.Lstat(directory)
		if err != nil {
			return err
		}
		if !info.IsDir() || !owner(info) || info.Mode().Perm() != 0700 {
			return errors.New("image configuration cache requires a protected directory")
		}
		return nil
	}
	exists := true
	if err := inspectDirectory(); err != nil {
		if !os.IsNotExist(err) {
			return "", err
		}
		exists = false
	}
	path := filepath.Join(directory, strings.TrimPrefix(image, "sha256:")+".json")
	if exists {
		info, err := os.Lstat(path)
		if err == nil {
			if !info.Mode().IsRegular() || !owner(info) || info.Mode().Perm() != 0600 || info.Size() > 512 {
				return "", errors.New("invalid protected image configuration record")
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return "", err
			}
			var record imageConfigRecord
			if json.Unmarshal(body, &record) != nil || record.Version != 1 || record.Image != image || !configDigestShape(record.Config) {
				return "", errors.New("image configuration record differs from its immutable key")
			}
			canonical, err := json.MarshalIndent(record, "", "  ")
			if err != nil || !bytes.Equal(body, append(canonical, '\n')) {
				return "", errors.New("noncanonical image configuration record")
			}
			return record.Config, nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
	}
	config, err := export(ctx, image)
	if err != nil {
		return "", err
	}
	if !configDigestShape(config) {
		return "", errors.New("invalid verified image configuration digest")
	}
	// Failure to reserve metadata space only disables memoization. It never
	// changes the verified result or starts/pulls a workload.
	parent := directory
	if !exists {
		parent = filepath.Dir(directory)
	}
	if !space(parent) {
		return config, nil
	}
	unlock, err := box.LockImageMetadata(ctx, root)
	if err != nil {
		return "", err
	}
	defer unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !exists {
		if err := os.Mkdir(directory, 0700); err != nil && !os.IsExist(err) {
			return "", err
		}
	}
	if err := inspectDirectory(); err != nil {
		return "", err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return "", err
	}
	entries, readErr := dir.ReadDir(imageConfigCacheLimit + 1)
	dir.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return "", readErr
	}
	if len(entries) > imageConfigCacheLimit {
		return config, nil
	}
	// Evict only known metadata records, under the same cache lock. No image,
	// release receipt, workload file or persistent product data is removed.
	if len(entries) >= imageConfigCacheLimit {
		type oldRecord struct {
			path string
			info os.FileInfo
		}
		known := []oldRecord{}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasSuffix(name, ".json") || !configDigestShape("sha256:"+strings.TrimSuffix(name, ".json")) {
				return config, nil
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() || !owner(info) || info.Mode().Perm() != 0600 || info.Size() > 512 {
				return config, nil
			}
			known = append(known, oldRecord{filepath.Join(directory, name), info})
		}
		sort.Slice(known, func(i, j int) bool {
			if known[i].info.ModTime().Equal(known[j].info.ModTime()) {
				return known[i].path < known[j].path
			}
			return known[i].info.ModTime().Before(known[j].info.ModTime())
		})
		if err := os.Remove(known[0].path); err != nil {
			return "", err
		}
	}
	if err := workload.WritePrivateJSON(path, imageConfigRecord{Version: 1, Image: image, Config: config}); err != nil {
		return "", err
	}
	return config, nil
}

// Recover an accepted configuration artifact without consulting a mutable tag,
// pulling, retagging, exporting, or changing the cache. The caller independently
// verifies the returned immutable local image against authenticated Build bytes.
func cachedConfigurationImage(ctx context.Context, directory, expected string, owner func(os.FileInfo) bool, present func(string) bool) (string, error) {
	if !configDigestShape(expected) {
		return "", errors.New("invalid accepted configuration identity")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || !owner(info) || info.Mode().Perm() != 0700 {
		return "", errors.New("configuration cache is not protected")
	}
	f, err := os.Open(directory)
	if err != nil {
		return "", err
	}
	entries, err := f.ReadDir(imageConfigCacheLimit + 1)
	f.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if len(entries) > imageConfigCacheLimit {
		return "", errors.New("configuration cache exceeds lookup bound")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		name := entry.Name()
		image := "sha256:" + strings.TrimSuffix(name, ".json")
		if !strings.HasSuffix(name, ".json") || !configDigestShape(image) {
			return "", errors.New("unknown configuration cache entry")
		}
		path := filepath.Join(directory, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || !owner(info) || info.Mode().Perm() != 0600 || info.Size() > 512 {
			return "", errors.New("unprotected configuration cache entry")
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		var record imageConfigRecord
		if json.Unmarshal(body, &record) != nil || record.Version != 1 || record.Image != image || !configDigestShape(record.Config) {
			return "", errors.New("configuration cache identity differs")
		}
		canonical, err := json.MarshalIndent(record, "", "  ")
		if err != nil || !bytes.Equal(body, append(canonical, '\n')) {
			return "", errors.New("noncanonical configuration cache entry")
		}
		if record.Config == expected && present(image) {
			return image, nil
		}
	}
	return "", errors.New("accepted configuration image is unavailable locally")
}
