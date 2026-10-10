package workload

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"
)

// DockerArchiveConfigDigest reads a single local Docker export without
// extracting files or contacting a registry. Both classic and containerd stores
// export manifest.json naming the exact configuration used by the local image.
func DockerArchiveConfigDigest(input io.Reader) (string, error) {
	const maxArchive = 2 << 30
	limited := &io.LimitedReader{R: input, N: maxArchive + 1}
	reader := tar.NewReader(limited)
	hashes := map[string]string{}
	seen := map[string]bool{}
	config := ""
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil || len(seen) >= 4096 || header.Size > maxArchive || header.Size < 0 {
			return "", errors.New("invalid local image archive")
		}
		name := header.Name
		if header.Typeflag == tar.TypeDir {
			name = strings.TrimSuffix(name, "/")
		}
		if path.IsAbs(name) || path.Clean(name) != name || strings.HasPrefix(name, "../") || seen[name] {
			return "", errors.New("ambiguous local image archive")
		}
		seen[name] = true
		if !header.FileInfo().Mode().IsRegular() || header.Size > 1<<20 {
			continue
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			return "", err
		}
		if len(hashes) >= 256 {
			return "", errors.New("too many local image metadata files")
		}
		sum := sha256.Sum256(body)
		hashes[name] = "sha256:" + hex.EncodeToString(sum[:])
		if name == "manifest.json" {
			var manifest []struct{ Config string }
			if rejectDuplicateJSON(body) != nil || json.Unmarshal(body, &manifest) != nil || len(manifest) != 1 || manifest[0].Config == "" {
				return "", errors.New("local image export must contain one image")
			}
			config = manifest[0].Config
		}
	}
	// Drain tar padding and require a complete, bounded successful export.
	if _, err := io.Copy(io.Discard, limited); err != nil || limited.N <= 0 {
		return "", errors.New("local image archive exceeds limit")
	}
	id := hashes[config]
	if config == "manifest.json" || id == "" {
		return "", errors.New("local image configuration missing")
	}
	return id, nil
}
