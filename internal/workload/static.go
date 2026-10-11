package workload

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const StaticRoot = "/srv/_public"
const StaticContainerRoot = "/srv/public"
const StaticMaxBytes int64 = 64 << 20
const StaticMaxFileBytes int64 = 16 << 20
const StaticMaxEntries = 4096

// StaticPolicy is an operator opt-in to a fixed serving profile. The exact
// gate configuration hash fences changes requiring new parity verification.
// Only the public tree is mounted into the existing shared proxy.
type StaticPolicy struct {
	Profile       string   `json:"profile"`
	GateConfigSHA string   `json:"gate_config_sha256"`
	Proxy         string   `json:"proxy"`
	Hostnames     []string `json:"hostnames"`
}

func (s StaticPolicy) Check() error {
	if s.Profile != "spa-v1" || !contentIdentity.MatchString(s.GateConfigSHA) || !identifier.MatchString(s.Proxy) {
		return errors.New("unsupported static serving profile")
	}
	if len(s.Hostnames) < 1 || len(s.Hostnames) > 16 {
		return errors.New("static profiles require reviewed exact hostnames")
	}
	seen := map[string]bool{}
	for _, host := range s.Hostnames {
		if !staticHostname.MatchString(host) || len(host) > 253 || seen[host] {
			return errors.New("invalid or duplicate static hostname")
		}
		seen[host] = true
	}
	return nil
}

// StaticTree extracts an immutable, bounded public archive into a fresh
// directory. Links, devices, traversal, duplicate/case-colliding names and
// hidden files (except the exact Expo route manifest) are refused. No archive-controlled permission is retained.
func StaticTree(reader io.Reader, destination string) (identity string, err error) {
	if err = os.Mkdir(destination, 0700); err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(destination)
		}
	}()
	limited := &io.LimitedReader{R: reader, N: StaticMaxBytes + StaticMaxEntries*2048 + 1}
	archive := tar.NewReader(limited)
	seen := map[string]bool{}
	hashes := map[string]string{}
	var total int64
	entries := 0
	for {
		h, nextErr := archive.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return "", errors.New("invalid public archive")
		}
		entries++
		if entries > StaticMaxEntries || limited.N <= 0 {
			return "", errors.New("public archive exceeds its envelope")
		}
		name := strings.TrimPrefix(h.Name, "./")
		if (name == "." || name == "") && h.Typeflag == tar.TypeDir {
			continue
		}
		name = strings.TrimSuffix(name, "/")
		if name == "" || path.Clean(name) != name || path.IsAbs(name) || strings.ContainsAny(name, "\\\x00\r\n") {
			return "", errors.New("public archive path escapes its tree")
		}
		for _, component := range strings.Split(name, "/") {
			if (strings.HasPrefix(component, ".") && name != "_expo/.routes.json") || strings.Contains(component, ":") {
				return "", errors.New("hidden or platform-sensitive public path")
			}
		}
		key := strings.ToLower(name)
		if seen[key] {
			return "", errors.New("duplicate public archive path")
		}
		seen[key] = true
		target := filepath.Join(destination, filepath.FromSlash(name))
		if h.Typeflag == tar.TypeDir {
			if err = os.MkdirAll(target, 0755); err != nil {
				return "", err
			}
			continue
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA || h.Size < 0 || h.Size > StaticMaxFileBytes || h.Size > StaticMaxBytes-total {
			return "", errors.New("unsupported or oversized public archive entry")
		}
		total += h.Size
		if err = os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return "", err
		}
		file, openErr := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if openErr != nil {
			return "", openErr
		}
		sum := sha256.New()
		_, copyErr := io.CopyN(io.MultiWriter(file, sum), archive, h.Size)
		syncErr, closeErr := file.Sync(), file.Close()
		if err = errors.Join(copyErr, syncErr, closeErr); err != nil {
			return "", err
		}
		if err = os.Chmod(target, 0444); err != nil {
			return "", err
		}
		if err = os.Chtimes(target, h.ModTime, h.ModTime); err != nil {
			return "", err
		}
		hashes[name] = hex.EncodeToString(sum.Sum(nil))
	}
	if limited.N <= 0 || hashes["index.html"] == "" {
		return "", errors.New("public archive lacks a bounded SPA entry point")
	}
	keys := make([]string, 0, len(hashes))
	for name := range hashes {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	sum := sha256.New()
	for _, name := range keys {
		_, _ = fmt.Fprintf(sum, "%s\x00%s\n", name, hashes[name])
	}
	err = filepath.WalkDir(destination, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if chmodErr := os.Chmod(name, 0755); chmodErr != nil {
				return chmodErr
			}
			directory, openErr := os.Open(name)
			if openErr != nil {
				return openErr
			}
			return errors.Join(directory.Sync(), directory.Close())
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// StaticRoute preserves the host-generated site's TLS, logs and revision
// headers. It replaces only the exact gate upstream with the reviewed profile.
// The unmodified upstream route remains the disabled/owner-stopped route.
var staticHostname = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$`)

func StaticRoute(route []byte, app, revision string, hostnames []string) ([]byte, error) {
	if !identifier.MatchString(app) || !commitID.MatchString(revision) || len(route) > MaxBytes {
		return nil, errors.New("invalid static route identity")
	}
	wanted, seen := map[string]bool{}, map[string]bool{}
	for _, host := range hostnames {
		wanted[host] = true
	}
	for _, line := range strings.Split(string(route), "\n") {
		if line == "" || line[0] == '\t' || line[0] == '#' || !strings.HasSuffix(line, " {") {
			continue
		}
		for _, host := range strings.Fields(strings.TrimSuffix(line, " {")) {
			if !wanted[host] || seen[host] {
				return nil, errors.New("static route hostname differs from its reviewed serving profile")
			}
			seen[host] = true
		}
	}
	if len(seen) != len(wanted) || len(seen) == 0 {
		return nil, errors.New("static route lacks its reviewed exact hostnames")
	}
	needle := "\treverse_proxy " + app + "-gate:80 {\n\t\theader_up X-Forwarded-For {remote_host}\n\t}\n"
	count := strings.Count(string(route), needle)
	if count < 1 || count > 64 {
		return nil, errors.New("static profile requires exact host-generated gate routes")
	}
	snippet := "\tencode zstd gzip\n\troot * " + StaticContainerRoot + "/" + app + "/" + revision + "\n" +
		"\ttry_files {path} {path}.html {path}/index.html /index.html\n\tfile_server\n" +
		"\theader {\n\t\tX-Frame-Options DENY\n\t\tX-Content-Type-Options nosniff\n" +
		"\t\tReferrer-Policy strict-origin-when-cross-origin\n\t}\n"
	return []byte(strings.ReplaceAll(string(route), needle, snippet)), nil
}

func StaticGate(compose []byte, app string) (string, error) {
	var document struct {
		Services map[string]struct {
			Image string `json:"image"`
		} `json:"services"`
	}
	if json.Unmarshal(compose, &document) != nil || len(document.Services) != 1 {
		return "", errors.New("static profile requires one gate-only service")
	}
	gate, ok := document.Services[app+"-gate"]
	if !ok || !strings.Contains(gate.Image, "@sha256:") {
		return "", errors.New("static profile requires the admitted immutable gate image")
	}
	return gate.Image, nil
}

func StaticTreeChecksum(directory string) (string, error) {
	hashes := map[string]string{}
	var total int64
	entries := 0
	err := filepath.WalkDir(directory, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entries++
		if entries > StaticMaxEntries+1 || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("cached public tree is linked or oversized")
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return infoErr
		}
		if entry.IsDir() {
			if info.Mode().Perm()&0022 != 0 {
				return errors.New("cached public directory is writable")
			}
			return nil
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0222 != 0 || info.Size() > StaticMaxFileBytes || info.Size() > StaticMaxBytes-total {
			return errors.New("cached public file is unsafe")
		}
		total += info.Size()
		relative, relativeErr := filepath.Rel(directory, name)
		if relativeErr != nil {
			return relativeErr
		}
		file, openErr := os.Open(name)
		if openErr != nil {
			return openErr
		}
		sum := sha256.New()
		_, copyErr := io.Copy(sum, io.LimitReader(file, StaticMaxFileBytes+1))
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return errors.Join(copyErr, closeErr)
		}
		hashes[filepath.ToSlash(relative)] = hex.EncodeToString(sum.Sum(nil))
		return nil
	})
	if err != nil || hashes["index.html"] == "" {
		return "", errors.Join(err, errors.New("invalid cached public entry point"))
	}
	keys := make([]string, 0, len(hashes))
	for name := range hashes {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	sum := sha256.New()
	for _, name := range keys {
		_, _ = fmt.Fprintf(sum, "%s\x00%s\n", name, hashes[name])
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}
