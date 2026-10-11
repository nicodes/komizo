package workload

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// DeploymentPolicy is operator authority. It is never copied from an image.
type DeploymentPolicy struct {
	RoutePath string `json:"route_path"`
	Proxy     string `json:"proxy"`
	ProxyDir  string `json:"proxy_dir"`
}

func (d DeploymentPolicy) Check(app string) error {
	if !identifier.MatchString(d.Proxy) || !filepath.IsAbs(d.ProxyDir) || filepath.Clean(d.ProxyDir) != d.ProxyDir || d.ProxyDir == "/" || d.RoutePath != filepath.Join(d.ProxyDir, "routes", app+".caddy") {
		return errors.New("invalid operator deployment authority")
	}
	return nil
}

// DeploymentStage references an operation-private credential slot; it carries
// no token or password. The slot's exact bytes are bound before submission.
type DeploymentStage struct {
	CredentialSHA256 string `json:"credential_sha256"`
	Generation       string `json:"generation,omitempty"`
}

func (s DeploymentStage) Check() error {
	if !contentIdentity.MatchString(s.CredentialSHA256) || (s.Generation != "" && !operationIdentity.MatchString(s.Generation)) {
		return errors.New("invalid deployment staging request")
	}
	return nil
}

// ReadConfiguration consumes Docker's copy archive without extracting paths.
// The configuration image contributes exactly two bounded ordinary files.
func ReadConfiguration(r io.Reader) (compose, hostnames []byte, err error) {
	limited := &io.LimitedReader{R: r, N: 4<<20 + 1}
	t := tar.NewReader(limited)
	seen := map[string]bool{}
	for {
		h, e := t.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, nil, errors.New("invalid configuration archive")
		}
		raw := strings.TrimPrefix(h.Name, "./")
		if raw == "" && h.Typeflag == tar.TypeDir {
			raw = "."
		}
		name := path.Clean(raw)
		if raw != name && raw != name+"/" || strings.HasPrefix(name, "/") || name == ".." || strings.HasPrefix(name, "../") {
			return nil, nil, errors.New("unsafe configuration archive path")
		}
		if h.Typeflag == tar.TypeDir && (name == "config" || name == ".") {
			continue
		}
		name = strings.TrimPrefix(name, "config/")
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA || seen[name] || (name != "compose.yml" && name != "hostnames") {
			return nil, nil, errors.New("configuration archive contains an unsupported entry")
		}
		seen[name] = true
		limit := int64(MaxBytes)
		if name == "hostnames" {
			limit = 16 << 10
		}
		if h.Size < 0 || h.Size > limit {
			return nil, nil, errors.New("configuration file exceeds its bound")
		}
		b, e := io.ReadAll(io.LimitReader(t, limit+1))
		if e != nil || int64(len(b)) != h.Size {
			return nil, nil, errors.New("incomplete configuration file")
		}
		if name == "compose.yml" {
			compose = b
		} else {
			hostnames = b
		}
	}
	if limited.N <= 0 || len(compose) == 0 {
		return nil, nil, errors.New("configuration archive exceeds its bound or has no compose file")
	}
	return compose, hostnames, nil
}

var hostLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// DeploymentRoute implements the existing gate routing and parent headers.
// Container annotations remain attribution metadata, never upstream authority.
func DeploymentRoute(app, revision string, hostnames []byte, allowWildcard bool) ([]byte, []byte, []string, error) {
	if !identifier.MatchString(app) || !commitID.MatchString(revision) || len(hostnames) > 16<<10 {
		return nil, nil, nil, errors.New("invalid route inputs")
	}
	var plain, wild, names, metadata []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(hostnames), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) > 4 {
			return nil, nil, nil, errors.New("invalid hostname annotation")
		}
		i := 1
		if len(f) > 1 && f[1] == "->" {
			if len(f) < 3 || !identifier.MatchString(f[2]) {
				return nil, nil, nil, errors.New("invalid container annotation")
			}
			i = 3
		}
		if len(f) > i {
			if len(f) != i+1 || f[i] != "on-demand" {
				return nil, nil, nil, errors.New("unsupported certificate mode")
			}
			i++
		}
		if i != len(f) {
			return nil, nil, nil, errors.New("invalid hostname annotation")
		}
		n := strings.ToLower(f[0])
		raw := strings.TrimPrefix(n, "*.")
		if len(n) > 253 || !strings.Contains(raw, ".") || seen[n] || len(names) >= 128 {
			return nil, nil, nil, errors.New("invalid or repeated hostname")
		}
		for _, label := range strings.Split(raw, ".") {
			if !hostLabel.MatchString(label) {
				return nil, nil, nil, errors.New("invalid hostname label")
			}
		}
		if strings.HasPrefix(n, "*.") {
			if !allowWildcard {
				return nil, nil, nil, errors.New("wildcard route needs the operator certificate approval gate")
			}
			wild = append(wild, n)
		} else {
			plain = append(plain, n)
		}
		seen[n] = true
		names = append(names, n)
		f[0] = n
		metadata = append(metadata, strings.Join(f, " "))
	}
	var b bytes.Buffer
	if len(names) > 0 {
		fmt.Fprintf(&b, "# Written by komizo from %s.\n# Edits here are lost on the next deploy.\n", revision)
	}
	for _, group := range []struct {
		names    []string
		wildcard bool
	}{{plain, false}, {wild, true}} {
		if len(group.names) == 0 {
			continue
		}
		fmt.Fprintf(&b, "%s {\n", strings.Join(group.names, ", "))
		if group.wildcard {
			b.WriteString("\ttls {\n\t\ton_demand\n\t}\n")
		}
		fmt.Fprintf(&b, "\theader Strict-Transport-Security \"max-age=31536000\"\n\theader >X-Komizo-Revision \"%s\"\n", revision)
		b.WriteString("\tlog {\n\t\toutput file /var/log/caddy/access.log {\n\t\t\troll_size 10mb\n\t\t\troll_keep 3\n\t\t}\n\t\tformat json\n\t}\n")
		fmt.Fprintf(&b, "\treverse_proxy %s-gate:80 {\n\t\theader_up X-Forwarded-For {remote_host}\n\t}\n}\n", app)
	}
	var recorded []byte
	if len(metadata) > 0 {
		recorded = []byte(strings.Join(metadata, "\n") + "\n")
	}
	return b.Bytes(), recorded, names, nil
}
