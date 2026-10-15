package box

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go.yaml.in/yaml/v3"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
)

const PreviewProfilesDir = "/etc/komizo/preview-profiles"
const previewProfileLimit = 128 << 10

// PreviewProfile is reviewed host configuration, never an application-CI
// artifact. All application-specific topology and environment policy live here.
type PreviewProfile struct {
	Version             int                      `json:"version"`
	Services            []string                 `json:"services"`
	ImagePrefixes       []string                 `json:"image_prefixes"`
	CredentialNamespace string                   `json:"credential_namespace"`
	Credentials         []string                 `json:"credentials"`
	EnvironmentRules    []PreviewEnvironmentRule `json:"environment_rules"`
	ComposeTemplate     string                   `json:"compose_template"`
	digest              string
}
type PreviewEnvironmentRule struct {
	Name        string `json:"name"`
	Pattern     string `json:"pattern,omitempty"`
	EqualsField string `json:"equals_field,omitempty"`
	Suffix      string `json:"suffix,omitempty"`
}

var previewProfileName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,79}$`)
var previewRevision = regexp.MustCompile(`^[a-f0-9]{40}$`)

func ParsePreviewProfile(body []byte) (*PreviewProfile, error) {
	if len(body) > previewProfileLimit {
		return nil, fmt.Errorf("preview profile exceeds limit")
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	var p PreviewProfile
	if err := d.Decode(&p); err != nil {
		return nil, fmt.Errorf("invalid preview profile: %w", err)
	}
	var extra any
	if d.Decode(&extra) != io.EOF || p.Version != 1 || len(p.Services) < 1 || len(p.Services) > 32 || len(p.ImagePrefixes) < 1 || len(p.ImagePrefixes) > 16 || len(p.Credentials) > 32 || len(p.EnvironmentRules) > 64 || len(p.ComposeTemplate) == 0 {
		return nil, fmt.Errorf("preview profile requires one bounded versioned definition")
	}
	for _, names := range [][]string{p.Services, p.Credentials} {
		seen := map[string]bool{}
		for _, name := range names {
			if !previewProfileName.MatchString(name) || seen[name] {
				return nil, fmt.Errorf("invalid or duplicate preview profile name")
			}
			seen[name] = true
		}
	}
	if len(p.Credentials) > 0 && (len(p.CredentialNamespace) < 1 || len(p.CredentialNamespace) > 128 || strings.ContainsAny(p.CredentialNamespace, "\r\n\x00")) {
		return nil, fmt.Errorf("preview credentials need an explicit bounded namespace")
	}
	for _, prefix := range p.ImagePrefixes {
		if !onlyCharsPreview(prefix, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.:/_-") || !strings.HasSuffix(prefix, ":") {
			return nil, fmt.Errorf("preview profile image prefix must end before an immutable revision tag")
		}
	}
	seen := map[string]bool{}
	for _, r := range p.EnvironmentRules {
		if !previewProfileName.MatchString(r.Name) || seen[r.Name] || (r.Pattern == "") == (r.EqualsField == "") || len(r.Pattern) > 512 || len(r.Suffix) > 256 || strings.ContainsAny(r.Suffix, "\r\n\x00") {
			return nil, fmt.Errorf("invalid preview environment rule")
		}
		if r.Pattern != "" {
			if !strings.HasPrefix(r.Pattern, "^") || !strings.HasSuffix(r.Pattern, "$") {
				return nil, fmt.Errorf("environment patterns must match the whole value")
			}
			if _, err := regexp.Compile(r.Pattern); err != nil {
				return nil, fmt.Errorf("invalid preview environment pattern")
			}
		}
		seen[r.Name] = true
	}
	for _, r := range p.EnvironmentRules {
		if r.EqualsField != "" && (!seen[r.EqualsField] || r.EqualsField == r.Name) {
			return nil, fmt.Errorf("invalid preview environment relationship")
		}
	}
	if _, err := template.New("preview").Option("missingkey=error").Parse(p.ComposeTemplate); err != nil {
		return nil, fmt.Errorf("invalid preview compose template: %w", err)
	}
	digest := sha256.Sum256(body)
	p.digest = hex.EncodeToString(digest[:])
	return &p, nil
}

// ReadPreviewProfile accepts only a regular root-owned private file. A missing
// profile selects the generic built-in image contract; malformed files refuse.
func ReadPreviewProfile(root, app string) (*PreviewProfile, error) {
	if !previewAppChars.MatchString(app) {
		return nil, fmt.Errorf("invalid preview application")
	}
	path := filepath.Join(root, PreviewProfilesDir, app+".json")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	uid, ok := fileUID(info)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ok || uid != 0 || info.Size() > previewProfileLimit {
		return nil, fmt.Errorf("preview profile is not protected")
	}
	// Do not follow writable or symlinked parent paths into another authority.
	for parent := filepath.Dir(path); parent != "." && parent != "/"; parent = filepath.Dir(parent) {
		i, e := os.Lstat(parent)
		if e != nil {
			return nil, e
		}
		u, known := fileUID(i)
		if !i.IsDir() || !known || u != 0 || i.Mode().Perm()&0022 != 0 {
			return nil, fmt.Errorf("preview profile parent is not protected")
		}
		if root != "" && parent == filepath.Clean(root) {
			break
		}
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePreviewProfile(body)
}
func (p *PreviewProfile) validateImages(images []string) error {
	if len(images) != len(p.ImagePrefixes) {
		return fmt.Errorf("preview images do not match the declared components")
	}
	revision := ""
	for i, prefix := range p.ImagePrefixes {
		tag, ok := strings.CutPrefix(images[i], prefix)
		if !ok || !previewRevision.MatchString(tag) || (revision != "" && revision != tag) {
			return fmt.Errorf("preview requires matching immutable component revisions")
		}
		revision = tag
	}
	return nil
}
func (p *PreviewProfile) validateEnvironment(path string) error {
	if len(p.EnvironmentRules) == 0 {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 4096 {
		return fmt.Errorf("preview requires bounded private stack.env")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("preview environment unavailable")
	}
	values := map[string]string{}
	rules := map[string]PreviewEnvironmentRule{}
	for _, r := range p.EnvironmentRules {
		rules[r.Name] = r
	}
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		_, allowed := rules[key]
		_, duplicate := values[key]
		if !ok || !allowed || duplicate {
			return fmt.Errorf("preview environment contains an unsupported or duplicate field")
		}
		values[key] = value
	}
	for _, r := range p.EnvironmentRules {
		v, present := values[r.Name]
		if !present || (r.Pattern != "" && !regexp.MustCompile(r.Pattern).MatchString(v)) || (r.EqualsField != "" && v != values[r.EqualsField]+r.Suffix) {
			return fmt.Errorf("preview environment does not match its operator policy")
		}
	}
	return nil
}
func previewProfileCredential(seed, namespace, role string) string {
	h := hmac.New(sha256.New, []byte(seed))
	h.Write([]byte(namespace + role))
	return hex.EncodeToString(h.Sum(nil))
}
func (p *PreviewProfile) compose(r PreviewRecord, k PreviewKnob, network string) (string, error) {
	data := struct {
		PreviewRecord
		PreviewKnob
		Network, Host, APIHost, CgroupParent string
		Limits, Credentials                  map[string]string
	}{r, k, network, r.WebHost(k), r.PublicAPIHost(k), k.cgroupParent, map[string]string{}, map[string]string{}}
	for _, s := range p.Services {
		data.Limits[s] = previewServiceMemory(k, r.App, s)
	}
	for _, role := range p.Credentials {
		data.Credentials[role] = previewProfileCredential(r.DBPassword, p.CredentialNamespace, role)
	}
	t, err := template.New("preview").Option("missingkey=error").Parse(p.ComposeTemplate)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if err := t.Execute(&b, data); err != nil {
		return "", fmt.Errorf("preview template could not render declared inputs")
	}
	if b.Len() > 1<<20 {
		return "", fmt.Errorf("rendered preview exceeds limit")
	}
	return b.String(), nil
}

// The operator owns topology, but a profile cannot escape Komizo's preview
// envelope or address host/production resources through Compose features.
func (p *PreviewProfile) validateCompose(body string, r PreviewRecord, k PreviewKnob, network string) error {
	var doc struct {
		Services map[string]map[string]any `yaml:"services"`
		Networks map[string]struct {
			External bool   `yaml:"external"`
			Name     string `yaml:"name"`
		} `yaml:"networks"`
		Volumes map[string]map[string]any `yaml:"volumes"`
	}
	if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
		return fmt.Errorf("preview compose is invalid")
	}
	var top map[string]any
	if err := yaml.Unmarshal([]byte(body), &top); err != nil {
		return err
	}
	for key := range top {
		if key != "services" && key != "networks" && key != "volumes" && !strings.HasPrefix(key, "x-") {
			return fmt.Errorf("unsupported preview compose section")
		}
	}
	if len(doc.Services) != len(p.Services) {
		return fmt.Errorf("preview compose service count differs from declaration")
	}
	allowed := map[string]bool{}
	for _, key := range strings.Fields("image mem_limit memswap_limit cgroup_parent cpu_shares cpus restart read_only cap_drop cap_add security_opt pids_limit tmpfs environment volumes networks healthcheck depends_on entrypoint command user env_file ports container_name") {
		allowed[key] = true
	}
	declared := map[string]bool{}
	for _, s := range p.Services {
		declared[s] = true
	}
	usedRoles := map[string]bool{}
	for name, service := range doc.Services {
		role := name
		if name == r.Project+"-gate" {
			role = "gate"
		}
		if !declared[role] || usedRoles[role] {
			return fmt.Errorf("undeclared preview compose service")
		}
		usedRoles[role] = true
		for key := range service {
			if !allowed[key] {
				return fmt.Errorf("unsupported preview service capability")
			}
		}
		text := func(key string) string {
			if service[key] == nil {
				return ""
			}
			return fmt.Sprint(service[key])
		}
		imageOK := false
		for _, image := range r.Images {
			if text("image") == image {
				imageOK = true
			}
		}
		pinned := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-f0-9]{64}$`).MatchString(text("image"))
		if !imageOK && !pinned {
			return fmt.Errorf("preview image is neither an admitted component nor pinned infrastructure")
		}
		limit := previewServiceMemory(k, r.App, role)
		if text("mem_limit") != limit || text("memswap_limit") != limit || text("cgroup_parent") != k.cgroupParent || text("cpu_shares") != "128" || text("cpus") != k.CPULimit {
			return fmt.Errorf("preview service resource limits differ from admission")
		}
		pids, err := strconv.Atoi(text("pids_limit"))
		if err != nil || pids < 1 || pids > 128 {
			return fmt.Errorf("preview service requires bounded process count")
		}
		if c := text("container_name"); c != "" && c != r.Project+"-gate" {
			return fmt.Errorf("preview container name escapes project")
		}
		for _, key := range []string{"volumes", "env_file", "ports", "networks", "cap_add"} {
			if service[key] == nil {
				continue
			}
			items, ok := service[key].([]any)
			if !ok {
				return fmt.Errorf("preview mounts, networks and ports require explicit short declarations")
			}
			for _, item := range items {
				value, ok := item.(string)
				if !ok {
					return fmt.Errorf("invalid preview resource reference")
				}
				switch key {
				case "volumes":
					source, _, found := strings.Cut(value, ":")
					if _, ok := doc.Volumes[source]; !found || !ok {
						return fmt.Errorf("preview volume must be project-owned")
					}
				case "env_file":
					if value != "stack.env" {
						return fmt.Errorf("preview may read only its own stack.env")
					}
				case "ports":
					if role != "gate" || value != fmt.Sprintf("127.0.0.1:%d:80", r.GatePort) {
						return fmt.Errorf("preview port escapes assigned loopback listener")
					}
				case "networks":
					n, found := doc.Networks[value]
					if !found || (n.External && role != "gate") {
						return fmt.Errorf("preview network escapes private topology")
					}
				case "cap_add":
					if !strings.Contains(" CHOWN DAC_OVERRIDE FOWNER SETGID SETUID ", " "+value+" ") {
						return fmt.Errorf("preview requests a host capability")
					}
				}
			}
		}
	}
	for name, v := range doc.Volumes {
		if !previewProfileName.MatchString(name) {
			return fmt.Errorf("invalid preview volume name")
		}
		if len(v) != 0 {
			return fmt.Errorf("preview volumes cannot select external names or host paths")
		}
	}
	rawNetworks, _ := top["networks"].(map[string]any)
	for name, row := range rawNetworks {
		if !previewProfileName.MatchString(name) {
			return fmt.Errorf("invalid preview network name")
		}
		fields, ok := row.(map[string]any)
		if !ok {
			return fmt.Errorf("preview networks need explicit declarations")
		}
		for key := range fields {
			if key != "internal" && key != "external" && key != "name" {
				return fmt.Errorf("preview network requests unsupported driver or capability")
			}
		}
	}
	for _, n := range doc.Networks {
		if n.External && n.Name != network || !n.External && n.Name != "" {
			return fmt.Errorf("preview network name escapes project")
		}
	}
	return nil
}

// ConfigurePreviewProfile installs only explicit operator-reviewed policy. CI's
// preview wrapper does not expose this command. Reconfiguration requires a
// drained application so persisted seed/topology/cleanup identities stay valid.
func ConfigurePreviewProfile(ctx context.Context, app string, body []byte) error {
	if os.Geteuid() != 0 || !previewAppChars.MatchString(app) {
		return fmt.Errorf("preview configure requires the host operator and one application")
	}
	if _, err := ParsePreviewProfile(body); err != nil {
		return err
	}
	ctx, release, err := previewOperation(ctx, "")
	if err != nil {
		return err
	}
	defer release()
	unlock, err := lockPreviews(ctx, "")
	if err != nil {
		return err
	}
	defer unlock()
	records, err := ListPreviews("")
	if err != nil {
		return err
	}
	for _, r := range records {
		if r.App == app {
			return fmt.Errorf("drain application previews before changing the profile")
		}
	}
	if err := os.MkdirAll(PreviewProfilesDir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(PreviewProfilesDir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("preview profile directory is not protected")
	}
	uid, ok := fileUID(info)
	if !ok || uid != 0 {
		return fmt.Errorf("preview profile directory is not root-owned")
	}
	for parent := filepath.Dir(PreviewProfilesDir); parent != "/"; parent = filepath.Dir(parent) {
		i, e := os.Lstat(parent)
		if e != nil {
			return e
		}
		u, known := fileUID(i)
		if !i.IsDir() || !known || u != 0 || i.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("preview profile parent is not protected")
		}
	}
	path := filepath.Join(PreviewProfilesDir, app+".json")
	if _, err := ReadPreviewProfile("", app); err != nil {
		return err
	}
	f, err := os.CreateTemp(PreviewProfilesDir, ".profile-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
