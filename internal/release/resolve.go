package release

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"
)

// MaxModelBytes bounds untrusted normalized input, not a runtime latency budget.
const MaxModelBytes = 8 << 20

// Policy is the small x-komizo lifecycle declaration. It is not a proof that
// application code is safe to overlap. Integration tests must establish that.
type Policy struct {
	Lifecycle         *Lifecycle `json:"lifecycle,omitempty"`
	Mode              string     `json:"mode"`
	Port              int        `json:"port,omitempty"`
	ReadyPath         string     `json:"ready_path,omitempty"`
	ReadyHost         string     `json:"ready_host,omitempty"`
	CandidateSafe     bool       `json:"candidate_safe,omitempty"`
	RestartOn         []string   `json:"restart_on,omitempty"`
	Hosts             []string   `json:"hosts,omitempty"`
	ConcurrentVolumes []string   `json:"concurrent_volumes,omitempty"`
}

// Lifecycle declares an in-container protocol adapter, not a host shell hook.
// Its ordered argv is part of the immutable service identity.
type Lifecycle struct {
	Version int      `json:"version"`
	Command []string `json:"command"`
}

func (l *Lifecycle) Validate() error {
	if l == nil || l.Version != 1 || len(l.Command) == 0 || len(l.Command) > 32 || !strings.HasPrefix(l.Command[0], "/") {
		return errors.New("lifecycle requires version 1 and absolute in-container command argv")
	}
	for _, arg := range l.Command {
		if len(arg) > 4096 || strings.ContainsAny(arg, "\x00\r\n") {
			return errors.New("invalid lifecycle command argument")
		}
	}
	return nil
}

type extension struct {
	Version        int               `json:"version"`
	Services       map[string]Policy `json:"services"`
	SecretVersions map[string]string `json:"secret_versions,omitempty"`
}

// Model is an in-memory resolved analysis model. Identity tokens are keyed with
// the same operator-private key for both sides. No raw configuration is exported.
type Model struct {
	Inventory Inventory
	Policies  map[string]Policy
	private   map[string]any
}

func (m *Model) String() string   { return "resolved release model (private configuration omitted)" }
func (m *Model) GoString() string { return m.String() }

// Resolve accepts canonical Compose JSON with immutable image references and
// x-komizo metadata. It intentionally does not read files or use environment
// variables. Unresolved interpolation, env files, file-backed configs and build
// instructions fail closed instead of producing an incomplete no-op decision.
//
// The key must be 32 random bytes, private to the operator. Keyed identities avoid
// publishing guessable hashes of environment/config values that may be sensitive.
// Key rotation invalidates identity equality; never compare tokens across keys.
func Resolve(data, key []byte) (*Model, error) {
	if len(key) != 32 {
		return nil, errors.New("identity key must contain exactly 32 bytes")
	}
	if len(data) > MaxModelBytes {
		return nil, errors.New("normalized Compose model exceeds size limit")
	}
	if !utf8.Valid(data) {
		return nil, errors.New("normalized Compose model must be valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := decodeValue(decoder, 0)
	if err != nil {
		return nil, errors.New("invalid or ambiguous normalized Compose JSON")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("normalized Compose model must contain one JSON document")
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("normalized Compose model must be an object")
	}
	services, ok := root["services"].(map[string]any)
	if !ok {
		return nil, errors.New("normalized Compose services are unresolved")
	}
	extBytes, err := json.Marshal(root["x-komizo"])
	if err != nil {
		return nil, errors.New("invalid x-komizo metadata")
	}
	var ext extension
	dec := json.NewDecoder(bytes.NewReader(extBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ext); err != nil || ext.Version != 1 || ext.Services == nil {
		return nil, errors.New("x-komizo requires version 1 and explicit service policies")
	}
	if len(ext.Services) != len(services) {
		return nil, errors.New("x-komizo policies must match the complete active service set")
	}
	for name := range ext.Services {
		if _, ok := services[name]; !ok {
			return nil, errors.New("x-komizo policy names an unknown service")
		}
	}
	model := &Model{Inventory: make(Inventory, len(services)), Policies: ext.Services, private: root}
	usedSecrets := map[string]bool{}
	for _, name := range slices.Sorted(maps.Keys(services)) {
		if !validName(name) {
			return nil, errors.New("normalized Compose contains an invalid service name")
		}
		fail := func(reason string) (*Model, error) {
			return nil, fmt.Errorf("service %q: %s", name, reason)
		}
		service, ok := services[name].(map[string]any)
		if !ok {
			return fail("expected a canonical service object")
		}
		for _, field := range []string{"build", "env_file", "profiles", "extends", "include", "models"} {
			if _, present := service[field]; present {
				return fail("unresolved or unsupported service input: " + field)
			}
		}
		// Compose 2.39.2 renders a network attachment with no options as
		// null. This is known-empty, unlike environment VALUE: null, which
		// delegates resolution to the process environment. Normalize only
		// the former; never broadly treat null inputs as resolved.
		if networks, ok := service["networks"].(map[string]any); ok {
			for network, options := range networks {
				if options == nil {
					networks[network] = map[string]any{}
				}
			}
		}
		if unresolved(service) {
			return fail("unresolved interpolation or null environment value")
		}
		image, ok := service["image"].(string)
		if !ok || !immutableImage(image) {
			return fail("image must use an immutable sha256 reference")
		}
		_, digest, _ := strings.Cut(image, "@")
		if strings.HasPrefix(image, "sha256:") {
			digest = "image-config:" + image
		}
		policy := ext.Services[name]
		if policy.Lifecycle != nil {
			if err := policy.Lifecycle.Validate(); err != nil {
				return fail(err.Error())
			}
		}
		policy.RestartOn = slices.Sorted(slices.Values(policy.RestartOn))
		policy.Hosts = slices.Sorted(slices.Values(policy.Hosts))
		policy.ConcurrentVolumes = slices.Sorted(slices.Values(policy.ConcurrentVolumes))
		model.Policies[name] = policy
		if err := validatePolicy(policy, service); err != nil {
			return fail(err.Error())
		}
		runtime := maps.Clone(service)
		delete(runtime, "image")
		// Explicit dependency names are hashed separately from their identities.
		// Changing a dependency does not implicitly restart all consumers.
		runtime["x-komizo-policy"] = policy
		resources := map[string]any{}
		for _, kind := range []string{"networks", "volumes", "configs"} {
			selected, err := referencedResources(kind, service[kind], root[kind])
			if err != nil {
				return fail(err.Error())
			}
			resources[kind] = selected
		}
		secrets, err := secretVersions(service["secrets"], root["secrets"], ext.SecretVersions, usedSecrets)
		if err != nil {
			return fail(err.Error())
		}
		model.Inventory[name] = Identity{
			Image: token(key, "image", digest),
			Runtime: token(key, "runtime", struct {
				Service, Resources map[string]any
			}{runtime, resources}),
			Secrets: token(key, "secrets", secrets),
		}
	}
	if len(usedSecrets) != len(ext.SecretVersions) {
		return nil, errors.New("secret version metadata must match granted secrets")
	}
	// Explicit invalidation edges are acyclic; compute dependency tokens in
	// dependency order without making map order part of a release identity.
	visiting, done := map[string]bool{}, map[string]bool{}
	var visit func(string) error
	visit = func(name string) error {
		if visiting[name] {
			return errors.New("restart_on dependency cycle")
		}
		if done[name] {
			return nil
		}
		visiting[name] = true
		deps := map[string]Identity{}
		for _, dep := range model.Policies[name].RestartOn {
			if _, exists := model.Inventory[dep]; !exists {
				return errors.New("restart_on references an unknown service")
			}
			if _, duplicate := deps[dep]; duplicate {
				return errors.New("restart_on contains a duplicate service")
			}
			if err := visit(dep); err != nil {
				return err
			}
			deps[dep] = model.Inventory[dep]
		}
		identity := model.Inventory[name]
		identity.Dependencies = token(key, "dependencies", deps)
		model.Inventory[name] = identity
		visiting[name], done[name] = false, true
		return nil
	}
	for _, name := range slices.Sorted(maps.Keys(model.Inventory)) {
		if err := visit(name); err != nil {
			return nil, err
		}
	}
	return model, nil
}

func token(key []byte, domain string, value any) string {
	// All callers supply JSON-compatible values from a validated JSON tree or
	// fixed structs. Marshal sorts map keys and preserves json.Number values.
	data, _ := json.Marshal(value)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(domain + "\x00"))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func immutableImage(image string) bool {
	name, digest, ok := strings.Cut(image, "@sha256:")
	if strings.HasPrefix(image, "sha256:") {
		name, digest, ok = "local-image", strings.TrimPrefix(image, "sha256:"), true
	}
	if !ok || name == "" || len(digest) != 64 || strings.ContainsAny(name, " \t\r\n@") {
		return false
	}
	for _, c := range digest {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func unresolved(v any) bool {
	switch v := v.(type) {
	case nil:
		return true
	case string:
		return strings.Contains(v, "$")
	case []any:
		for _, item := range v {
			if unresolved(item) {
				return true
			}
		}
	case map[string]any:
		for _, item := range v {
			if unresolved(item) {
				return true
			}
		}
	}
	return false
}

func validatePolicy(p Policy, service map[string]any) error {
	switch p.Mode {
	case "persistent", "job":
		if p.CandidateSafe || p.Port != 0 || p.ReadyPath != "" || p.ReadyHost != "" || len(p.Hosts) != 0 || len(p.ConcurrentVolumes) != 0 {
			return errors.New("non-HTTP policy cannot declare HTTP candidate settings")
		}
	case "http":
		if p.Lifecycle != nil {
			if restart, exists := service["restart"]; exists && restart != "no" {
				return errors.New("lifecycle execution requires restart: no; automatic restarts invalidate application drain proof")
			}
		}
		if p.ReadyHost != "" && !validName(p.ReadyHost) {
			return errors.New("invalid readiness host")
		}
		u, err := url.ParseRequestURI(p.ReadyPath)
		if !p.CandidateSafe || p.Port < 1 || p.Port > 65535 || err != nil ||
			!strings.HasPrefix(p.ReadyPath, "/") || strings.HasPrefix(p.ReadyPath, "//") ||
			u.Host != "" || u.Scheme != "" || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(p.ReadyPath, "\r\n") {
			return errors.New("HTTP candidate needs a port, local readiness path and candidate_safe declaration")
		}
		for _, field := range []string{"ports", "container_name", "network_mode", "mac_address", "pid", "ipc", "devices", "volumes_from", "links", "external_links", "deploy"} {
			if _, exists := service[field]; exists {
				return errors.New("HTTP candidate has unsupported overlap setting: " + field)
			}
		}
		if service["privileged"] == true {
			return errors.New("privileged HTTP candidates are not supported")
		}
		if networks, ok := service["networks"].(map[string]any); ok {
			for _, raw := range networks {
				options, ok := raw.(map[string]any)
				if !ok {
					return errors.New("invalid canonical network attachment")
				}
				for _, field := range []string{"aliases", "ipv4_address", "ipv6_address", "link_local_ips", "mac_address"} {
					if _, exists := options[field]; exists {
						return errors.New("HTTP candidate network identities must be assigned by the rollout executor")
					}
				}
			}
		}
		concurrent := map[string]bool{}
		for _, name := range p.ConcurrentVolumes {
			if !validName(name) {
				return errors.New("invalid concurrent volume declaration")
			}
			if _, duplicate := concurrent[name]; duplicate {
				return errors.New("duplicate concurrent volume declaration")
			}
			concurrent[name] = false
		}
		if mounts, exists := service["volumes"]; exists {
			list, ok := mounts.([]any)
			if !ok {
				return errors.New("volumes must use canonical long syntax")
			}
			for _, raw := range list {
				mount, ok := raw.(map[string]any)
				if !ok {
					return errors.New("invalid canonical volume mount")
				}
				if mount["read_only"] != true {
					name, _ := mount["source"].(string)
					if _, declared := concurrent[name]; !declared || mount["type"] != "volume" {
						return errors.New("HTTP writable volumes require explicit concurrent-writer capability")
					}
					concurrent[name] = true
				}
			}
		}
		for _, used := range concurrent {
			if !used {
				return errors.New("concurrent volume declaration does not match a writable grant")
			}
		}
	default:
		return errors.New("unsupported lifecycle mode")
	}
	return nil
}

func referencedResources(kind string, value, definitions any) (map[string]any, error) {
	selected := map[string]any{}
	if value == nil {
		return selected, nil
	}
	defs, _ := definitions.(map[string]any)
	names := []string{}
	if kind == "networks" {
		refs, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("networks must use canonical long syntax")
		}
		names = slices.Sorted(maps.Keys(refs))
	} else {
		refs, ok := value.([]any)
		if !ok {
			return nil, errors.New(kind + " must use canonical long syntax")
		}
		for _, raw := range refs {
			ref, ok := raw.(map[string]any)
			if !ok {
				return nil, errors.New(kind + " must use canonical long syntax")
			}
			if kind == "volumes" && ref["type"] != "volume" {
				return nil, errors.New("bind and non-volume mounts need a content resolver")
			}
			name, ok := ref["source"].(string)
			if !ok || name == "" {
				return nil, errors.New(kind + " source is unresolved")
			}
			names = append(names, name)
		}
	}
	for _, name := range names {
		definition, ok := defs[name].(map[string]any)
		if !ok || unresolved(definition) {
			return nil, errors.New(kind + " definition is unresolved")
		}
		if kind == "configs" {
			if _, ok := definition["content"].(string); !ok || definition["file"] != nil || definition["environment"] != nil || definition["external"] == true {
				return nil, errors.New("configs require resolved inline content")
			}
		}
		selected[name] = definition
	}
	return selected, nil
}

func secretVersions(value, definitions any, versions map[string]string, used map[string]bool) (map[string]any, error) {
	selected := map[string]any{}
	if value == nil {
		return selected, nil
	}
	refs, ok := value.([]any)
	if !ok {
		return nil, errors.New("secret grants must use canonical long syntax")
	}
	defs, _ := definitions.(map[string]any)
	for _, raw := range refs {
		ref, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("secret grants must use canonical long syntax")
		}
		name, ok := ref["source"].(string)
		definition, defined := defs[name].(map[string]any)
		if !ok || !validName(name) || !defined || strings.TrimSpace(versions[name]) == "" {
			return nil, errors.New("secret grant needs a definition and opaque version")
		}
		// Source descriptors affect identity, but secret contents never enter it.
		// File-backed definitions point to operator-managed versioned material;
		// validation here does not read it or attest the supplied version mapping.
		if definition["content"] != nil || unresolved(definition) {
			return nil, errors.New("inline secret content is not supported")
		}
		if _, duplicate := selected[name]; duplicate {
			return nil, errors.New("duplicate secret grant")
		}
		selected[name] = map[string]any{"version": versions[name], "source": definition}
		used[name] = true
	}
	return selected, nil
}

// decodeValue rejects duplicate keys at every depth. encoding/json's ordinary
// last-key-wins behavior is not suitable for an authorization/lifecycle boundary.
func decodeValue(d *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, errors.New("JSON nesting limit")
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch t {
	case json.Delim('{'):
		object := map[string]any{}
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok {
				return nil, errors.New("invalid object key")
			}
			if _, exists := object[name]; exists {
				return nil, errors.New("duplicate object key")
			}
			value, err := decodeValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			object[name] = value
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return nil, errors.New("invalid object end")
		}
		return object, nil
	case json.Delim('['):
		array := []any{}
		for d.More() {
			value, err := decodeValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return nil, errors.New("invalid array end")
		}
		return array, nil
	default:
		if _, delimiter := t.(json.Delim); delimiter {
			return nil, errors.New("unexpected delimiter")
		}
		return t, nil
	}
}
