// Package workload restricts repository-supplied Compose to an app's host-owned
// authority. It parses configuration without resolving includes, reading env
// files or invoking Docker. The validated JSON is the only configuration Docker
// subsequently consumes.
package workload

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

const MaxBytes = 1 << 20

type Policy struct {
	Version                 int              `json:"version"`
	App                     string           `json:"app"`
	AppDir                  string           `json:"app_dir"`
	ImagePrefix             string           `json:"image_prefix"`
	SharedNetwork           string           `json:"shared_network"`
	SourceRepository        string           `json:"source_repository,omitempty"`
	RepositoryID            string           `json:"repository_id,omitempty"`
	Resources               *ResourcePolicy  `json:"resources,omitempty"`
	Readiness               *ReadinessPolicy `json:"readiness,omitempty"`
	IngressNetwork          string           `json:"ingress_network,omitempty"`
	RequireStatefulContract bool             `json:"require_stateful_contract,omitempty"`
}

var identifier = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
var imageRepository = regexp.MustCompile(`^[a-z0-9][a-z0-9./_-]+$`)
var revision = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var digest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func (p Policy) Check() error {
	if p.RequireStatefulContract && p.SourceRepository == "" {
		return errors.New("stateful contracts require authenticated release source authority")
	}
	if p.IngressNetwork != "" && p.IngressNetwork != IsolatedIngress(p.App) {
		return errors.New("ingress network must belong to this app")
	}
	if p.Readiness != nil {
		if err := p.Readiness.Check(); err != nil {
			return err
		}
	}
	if p.Resources != nil {
		if err := p.Resources.Check(); err != nil {
			return err
		}
	}
	if (p.SourceRepository != "" || p.RepositoryID != "") && (!repositoryName.MatchString(p.SourceRepository) || !numericID.MatchString(p.RepositoryID)) {
		return errors.New("invalid workload source identity")
	}
	if p.Version != 1 || !identifier.MatchString(p.App) || !identifier.MatchString(p.SharedNetwork) ||
		!filepath.IsAbs(p.AppDir) || filepath.Clean(p.AppDir) != p.AppDir || p.AppDir == "/" ||
		!imageRepository.MatchString(p.ImagePrefix) || !strings.HasSuffix(p.ImagePrefix, "-") {
		return errors.New("invalid host workload policy")
	}
	return nil
}

func NewPolicy(app, dir, configImage, network string) (Policy, error) {
	if !strings.HasSuffix(configImage, "-config") {
		return Policy{}, errors.New("configuration repository must end in -config")
	}
	p := Policy{Version: 1, App: app, AppDir: dir, ImagePrefix: strings.TrimSuffix(configImage, "config"), SharedNetwork: network}
	return p, p.Check()
}

func ReadPolicy(r io.Reader) (Policy, error) {
	var p Policy
	dec := json.NewDecoder(io.LimitReader(r, MaxBytes+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, errors.New("invalid host workload policy document")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return p, errors.New("host workload policy must contain one document")
	}
	return p, p.Check()
}

// Validate rejects unknown features instead of inheriting new Compose powers.
// It returns self-contained JSON with a host-selected project namespace.
func Validate(r io.Reader, p Policy, version string) ([]byte, error) {
	if err := p.Check(); err != nil {
		return nil, err
	}
	if !revision.MatchString(version) {
		return nil, errors.New("invalid release revision")
	}
	b, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil || len(b) > MaxBytes {
		return nil, errors.New("workload exceeds document limit")
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var node yaml.Node
	if dec.Decode(&node) != nil || len(node.Content) != 1 {
		return nil, errors.New("invalid workload YAML")
	}
	var extra yaml.Node
	if dec.Decode(&extra) != io.EOF {
		return nil, errors.New("workload must contain one document")
	}
	value, err := plain(node.Content[0], 0)
	if err != nil {
		return nil, err
	}
	doc, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("workload must be an object")
	}
	if err := keys(doc, "workload", "services", "networks", "volumes"); err != nil {
		return nil, err
	}
	services, ok := doc["services"].(map[string]any)
	if !ok || len(services) > 32 {
		return nil, errors.New("workload needs an object with at most 32 services")
	}
	if err := validateResources(doc, p); err != nil {
		return nil, err
	}
	for name, raw := range services {
		if !identifier.MatchString(name) {
			return nil, errors.New("invalid service name")
		}
		s, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("service must be an object")
		}
		if err := validateService(name, s, doc, p, version); err != nil {
			return nil, err
		}
	}
	if err := boundResources(services, p.Resources); err != nil {
		return nil, err
	}
	doc["name"] = p.App
	return json.MarshalIndent(doc, "", "  ")
}

func plain(n *yaml.Node, depth int) (any, error) {
	if depth > 32 || n.Anchor != "" || n.Kind == yaml.AliasNode || (n.Kind == yaml.MappingNode && n.Tag != "!!map") || (n.Kind == yaml.SequenceNode && n.Tag != "!!seq") {
		return nil, errors.New("workload nesting, anchors or aliases are not supported")
	}
	switch n.Kind {
	case yaml.MappingNode:
		out := map[string]any{}
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "<<" {
				return nil, errors.New("workload keys must be plain strings")
			}
			if _, exists := out[key.Value]; exists {
				return nil, errors.New("duplicate workload key")
			}
			v, err := plain(n.Content[i+1], depth+1)
			if err != nil {
				return nil, err
			}
			out[key.Value] = v
		}
		return out, nil
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for _, child := range n.Content {
			v, err := plain(child, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!str", "!!null", "!!bool", "!!int", "!!float":
		default:
			return nil, errors.New("unsupported workload scalar")
		}
		var out any
		if n.Decode(&out) != nil {
			return nil, errors.New("invalid workload scalar")
		}
		return out, nil
	default:
		return nil, errors.New("unsupported workload YAML node")
	}
}

func keys(m map[string]any, where string, allowed ...string) error {
	for k := range m {
		found := false
		for _, a := range allowed {
			if k == a {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("unsupported %s field %q", where, k)
		}
	}
	return nil
}

func object(raw any) (map[string]any, bool) {
	if raw == nil {
		return map[string]any{}, true
	}
	m, ok := raw.(map[string]any)
	return m, ok
}

func validateResources(doc map[string]any, p Policy) error {
	for _, kind := range []string{"volumes", "networks"} {
		resources, ok := object(doc[kind])
		if !ok {
			return fmt.Errorf("%s must be an object", kind)
		}
		for name, raw := range resources {
			if !identifier.MatchString(name) {
				return errors.New("invalid resource name")
			}
			cfg, ok := object(raw)
			if !ok {
				return errors.New("resource must be an object")
			}
			if kind == "volumes" {
				if err := keys(cfg, "volume", "name"); err != nil {
					return err
				}
				if raw, exists := cfg["name"]; exists {
					name, ok := raw.(string)
					if !ok || !identifier.MatchString(name) || !strings.HasPrefix(name, p.App+"_") {
						return errors.New("foreign volume namespace refused")
					}
				}
			} else {
				if err := keys(cfg, "network", "internal", "external", "name"); err != nil {
					return err
				}
				if internal, exists := cfg["internal"]; exists {
					if _, ok := internal.(bool); !ok {
						return errors.New("network internal must be boolean")
					}
				}
				external, exists := cfg["external"]
				if exists && external != true && external != false {
					return errors.New("network external must be boolean")
				}
				if external == true {
					netName, ok := cfg["name"].(string)
					if !ok {
						return errors.New("external network needs a host-approved name")
					}
					netName = strings.ReplaceAll(netName, "${SHARED_NETWORK:-edge}", p.SharedNetwork)
					if netName != p.SharedNetwork {
						return errors.New("foreign external network refused")
					}
					if p.IngressNetwork != "" {
						netName = p.IngressNetwork
					}
					cfg["name"] = netName
				} else if _, exists := cfg["name"]; exists {
					return errors.New("custom network namespace refused")
				}
			}
		}
	}
	return nil
}

func validateService(name string, s, doc map[string]any, p Policy, version string) error {
	if err := keys(s, "service", "image", "user", "read_only", "cap_drop", "cap_add", "security_opt", "logging", "sysctls", "tmpfs", "restart", "networks", "env_file", "environment", "volumes", "healthcheck", "depends_on", "mem_limit", "memswap_limit", "cpus", "cpu_shares", "pids_limit", "stop_grace_period", "entrypoint", "command", "init", "working_dir", "ulimits"); err != nil {
		return err
	}
	image, ok := s["image"].(string)
	if !ok {
		return errors.New("service image is required")
	}
	for _, expression := range []string{"${APP_VERSION:?set the exact release commit}", "${APP_VERSION:?}", "${APP_VERSION}", "${APP_VERSION:-latest}", "$APP_VERSION"} {
		image = strings.ReplaceAll(image, expression, version)
	}
	// Other error-message variants are permitted, but no unrelated interpolation.
	image = regexp.MustCompile(`\$\{APP_VERSION:\?[^}]*\}`).ReplaceAllString(image, version)
	if !allowedImage(image, p.ImagePrefix, version) {
		return fmt.Errorf("service %q uses an unauthorized image", name)
	}
	s["image"] = image
	if err := validateEnvFiles(s["env_file"], p, name); err != nil {
		return err
	}
	if raw, exists := s["volumes"]; exists {
		mounts, ok := raw.([]any)
		if !ok {
			return errors.New("service volumes must be a list")
		}
		resources, _ := object(doc["volumes"])
		for _, raw := range mounts {
			mount, ok := raw.(string)
			if !ok {
				return errors.New("only named volume short syntax is permitted")
			}
			parts := strings.Split(mount, ":")
			if len(parts) < 2 || len(parts) > 3 || !identifier.MatchString(parts[0]) || !strings.HasPrefix(parts[1], "/") {
				return errors.New("host and anonymous mounts refused")
			}
			if _, declared := resources[parts[0]]; !declared {
				return errors.New("undeclared volume refused")
			}
			if len(parts) == 3 && parts[2] != "ro" && parts[2] != "rw" {
				return errors.New("unsupported volume option")
			}
		}
	}
	caps := []any{"ALL"}
	if raw, exists := s["cap_drop"]; exists {
		values, ok := raw.([]any)
		if !ok || len(values) != 1 || values[0] != "ALL" {
			return errors.New("all capabilities must be dropped")
		}
	} else {
		s["cap_drop"] = caps
	}
	postgres := strings.HasPrefix(image, "postgres@") || strings.HasPrefix(image, "postgres:") || strings.HasPrefix(image, p.ImagePrefix+"postgres:") || strings.HasPrefix(image, p.ImagePrefix+"postgres@")
	if raw, exists := s["cap_add"]; exists {
		values, ok := raw.([]any)
		if !ok {
			return errors.New("cap_add must be a list")
		}
		for _, value := range values {
			cap, ok := value.(string)
			if !ok || !((postgres && strings.Contains(" CHOWN DAC_OVERRIDE FOWNER SETGID SETUID SETPCAP SYS_NICE ", " "+cap+" ")) || cap == "NET_BIND_SERVICE") {
				return errors.New("capability grant refused")
			}
		}
	} else if postgres {
		s["cap_add"] = []string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"}
	}
	if raw, exists := s["security_opt"]; exists {
		values, ok := raw.([]any)
		if !ok || len(values) != 1 || (values[0] != "no-new-privileges:true" && values[0] != "no-new-privileges=true") {
			return errors.New("security option refused")
		}
	} else {
		s["security_opt"] = []string{"no-new-privileges:true"}
	}
	if raw, exists := s["sysctls"]; exists {
		values, ok := raw.(map[string]any)
		if !ok || len(values) != 1 || fmt.Sprint(values["net.ipv4.ip_unprivileged_port_start"]) != "0" {
			return errors.New("sysctl refused")
		}
	}
	{
		resources, _ := object(doc["networks"])
		var names []string
		raw, exists := s["networks"]
		if !exists {
			raw = []any{"default"}
		}
		switch n := raw.(type) {
		case []any:
			for _, v := range n {
				name, ok := v.(string)
				if !ok {
					return errors.New("invalid service network")
				}
				names = append(names, name)
			}
		case map[string]any:
			for name, cfg := range n {
				options, ok := object(cfg)
				if !ok {
					return errors.New("network attachment options refused")
				}
				if err := keys(options, "network attachment", "aliases"); err != nil {
					return err
				}
				if raw, exists := options["aliases"]; exists {
					aliases, ok := raw.([]any)
					if !ok {
						return errors.New("invalid network aliases")
					}
					network, _ := object(resources[name])
					if network["external"] == true {
						return errors.New("aliases on ingress refused")
					}
					for _, raw := range aliases {
						alias, ok := raw.(string)
						if !ok || !identifier.MatchString(alias) {
							return errors.New("invalid network alias")
						}
					}
				}
				names = append(names, name)
			}
		default:
			return errors.New("invalid service networks")
		}
		for _, netName := range names {
			cfg, declared := resources[netName]
			if !declared && netName == "default" {
				continue
			}
			if !declared {
				return errors.New("undeclared network refused")
			}
			options, _ := object(cfg)
			if options["external"] == true && name != p.App+"-gate" {
				return errors.New("only this app's gateway may join ingress")
			}
		}
	}
	if raw, exists := s["logging"]; exists {
		log, ok := raw.(map[string]any)
		if !ok {
			return errors.New("invalid logging configuration")
		}
		if err := keys(log, "logging", "driver", "options"); err != nil {
			return err
		}
		if log["driver"] != "json-file" {
			return errors.New("logging driver refused")
		}
		opts, ok := object(log["options"])
		if !ok {
			return errors.New("invalid logging options")
		}
		if err := keys(opts, "logging option", "max-size", "max-file"); err != nil {
			return err
		}
	}
	// Logs and process counts are bounded even for older product manifests.
	s["logging"] = map[string]any{"driver": "json-file", "options": map[string]string{"max-size": "10m", "max-file": "3"}}
	if raw, exists := s["pids_limit"]; exists {
		n, err := strconv.Atoi(fmt.Sprint(raw))
		if err != nil || n <= 0 || n > 1024 {
			return errors.New("pids_limit must be between 1 and 1024")
		}
	} else {
		s["pids_limit"] = 128
	}
	if raw, exists := s["ulimits"]; exists {
		limits, ok := raw.(map[string]any)
		if !ok {
			return errors.New("invalid ulimits")
		}
		if err := keys(limits, "ulimit", "nofile", "nproc"); err != nil {
			return err
		}
		for _, raw := range limits {
			values, ok := raw.(map[string]any)
			if !ok {
				return errors.New("ulimits require bounded soft/hard values")
			}
			if err := keys(values, "ulimit", "soft", "hard"); err != nil {
				return err
			}
			soft, e1 := strconv.Atoi(fmt.Sprint(values["soft"]))
			hard, e2 := strconv.Atoi(fmt.Sprint(values["hard"]))
			if e1 != nil || e2 != nil || soft <= 0 || hard < soft || hard > 65536 {
				return errors.New("ulimits must be bounded")
			}
		}
	}
	if raw, exists := s["healthcheck"]; exists {
		h, ok := raw.(map[string]any)
		if !ok {
			return errors.New("invalid healthcheck")
		}
		if err := keys(h, "healthcheck", "test", "interval", "timeout", "retries", "start_period", "start_interval", "disable"); err != nil {
			return err
		}
	}
	return nil
}

func allowedImage(image, prefix, version string) bool {
	if strings.ContainsAny(image, " $\\\n\r\t") {
		return false
	}
	if strings.HasPrefix(image, prefix) {
		ref := strings.TrimPrefix(image, prefix)
		parts := strings.SplitN(ref, "@", 2)
		if len(parts) == 2 {
			component := strings.TrimSuffix(parts[0], ":"+version)
			return identifier.MatchString(component) && digest.MatchString(parts[1])
		}
		parts = strings.SplitN(ref, ":", 2)
		return len(parts) == 2 && identifier.MatchString(parts[0]) && parts[1] == version
	}
	// Dependency images are accepted only from these upstream repositories and
	// only by digest; a compromised app publisher cannot write these repositories.
	for _, base := range []string{"postgres", "redis"} {
		parts := strings.SplitN(image, "@", 2)
		if len(parts) != 2 || !digest.MatchString(parts[1]) {
			continue
		}
		if parts[0] == base || (strings.HasPrefix(parts[0], base+":") && revision.MatchString(strings.TrimPrefix(parts[0], base+":"))) {
			return true
		}
	}
	return false
}

func validateEnvFiles(raw any, p Policy, service string) error {
	if raw == nil {
		return nil
	}
	var files []any
	if s, ok := raw.(string); ok {
		files = []any{s}
	} else {
		var ok bool
		files, ok = raw.([]any)
		if !ok {
			return errors.New("env_file must contain relative filenames")
		}
	}
	for _, raw := range files {
		name, ok := raw.(string)
		if !ok || strings.ContainsAny(name, "$\x00\n\r") || filepath.IsAbs(name) {
			return errors.New("env_file must be a literal app-relative filename")
		}
		clean := filepath.Clean(name)
		allowed := clean == "secrets.env" || clean == "secrets/current/"+service+".env" || clean == "secrets/"+service+".env"
		if service == "postgres" && (clean == "postgres-owner.env" || clean == "secrets/postgres-owner.env") {
			allowed = true
		}
		if !allowed {
			return errors.New("env_file is outside service secret scope")
		}
		target := filepath.Join(p.AppDir, clean)
		if real, err := filepath.EvalSymlinks(target); err == nil && !within(real, p.AppDir) {
			return errors.New("env_file symlink escapes this app")
		}
	}
	return nil
}

func within(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
