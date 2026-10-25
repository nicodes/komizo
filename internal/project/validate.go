package project

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

type WorkflowPolicy struct {
	Required []string `json:"required"`
	CIGates  []string `json:"ci_gates"`
}

type Validation struct {
	Recipe    string   `json:"recipe"`
	Workflows []string `json:"workflows"`
	Checks    []string `json:"checks"`
}

var fullRef = regexp.MustCompile(`^[a-f0-9]{40}$`)
var pinnedImage = regexp.MustCompile(`@sha256:[a-f0-9]{64}$`)
var workflowNames = map[string]string{
	"ci.yml": "Build & Test", "cd.yml": "Deploy", "pr-preview.yml": "PR Preview",
	"dependency-maintenance.yml": "Dependency Maintenance", "dependency-policy.yml": "Dependency Policy",
	"security-scan.yml": "Security Scan", "production-verification.yml": "Production Verification",
	"backup.yml": "Backup", "recovery.yml": "Recovery", "production-diagnostics.yml": "Production Diagnostics",
	"release.yml": "Release", "fleet-audit.yml": "Fleet Audit", "ghenv.yml": "Local Environment",
}

func mapping(value any) map[string]any {
	if m, ok := value.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func eventMap(value any) map[string]any {
	if name, ok := value.(string); ok {
		return map[string]any{name: nil}
	}
	if names, ok := value.([]any); ok {
		m := map[string]any{}
		for _, name := range names {
			if s, ok := name.(string); ok {
				m[s] = nil
			}
		}
		return m
	}
	return mapping(value)
}

func noDuplicateYAML(node *yaml.Node) error {
	if node.Kind == yaml.AliasNode {
		return errors.New("workflow aliases must be expanded")
	}
	if node.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Value == "<<" || seen[key.Value] {
				return errors.New("duplicate, merged or non-scalar YAML key")
			}
			seen[key.Value] = true
		}
	}
	for _, child := range node.Content {
		if err := noDuplicateYAML(child); err != nil {
			return err
		}
	}
	return nil
}

func validateUses(value string) error {
	if strings.HasPrefix(value, "./") {
		return nil
	}
	if strings.HasPrefix(value, "docker://") && pinnedImage.MatchString(value) {
		return nil
	}
	_, ref, ok := strings.Cut(value, "@")
	if !ok || !fullRef.MatchString(ref) {
		return errors.New("remote actions and reusable workflows require full commit pins")
	}
	return nil
}

func Validate(root, platform string) (Validation, error) {
	m, data, err := Read(root)
	report := Validation{Recipe: m.Recipe}
	if err != nil {
		return report, err
	}
	if err = CheckLock(root, platform, data, m); err != nil {
		return report, err
	}
	policy := WorkflowPolicy{Required: []string{"ci.yml"}}
	if raw := m.Validation["workflow"]; len(raw) > 0 {
		if err = decode(raw, &policy); err != nil {
			return report, err
		}
	}
	required := map[string]bool{}
	for _, name := range policy.Required {
		if _, ok := workflowNames[name]; !ok {
			return report, fmt.Errorf("unknown workflow purpose %q", name)
		}
		required[name] = true
	}
	folder := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(folder)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && m.Validation["workflow"] == nil {
			report.Checks = []string{"manifest", "platform lock"}
			return report, nil
		}
		return report, err
	}
	for _, entry := range entries {
		name := entry.Name()
		if filepath.Ext(name) != ".yml" && filepath.Ext(name) != ".yaml" {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
			return report, errors.New("workflow must be a regular file")
		}
		b, err := os.ReadFile(filepath.Join(folder, name))
		if err != nil {
			return report, err
		}
		var node yaml.Node
		if err = yaml.Unmarshal(b, &node); err != nil {
			return report, err
		}
		if err = noDuplicateYAML(&node); err != nil {
			return report, fmt.Errorf("%s: %w", name, err)
		}
		var doc map[string]any
		if err = node.Decode(&doc); err != nil {
			return report, err
		}
		if expected, known := workflowNames[name]; known && doc["name"] != expected {
			return report, fmt.Errorf("%s: expected name %s", name, expected)
		}
		events := eventMap(doc["on"])
		jobs := mapping(doc["jobs"])
		if len(jobs) == 0 {
			return report, fmt.Errorf("%s: no executable jobs", name)
		}
		if name == "ci.yml" {
			if _, ok := events["pull_request"]; !ok {
				return report, errors.New("CI requires pull_request")
			}
			if _, ok := events["workflow_dispatch"]; !ok {
				return report, errors.New("CI requires workflow_dispatch")
			}
			if len(m.Images) > 0 {
				if _, ok := events["push"]; ok {
					return report, errors.New("product CI duplicates main Deploy verification")
				}
			}
			types, _ := mapping(events["pull_request"])["types"].([]any)
			seenTypes := map[string]bool{}
			for _, v := range types {
				if s, ok := v.(string); ok {
					seenTypes[s] = true
				}
			}
			for _, v := range []string{"opened", "synchronize", "reopened", "ready_for_review"} {
				if !seenTypes[v] {
					return report, fmt.Errorf("CI lacks PR lifecycle event %s", v)
				}
			}
			seen := map[string]bool{}
			for key, value := range jobs {
				n, _ := mapping(value)["name"].(string)
				if n == "" {
					n = key
				}
				seen[n] = true
			}
			for _, gate := range policy.CIGates {
				if !seen[gate] {
					return report, fmt.Errorf("required CI gate %s is absent", gate)
				}
			}
		}
		if name == "cd.yml" {
			branches, _ := mapping(events["push"])["branches"].([]any)
			if len(branches) != 1 || branches[0] != "main" {
				return report, errors.New("Deploy requires a main-only push")
			}
			if _, ok := events["workflow_dispatch"]; !ok {
				return report, errors.New("Deploy requires manual dispatch")
			}
			if mapping(doc["concurrency"])["cancel-in-progress"] != false {
				return report, errors.New("deployment cancellation must remain disabled")
			}
		}
		if name == "recovery.yml" || name == "production-diagnostics.yml" || name == "ghenv.yml" {
			if len(events) != 1 {
				return report, fmt.Errorf("%s must be manual only", name)
			}
			if _, ok := events["workflow_dispatch"]; !ok {
				return report, fmt.Errorf("%s must be manual only", name)
			}
		}
		for key, value := range jobs {
			job := mapping(value)
			if used, ok := job["uses"].(string); ok {
				if err = validateUses(used); err != nil {
					return report, fmt.Errorf("%s/%s: %w", name, key, err)
				}
			}
			steps, _ := job["steps"].([]any)
			if len(steps) == 0 && job["uses"] == nil {
				return report, fmt.Errorf("%s/%s has no implementation", name, key)
			}
			if name == "ghenv.yml" {
				env := job["environment"]
				if obj, ok := env.(map[string]any); ok {
					env = obj["name"]
				}
				if env != nil && env != "Preview" {
					return report, errors.New("local handoffs may only select Preview")
				}
			}
			for _, value := range steps {
				step := mapping(value)
				used, _ := step["uses"].(string)
				if used != "" {
					if err = validateUses(used); err != nil {
						return report, fmt.Errorf("%s/%s: %w", name, key, err)
					}
				}
				if _, privileged := events["pull_request_target"]; privileged && strings.HasPrefix(used, "actions/checkout@") {
					ref, _ := mapping(step["with"])["ref"].(string)
					if strings.Contains(ref, "pull_request.head") || strings.Contains(ref, "head_ref") {
						return report, errors.New("privileged workflow checks out untrusted PR source")
					}
				}
			}
		}
		delete(required, name)
		report.Workflows = append(report.Workflows, name)
	}
	if len(required) > 0 {
		var names []string
		for n := range required {
			names = append(names, n)
		}
		sort.Strings(names)
		return report, fmt.Errorf("required workflows missing: %s", strings.Join(names, ", "))
	}
	if operations := m.Validation["operations"]; len(operations) > 0 {
		var specs map[string]struct {
			Commands [][]string `json:"commands"`
			Timeout  int        `json:"timeout_seconds,omitempty"`
		}
		if err = decode(operations, &specs); err != nil {
			return report, err
		}
		for name, spec := range specs {
			if len(spec.Commands) == 0 {
				return report, fmt.Errorf("%s has no operation", name)
			}
			for _, command := range spec.Commands {
				if len(command) == 0 || command[0] == "echo" || command[0] == "true" || command[0] == ":" {
					return report, errors.New("successful placeholders are not operations")
				}
				for _, arg := range command {
					if arg == "" || strings.ContainsRune(arg, 0) {
						return report, errors.New("invalid fixed operation arguments")
					}
				}
			}
		}
	}
	report.Checks = []string{"manifest", "platform lock", "workflow purposes", "immutable action pins", "privileged source boundaries", "fixed operations"}
	return report, nil
}
