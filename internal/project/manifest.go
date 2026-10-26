package project

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
)

const ManifestName = "komizo.json"
const LockName = "komizo.lock"

type Auth struct {
	Provider string `json:"provider"`
	API      bool   `json:"api"`
}

// Manifest contains project inputs. Deployment authority is operator-owned.
type Manifest struct {
	Version                  int                        `json:"version"`
	Recipe                   string                     `json:"recipe"`
	Repository               string                     `json:"repository,omitempty"`
	Tools                    map[string]json.RawMessage `json:"tools,omitempty"`
	Stages                   map[string]json.RawMessage `json:"stages,omitempty"`
	Tasks                    map[string]json.RawMessage `json:"tasks,omitempty"`
	Artifacts                []string                   `json:"artifacts,omitempty"`
	Images                   []string                   `json:"images,omitempty"`
	Auth                     *Auth                      `json:"auth,omitempty"`
	BuildEnvironment         []string                   `json:"build_environment,omitempty"`
	BuildEnvironmentDefaults map[string]string          `json:"build_environment_defaults,omitempty"`
	RevisionEnvironment      []string                   `json:"revision_environment,omitempty"`
	ArtifactBrowser          bool                       `json:"artifact_browser,omitempty"`
	Release                  map[string]string          `json:"release,omitempty"`
	Development              map[string]json.RawMessage `json:"development,omitempty"`
	Verification             *VerificationPolicy        `json:"verification,omitempty"`
	Validation               map[string]json.RawMessage `json:"validation,omitempty"`
}

type Lock struct {
	Version          int    `json:"version"`
	Platform         string `json:"platform"`
	PlatformRevision string `json:"platform_revision"`
	ManifestSHA256   string `json:"manifest_sha256"`
	RuntimeSHA256    string `json:"runtime_sha256"`
	RecipeSHA256     string `json:"recipe_sha256"`
}

func SourceRevision() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				return setting.Value
			}
		}
	}
	return ""
}

var stageNames = []string{"install", "lint", "unit", "integration", "build", "artifact-check", "browser-install", "e2e", "vuln", "dev", "stop", "clean"}
var exactVersion = regexp.MustCompile(`^(?:[a-z][a-z0-9]*-)?v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?$`)
var toolName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_:/@.+-]*$`)

func digest(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// uniqueJSON rejects duplicate fields at every nesting level and trailing input.
func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("manifest nesting exceeds 32 levels")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("duplicate or invalid JSON field")
				}
				seen[name] = true
				if err := uniqueJSON(d, depth+1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := uniqueJSON(d, depth+1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		if _, err := d.Token(); err != nil {
			return err
		}
	}
	if depth == 0 {
		if _, err := d.Token(); err != io.EOF {
			return errors.New("trailing JSON input")
		}
	}
	return nil
}

func decode(data []byte, v any) error {
	if len(data) > 1<<20 {
		return errors.New("project configuration exceeds 1 MiB")
	}
	if err := uniqueJSON(json.NewDecoder(bytes.NewReader(data)), 0); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

func Read(root string) (Manifest, []byte, error) {
	var m Manifest
	p := filepath.Join(root, ManifestName)
	info, err := os.Lstat(p)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return m, nil, errors.New("a regular komizo.json is required; run komizo init --recipe RECIPE")
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return m, nil, err
	}
	if err = decode(data, &m); err != nil {
		return m, nil, fmt.Errorf("invalid komizo.json: %w", err)
	}
	if m.Version != 1 {
		return m, nil, errors.New("komizo.json requires version 1")
	}
	if _, err := recipe(m.Recipe); err != nil {
		return m, nil, err
	}
	if m.Auth == nil && (m.Recipe == "go-service" || m.Recipe == "godot-app") {
		return m, nil, errors.New("application recipes must declare auth.provider and auth.api")
	}
	if m.Auth != nil && m.Auth.Provider != "none" && m.Auth.Provider != "clerk" {
		return m, nil, errors.New("unsupported authentication provider")
	}
	for name, value := range m.Tools {
		if !toolName.MatchString(name) || strings.HasPrefix(name, "http:cicd-engineering") || strings.Contains(name, "ghenv") {
			return m, nil, fmt.Errorf("invalid or redundant tool %q", name)
		}
		var version string
		if json.Unmarshal(value, &version) != nil {
			var spec map[string]json.RawMessage
			if json.Unmarshal(value, &spec) != nil || json.Unmarshal(spec["version"], &version) != nil {
				return m, nil, fmt.Errorf("tool %s requires an exact version", name)
			}
		}
		if !exactVersion.MatchString(version) {
			return m, nil, fmt.Errorf("tool %s requires an exact version", name)
		}
	}
	for name := range m.Stages {
		if !knownStage(name) {
			return m, nil, fmt.Errorf("unknown stage %q", name)
		}
		if err := validateStage(m.Stages[name]); err != nil {
			return m, nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	for name, value := range m.Tasks {
		if !regexp.MustCompile(`^[a-z][a-z0-9-]*$`).MatchString(name) || knownStage(name) || name == "test" || name == "check" || name == "validate" {
			return m, nil, fmt.Errorf("invalid or reserved task %q", name)
		}
		var commands [][]string
		if err := json.Unmarshal(value, &commands); err != nil || len(commands) == 0 {
			return m, nil, fmt.Errorf("%s: tasks require commands", name)
		}
		if err := validateStage(value); err != nil {
			return m, nil, err
		}
	}
	for name := range m.Development {
		if !strings.Contains(" default_mode secrets variables prefixes aliases environment ", " "+name+" ") {
			return m, nil, fmt.Errorf("unknown development field %q", name)
		}
	}
	for name := range m.Validation {
		if name != "workflow" {
			return m, nil, fmt.Errorf("unknown validation field %q", name)
		}
	}
	for _, name := range m.Artifacts {
		if name == "" || name == "." || filepath.IsAbs(name) || strings.Contains(name, "\\") || strings.ContainsAny(strings.Split(name, "/")[0], "*?[") {
			return m, nil, errors.New("artifacts must be relative checkout paths")
		}
		for _, part := range strings.Split(name, "/") {
			if part == ".." || part == ".git" {
				return m, nil, errors.New("artifact path leaves the project")
			}
		}
	}
	if err := m.validateVerification(); err != nil {
		return m, nil, err
	}
	return m, data, nil
}

func validateStage(value json.RawMessage) error {
	var skip struct {
		Inapplicable string `json:"inapplicable"`
	}
	if decode(value, &skip) == nil && strings.TrimSpace(skip.Inapplicable) != "" {
		return nil
	}
	var commands [][]string
	if json.Unmarshal(value, &commands) != nil || len(commands) == 0 {
		return errors.New("supply argument arrays or an explicit inapplicable reason")
	}
	for _, command := range commands {
		if len(command) == 0 {
			return errors.New("empty command")
		}
		for _, argument := range command {
			if argument == "" || strings.ContainsRune(argument, 0) {
				return errors.New("empty or invalid command argument")
			}
		}
	}
	return nil
}

func knownStage(name string) bool {
	for _, stage := range stageNames {
		if stage == name {
			return true
		}
	}
	return false
}

func command(args ...string) json.RawMessage {
	b, _ := json.Marshal([][]string{args})
	return b
}

func inapplicable(reason string) json.RawMessage {
	b, _ := json.Marshal(map[string]string{"inapplicable": reason})
	return b
}

func recipe(name string) (map[string]json.RawMessage, error) {
	stages := map[string]json.RawMessage{}
	switch name {
	case "godot-app":
		for _, stage := range stageNames {
			stages[stage] = command("bash", "scripts/"+stage+".sh")
		}
	case "godot-addon":
		for _, stage := range stageNames {
			stages[stage] = inapplicable("No " + stage + " operation is declared for this addon")
		}
		for _, stage := range []string{"install", "lint", "unit", "build", "artifact-check", "clean"} {
			stages[stage] = command("python3", "-c", `import os,runpy;runpy.run_path(os.environ["CICD_ENGINEERING"]+"/helpers/godot-addon.py",run_name="__main__")`, stage)
		}
		stages["dev"] = inapplicable("Use the addon from a consuming Godot project")
		stages["stop"] = inapplicable("An addon has no standalone development process")
	case "go-service":
		for _, stage := range stageNames {
			stages[stage] = inapplicable("No " + stage + " operation is declared for this Go application")
		}
		helper := func(stage string) json.RawMessage {
			return command("python3", "-c", `import os,runpy;runpy.run_path(os.environ["CICD_ENGINEERING"]+"/helpers/go-project.py",run_name="__main__")`, stage)
		}
		stages["install"] = command("go", "mod", "download")
		stages["lint"] = helper("lint")
		stages["unit"] = command("go", "test", "-race", "-count=1", "./...")
		stages["build"] = helper("build")
		stages["artifact-check"] = helper("artifact-check")
		stages["vuln"] = command("govulncheck", "./...")
		stages["dev"] = command("go", "run", ".")
		stages["clean"] = helper("clean")
		stages["stop"] = inapplicable("Development runs in the foreground; Ctrl-C stops its process group")
	case "go-cli", "go-library":
		stages, _ = recipe("go-service")
		if name == "go-library" {
			stages["build"] = command("go", "build", "./...")
			stages["artifact-check"] = inapplicable("Go modules distribute reviewed source; no application executable is published")
			stages["dev"] = inapplicable("A library has no foreground application; use its focused tests")
			stages["stop"] = inapplicable("A library has no development process to stop")
		}
	case "configuration":
		for _, stage := range stageNames {
			stages[stage] = inapplicable("No " + stage + " operation is declared for this configuration project")
		}
		stages["lint"] = command("bash", "scripts/lint.sh")
		stages["unit"] = command("bash", "scripts/unit.sh")
	case "static-site":
		for _, stage := range stageNames {
			stages[stage] = inapplicable("Static site: no " + stage + " operation is declared")
		}
		stages["install"] = command("bun", "install", "--frozen-lockfile")
		stages["build"] = command("bun", "run", "build")
		stages["artifact-check"] = command("bash", "scripts/test-site.sh")
		stages["dev"] = command("python3", "-c", `import os,runpy;runpy.run_path(os.environ["CICD_ENGINEERING"]+"/helpers/static-site.py",run_name="__main__")`)
		stages["stop"] = inapplicable("Development runs in the foreground; Ctrl-C stops its process group")
		stages["clean"] = command("bun", "-e", `const fs=require('node:fs');for(const p of ['dist','.astro'])fs.rmSync(p,{recursive:true,force:true})`)
	default:
		return nil, fmt.Errorf("unknown recipe %q; choose static-site, go-service, go-cli, go-library, godot-app, godot-addon or configuration", name)
	}
	return stages, nil
}

func (m Manifest) Contract() (map[string]any, error) {
	stages, err := recipe(m.Recipe)
	if err != nil {
		return nil, err
	}
	for k, v := range m.Stages {
		stages[k] = v
	}
	artifacts := m.Artifacts
	if len(artifacts) == 0 {
		artifacts = []string{".artifacts/build"}
		if m.Recipe == "static-site" || m.Recipe == "godot-addon" {
			artifacts = []string{"dist"}
		} else if m.Recipe == "go-library" {
			artifacts = []string{}
		}
	}
	result := map[string]any{"version": 1, "stages": stages, "artifacts": artifacts, "artifact_browser": m.ArtifactBrowser}
	if m.Recipe == "go-library" && len(artifacts) == 0 && len(m.Images) == 0 {
		result["source_only_build"] = true
	}
	if len(m.Tasks) > 0 {
		result["tasks"] = m.Tasks
	}
	if m.Verification != nil {
		result["check_targets"] = m.Verification.FullTargets
	} else if m.Recipe == "godot-addon" {
		result["check_targets"] = []string{"lint", "build", "test", "artifact-check"}
	}
	if len(m.Images) > 0 {
		result["images"] = m.Images
	}
	if m.Auth != nil {
		result["auth"] = map[string]any{"provider": m.Auth.Provider, "api": m.Auth.API, "enforced": true}
	}
	if len(m.BuildEnvironment) > 0 {
		result["build_environment"] = m.BuildEnvironment
	}
	if len(m.BuildEnvironmentDefaults) > 0 {
		result["build_environment_defaults"] = m.BuildEnvironmentDefaults
	}
	if len(m.RevisionEnvironment) > 0 {
		result["revision_environment"] = m.RevisionEnvironment
	}
	if len(m.Release) > 0 {
		result["release"] = m.Release
	}
	return result, nil
}

func Init(root, name, platform string) (Lock, error) {
	if _, err := recipe(name); err != nil {
		return Lock{}, err
	}
	if _, err := os.Lstat(filepath.Join(root, ManifestName)); !errors.Is(err, os.ErrNotExist) {
		return Lock{}, errors.New("komizo.json already exists or cannot be inspected")
	}
	m := Manifest{Version: 1, Recipe: name}
	if name == "go-service" || name == "godot-app" {
		m.Auth = &Auth{Provider: "none"}
	}
	if err := writeJSON(filepath.Join(root, ManifestName), m); err != nil {
		return Lock{}, err
	}
	ignore := filepath.Join(root, ".gitignore")
	data, err := os.ReadFile(ignore)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Lock{}, err
	}
	for _, line := range []string{".artifacts/", ".komizo.mise*.toml", ".komizo.mise*.lock"} {
		if !strings.Contains("\n"+string(data)+"\n", "\n"+line+"\n") {
			data = append(data, []byte("\n"+line+"\n")...)
		}
	}
	if err = atomicFile(ignore, data, 0o644); err != nil {
		return Lock{}, err
	}
	return WriteLock(root, platform)
}

func WriteLock(root, platform string) (Lock, error) {
	m, data, err := Read(root)
	if err != nil {
		return Lock{}, err
	}
	r, _ := recipe(m.Recipe)
	b, _ := json.Marshal(map[string]any{"stages": r, "tools": recipeTools(m.Recipe)})
	l := Lock{Version: 1, Platform: platform, PlatformRevision: SourceRevision(), ManifestSHA256: digest(data), RuntimeSHA256: RuntimeIdentity(), RecipeSHA256: digest(b)}
	return l, writeJSON(filepath.Join(root, LockName), l)
}

func CheckLock(root, platform string, data []byte, m Manifest) error {
	info, err := os.Lstat(filepath.Join(root, LockName))
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return errors.New("a bounded regular komizo.lock is required; run komizo lock")
	}
	b, err := os.ReadFile(filepath.Join(root, LockName))
	if err != nil {
		return errors.New("komizo.lock is required; run komizo lock")
	}
	var lock Lock
	if err := decode(b, &lock); err != nil {
		return err
	}
	r, _ := recipe(m.Recipe)
	raw, _ := json.Marshal(map[string]any{"stages": r, "tools": recipeTools(m.Recipe)})
	if lock.Version != 1 || lock.Platform != platform || lock.PlatformRevision != SourceRevision() || lock.ManifestSHA256 != digest(data) || lock.RuntimeSHA256 != RuntimeIdentity() || lock.RecipeSHA256 != digest(raw) {
		return errors.New("project lock differs from the manifest or installed Komizo; run komizo lock with the intended platform version")
	}
	return nil
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return atomicFile(path, append(data, '\n'), 0o600)
}

func recipeTools(name string) map[string]json.RawMessage {
	tools := map[string]json.RawMessage{"python": json.RawMessage(`"3.13.11"`)}
	if name == "go-service" || name == "go-cli" || name == "go-library" {
		tools["go"] = json.RawMessage(`"1.27.3"`)
		tools["go:golang.org/x/vuln/cmd/govulncheck"] = json.RawMessage(`"1.7.0"`)
	}
	if name == "static-site" || name == "godot-app" {
		tools["bun"] = json.RawMessage(`"1.4.1"`)
		tools["node"] = json.RawMessage(`"24.18.1"`)
	}
	return tools
}
func (m Manifest) ToolsForRecipe() map[string]json.RawMessage {
	tools := recipeTools(m.Recipe)
	for name, version := range m.Tools {
		tools[name] = version
	}
	return tools
}
