package project

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

var verificationStages = []string{"lint", "unit", "integration", "build", "artifact-check", "vuln", "browser-install", "e2e"}

type VerificationRule struct {
	Paths   []string `json:"paths"`
	Targets []string `json:"targets"`
}

type VerificationPolicy struct {
	Version     int                `json:"version"`
	FullTargets []string           `json:"full_targets"`
	Always      []string           `json:"always,omitempty"`
	Rules       []VerificationRule `json:"rules,omitempty"`
	ForceFull   []string           `json:"force_full,omitempty"`
}

type VerificationPlan struct {
	Version        int      `json:"version"`
	Head           string   `json:"head"`
	Base           string   `json:"base,omitempty"`
	ChangedPaths   []string `json:"changed_paths"`
	PathsTruncated bool     `json:"paths_truncated,omitempty"`
	ManifestSHA256 string   `json:"manifest_sha256"`
	PolicySHA256   string   `json:"policy_sha256"`
	Mode           string   `json:"mode"`
	Targets        []string `json:"targets"`
	Reasons        []string `json:"reasons"`
	Command        []string `json:"command"`
	Note           string   `json:"note"`
}

func (m Manifest) verificationPolicy() VerificationPolicy {
	if m.Verification != nil {
		return *m.Verification
	}
	return VerificationPolicy{Version: 1, FullTargets: slices.Clone(verificationStages)}
}

func (m Manifest) validateVerification() error {
	p := m.Verification
	if p == nil {
		return nil
	}
	if p.Version != 1 || len(p.FullTargets) == 0 || len(p.Rules) > 128 || len(p.ForceFull) > 128 {
		return errors.New("verification requires version 1 and a bounded complete gate")
	}
	full := map[string]bool{}
	for _, name := range p.FullTargets {
		if full[name] || !slices.Contains(verificationStages, name) && name != "test" {
			return fmt.Errorf("invalid or duplicate verification target %q", name)
		}
		full[name] = true
	}
	contract, err := m.Contract()
	if err != nil {
		return err
	}
	stages := contract["stages"].(map[string]json.RawMessage)
	for _, name := range verificationStages {
		var commands [][]string
		if json.Unmarshal(stages[name], &commands) != nil {
			continue
		}
		covered := full[name] || (name == "unit" || name == "integration") && full["test"] ||
			name == "build" && (full["artifact-check"] || full["e2e"]) ||
			name == "browser-install" && (full["e2e"] || m.ArtifactBrowser && full["artifact-check"])
		if !covered {
			return fmt.Errorf("verification full_targets omits applicable stage %s", name)
		}
	}
	validTargets := func(targets []string) bool {
		seen := map[string]bool{}
		for _, name := range targets {
			if !full[name] || seen[name] {
				return false
			}
			seen[name] = true
		}
		return true
	}
	patterns := slices.Clone(p.ForceFull)
	if !validTargets(p.Always) {
		return errors.New("verification always must select unique full-gate targets")
	}
	for _, rule := range p.Rules {
		if len(rule.Paths) == 0 || len(rule.Paths) > 128 || !validTargets(rule.Targets) {
			return errors.New("verification rules must select explicit paths and full-gate targets")
		}
		patterns = append(patterns, rule.Paths...)
	}
	if len(patterns) > 1024 {
		return errors.New("verification patterns exceed the finite policy budget")
	}
	for _, pattern := range patterns {
		if len(pattern) == 0 || len(pattern) > 512 || !safeInputPath(pattern) {
			return errors.New("verification patterns must remain inside the checkout")
		}
	}
	return nil
}

func safeInputPath(name string) bool {
	return name != "" && !strings.ContainsAny(name, "\\\x00\r\n") && !strings.HasPrefix(name, "/") &&
		!slices.Contains(strings.Split(name, "/"), "..")
}

func selectedVerification(p VerificationPolicy, changed []string, event string) (string, []string, []string) {
	full := event != "local" && event != "pull_request"
	selected := map[string]bool{}
	for _, name := range p.Always {
		selected[name] = true
	}
	reasons := []string{}
	if full {
		return "full", slices.Clone(p.FullTargets), []string{"This event requires complete verification"}
	}
	addReason := func(reason string) {
		if len(reasons) < 256 {
			reasons = append(reasons, reason)
		}
	}
	matchers := map[string]*regexp.Regexp{}
	matches := func(pattern, name string) bool {
		matcher := matchers[pattern]
		if matcher == nil {
			patternText := regexp.QuoteMeta(pattern)
			patternText = strings.ReplaceAll(strings.ReplaceAll(patternText, `\*`, ".*"), `\?`, ".")
			matcher = regexp.MustCompile("^(?:" + patternText + ")$")
			matchers[pattern] = matcher
		}
		return matcher.MatchString(name)
	}
	sensitive := []string{"komizo.json", "komizo.lock", ".github/*", ".gitmodules", "go.mod", "go.sum", "*/go.mod", "*/go.sum", "package.json", "*/package.json", "*lock*", "*requirements*"}
	for _, name := range changed {
		force := !safeInputPath(name)
		for _, pattern := range append(sensitive, p.ForceFull...) {
			force = force || matches(pattern, name)
		}
		if force {
			addReason(name + ": shared, policy or dependency input requires complete verification")
			return "full", slices.Clone(p.FullTargets), reasons
		}
		matched := false
		for _, rule := range p.Rules {
			for _, pattern := range rule.Paths {
				if matches(pattern, name) {
					matched = true
					for _, target := range rule.Targets {
						selected[target] = true
					}
					addReason(name + ": selects " + strings.Join(rule.Targets, ", "))
					break
				}
			}
		}
		if !matched {
			addReason(name + ": no reviewed dependency rule; complete verification required")
			return "full", slices.Clone(p.FullTargets), reasons
		}
	}
	targets := []string{}
	for _, name := range p.FullTargets {
		if selected[name] {
			targets = append(targets, name)
		}
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "No changed inputs; always-required checks remain")
	}
	return "focused", targets, reasons
}

type boundedGitOutput struct {
	buffer    bytes.Buffer
	truncated bool
}

func (b *boundedGitOutput) Write(p []byte) (int, error) {
	count := len(p)
	remaining := (1 << 20) - b.buffer.Len()
	if count > remaining {
		p, b.truncated = p[:remaining], true
	}
	_, _ = b.buffer.Write(p)
	return count, nil // Drain the process even after the retention ceiling.
}

func verificationGit(ctx context.Context, root string, args ...string) ([]byte, error) {
	command := exec.Command("git", append([]string{"-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false"}, args...)...)
	var output boundedGitOutput
	command.Dir, command.Stdout, command.Stderr = root, &output, io.Discard
	// Ignore inherited Git overrides and optional external filesystem monitors.
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_OPTIONAL_LOCKS=0"}
	if err := runCommand(ctx, command); err != nil {
		return nil, err
	}
	if output.truncated {
		return nil, errors.New("Git input inventory exceeds 1 MiB")
	}
	return output.buffer.Bytes(), nil
}

// Plan reads bounded source metadata only. It never installs tools, executes
// caller commands or produces test/build/publication authority.
func Plan(ctx context.Context, root, platform, base string) (VerificationPlan, error) {
	var plan VerificationPlan
	m, data, err := Read(root)
	if err != nil {
		return plan, err
	}
	if err = CheckLock(root, platform, data, m); err != nil {
		return plan, err
	}
	if base != "" && !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(base) {
		return plan, errors.New("verification base must be an exact commit")
	}
	head, err := verificationGit(ctx, root, "rev-parse", "HEAD")
	if err != nil {
		return plan, err
	}
	p := m.verificationPolicy()
	policyBytes, _ := json.Marshal(p)
	plan = VerificationPlan{Version: 1, Head: strings.TrimSpace(string(head)), Base: base, ChangedPaths: []string{},
		ManifestSHA256: digest(data), PolicySHA256: digest(policyBytes),
		Mode: "full", Targets: slices.Clone(p.FullTargets), Reasons: []string{"No base selected; complete verification required"},
		Note: "Selection is not test, build or publication evidence."}
	if base != "" {
		_, ancestorErr := verificationGit(ctx, root, "merge-base", "--is-ancestor", base, plan.Head)
		if ancestorErr != nil {
			if ctx.Err() != nil {
				return plan, ctx.Err()
			}
			plan.Reasons = []string{"Base is unavailable or is not an ancestor; complete verification required"}
		} else {
			tracked, err := verificationGit(ctx, root, "diff", "--no-ext-diff", "--no-textconv", "--name-only", "--no-renames", "-z", base, "--")
			if err != nil {
				return plan, err
			}
			untracked, err := verificationGit(ctx, root, "ls-files", "--others", "--exclude-standard", "-z")
			if err != nil {
				return plan, err
			}
			names := map[string]bool{}
			for _, name := range strings.Split(string(tracked)+string(untracked), "\x00") {
				if name != "" {
					names[filepath.ToSlash(name)] = true
				}
			}
			for name := range names {
				plan.ChangedPaths = append(plan.ChangedPaths, name)
			}
			sort.Strings(plan.ChangedPaths)
			retained, size := 0, 0
			for _, name := range plan.ChangedPaths {
				if retained >= 4096 || size+len(name) > 256<<10 {
					break
				}
				retained++
				size += len(name)
			}
			if retained < len(plan.ChangedPaths) {
				plan.PathsTruncated = true
				plan.ChangedPaths = plan.ChangedPaths[:retained]
				plan.Reasons = []string{"Input inventory exceeds the display budget; complete verification required"}
				plan.Command = append([]string{"komizo", "run", "install"}, plan.Targets...)
				return plan, nil
			}
			event := os.Getenv("GITHUB_EVENT_NAME")
			if event == "" {
				event = "local"
			}
			plan.Mode, plan.Targets, plan.Reasons = selectedVerification(p, plan.ChangedPaths, event)
		}
	}
	plan.Command = []string{}
	if len(plan.Targets) > 0 {
		plan.Command = append([]string{"komizo", "run", "install"}, plan.Targets...)
	}
	return plan, nil
}

// CheckSelected retains workflow preflight and the complete declared toolchain.
// Selection evidence is separate from actual test/build receipts.
func CheckSelected(ctx context.Context, root, platform, base string, in io.Reader, progress io.Writer) (result Result, err error) {
	defer func() { result.failed(err) }()
	if _, err = Validate(root, platform); err != nil {
		return result, err
	}
	plan, err := Plan(ctx, root, platform, base)
	if err != nil {
		return result, err
	}
	if err = projectDirectory(root, ".artifacts", "contract"); err != nil {
		return result, err
	}
	if err = writeJSON(filepath.Join(root, ".artifacts/contract/verification-plan.json"), plan); err != nil {
		return result, err
	}
	if len(plan.Targets) == 0 {
		m, _, readErr := Read(root)
		if readErr != nil {
			return result, readErr
		}
		return Result{Recipe: m.Recipe, Completed: true, Targets: []string{}, Selection: &plan}, nil
	}
	result, err = Execute(ctx, root, platform, append([]string{"install"}, plan.Targets...), "auto", nil, in, progress)
	result.Selection = &plan
	return result, err
}
