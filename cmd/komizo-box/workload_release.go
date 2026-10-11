package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/nicodes/komizo/internal/workload"
)

func runWorkloadRelease(args []string) error {
	fs := flag.NewFlagSet("workload "+args[0], flag.ContinueOnError)
	policyPath := fs.String("policy", "", "root-owned workload policy")
	source := fs.String("source-repository", "", "operator-approved GitHub repository")
	repoID := fs.String("repository-id", "", "immutable GitHub repository ID")
	version := fs.String("version", "", "release source revision")
	previous := fs.String("previous", "", "previous deployed revision")
	phase := fs.String("phase", "", "durable operation phase")
	store := fs.String("store", "/var/lib/komizo/releases", "root-owned release store")
	output := fs.String("output", "", "private result destination")
	releaseFile := fs.String("release", "", "root-accepted release document")
	configImage := fs.String("config-image", "", "configuration image reference")
	compose := fs.String("compose", "", "host-approved canonical Compose JSON")
	localOnly := fs.Bool("local-only", false, "bind an accepted current/previous release using exact local images without network")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *policyPath == "" {
		return errors.New("workload release command needs a policy")
	}
	if *localOnly && args[0] != "release-bind" {
		return errors.New("local-only applies only to release-bind")
	}
	p, err := readWorkloadPolicy(*policyPath)
	if err != nil {
		return err
	}
	if args[0] == "trust" {
		p.SourceRepository = *source
		p.RepositoryID = *repoID
		if err := p.Check(); err != nil {
			return err
		}
		if p.SourceRepository == "" {
			return errors.New("source identity is required")
		}
		return workload.WritePrivateJSON(*policyPath, p)
	}
	dir := filepath.Join(*store, p.App)
	if err := protectedReleaseDirectory(dir); err != nil {
		return err
	}
	switch args[0] {
	case "release-admit":
		return admitWorkloadRelease(p, *version, dir, *output)
	case "operation":
		return workload.RecordOperation(filepath.Join(dir, "operation.json"), p.App, *version, *previous, *phase, time.Now().UTC())
	case "ready":
		return readyWorkload(p, *version, *previous, dir, *compose)
	case "release-bootstrap":
		if *compose == "" || *configImage == "" {
			return errors.New("bootstrap needs local compose and configuration image")
		}
		body, err := os.ReadFile(*compose)
		if err != nil {
			return err
		}
		accepted, err := workload.BootstrapRelease(context.Background(), dockerReleaseRun, p, *version, *configImage, body, time.Now().UTC())
		if err != nil {
			return err
		}
		path := filepath.Join(dir, *version+".json")
		if _, err := os.Lstat(path); err == nil {
			return errors.New("existing accepted release cannot be replaced by bootstrap")
		} else if !os.IsNotExist(err) {
			return err
		}
		return workload.WritePrivateJSON(path, accepted)
	case "release-bind":
		if *output == "" || *compose == "" || *releaseFile == "" {
			return errors.New("release binding needs accepted release, compose and output")
		}
		var accepted workload.ReleaseAcceptance
		if err := readPrivateRelease(*releaseFile, &accepted); err != nil {
			return err
		}
		body, err := os.ReadFile(*compose)
		if err != nil {
			return err
		}
		bind := workload.BindRelease
		if *localOnly {
			if os.Geteuid() != 0 || !cachedRollbackAllowed(p, *version) {
				return errors.New("local binding requires the root operator's current/previous accepted revision")
			}
			bind = workload.BindLocalRelease
		}
		pinned, err := bind(context.Background(), dockerReleaseRun, p, accepted, *version, *configImage, body)
		if err != nil {
			return err
		}
		out, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, writeErr := out.Write(pinned)
		closeErr := out.Close()
		if writeErr != nil {
			return writeErr
		}
		return closeErr
	default:
		return errors.New("unknown workload release command")
	}
}

func protectedReleaseDirectory(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return errors.New("release store must be absolute and canonical")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 || !workloadRootOwner(info) {
		return errors.New("release store must be a protected root-owned directory")
	}
	return nil
}
func readPrivateRelease(path string, out any) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || !workloadRootOwner(info) {
		return errors.New("accepted release must be a protected root-owned regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, workload.ReleaseMaxBytes+1))
	if err != nil || len(body) > workload.ReleaseMaxBytes {
		return errors.New("accepted release is unreadable or oversized")
	}
	return json.Unmarshal(body, out)
}
func admitWorkloadRelease(p workload.Policy, version, dir, output string) error {
	return admitWorkloadReleaseFrom(p, version, dir, output, os.Stdin)
}
func admitWorkloadReleaseFrom(p workload.Policy, version, dir, output string, input io.Reader) error {
	if output == "" {
		return errors.New("release admission needs a private output")
	}
	if p.SourceRepository == "" {
		return workload.WritePrivateJSON(output, workload.ReleaseAcceptance{})
	}
	if len(version) != 40 || strings.ContainsAny(version, "/.") {
		return errors.New("authenticated releases require a full commit revision")
	}
	path := filepath.Join(dir, version+".json")
	var existing workload.ReleaseAcceptance
	have := false
	if _, err := os.Lstat(path); err == nil {
		if err := readPrivateRelease(path, &existing); err != nil {
			return err
		}
		if err := existing.Check(p, version); err != nil {
			return err
		}
		have = true
	} else if !os.IsNotExist(err) {
		return err
	}
	wire, err := io.ReadAll(io.LimitReader(input, 128<<10+1))
	if err != nil || len(wire) > 128<<10 {
		return errors.New("release proof exceeds wire limit")
	}
	if len(bytesTrim(wire)) == 0 {
		if !have || !cachedRollbackAllowed(p, version) {
			return errors.New("release requires authenticated Actions proof or the current/previous accepted revision")
		}
		return workload.WritePrivateJSON(output, existing)
	}
	const frame = "komizo-release/v1:"
	if !strings.HasPrefix(string(wire), frame) {
		return errors.New("invalid release proof frame")
	}
	body, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(string(wire), frame)))
	if err != nil {
		return errors.New("invalid release proof encoding")
	}
	accepted, err := workload.VerifyRelease(context.Background(), body, p, version, time.Now().UTC(), workload.GitHubReleaseKey)
	if err != nil {
		return err
	}
	if have && (!reflect.DeepEqual(existing.Manifest.Images, accepted.Manifest.Images) || !reflect.DeepEqual(existing.Manifest.StatefulContract, accepted.Manifest.StatefulContract)) {
		return errors.New("release revision was already accepted with different images or stateful contract")
	}
	if have {
		if err := statefulRetryAllowed(p, version, dir, existing); err != nil {
			return err
		}
	}
	if !have {
		if err := workload.WritePrivateJSON(path, accepted); err != nil {
			return err
		}
	} else {
		accepted = existing
	}
	return workload.WritePrivateJSON(output, accepted)
}
func bytesTrim(body []byte) []byte { return []byte(strings.TrimSpace(string(body))) }

func dockerReleaseRun(ctx context.Context, args ...string) (string, error) {
	if len(args) == 2 && args[0] == "config-digest" {
		ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "docker", "image", "save", args[1])
		cmd.Env = deploymentDockerEnv(ctx)
		cmd.WaitDelay = 2 * time.Second
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return "", err
		}
		if err := cmd.Start(); err != nil {
			return "", err
		}
		id, readErr := workload.DockerArchiveConfigDigest(stdout)
		if readErr != nil {
			cancel()
		}
		waitErr := cmd.Wait()
		if readErr != nil {
			return "", readErr
		}
		return id, waitErr
	}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Env = deploymentDockerEnv(ctx)
	cmd.WaitDelay = 2 * time.Second
	output := &boundedDockerOutput{limit: 2 << 20}
	cmd.Stdout = output
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return "", errors.New("bounded Docker operation failed or timed out")
	}
	return output.String(), nil
}

type boundedDockerOutput struct {
	buffer bytes.Buffer
	limit  int
}

func (b *boundedDockerOutput) String() string { return b.buffer.String() }

func (b *boundedDockerOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.buffer.Len() {
		return 0, errors.New("Docker output exceeded its bound")
	}
	return b.buffer.Write(p)
}
func retainedRevisions(p workload.Policy) (string, string, error) {
	var body []byte
	if err := readPrivateReleaseText(filepath.Join(p.AppDir, ".komizo-image-retention"), &body); err != nil {
		return "", "", err
	}
	values := map[string]string{}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || seen[key] {
			return "", "", errors.New("invalid retained revisions")
		}
		values[key] = value
		seen[key] = true
	}
	if values["CURRENT"] == "" {
		return "", "", errors.New("current revision unavailable")
	}
	return values["CURRENT"], values["PREVIOUS"], nil
}
func readPrivateReleaseText(path string, out *[]byte) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || !workloadRootOwner(info) || info.Size() > 4096 {
		return errors.New("retention requires a bounded protected root-owned regular file")
	}
	*out, err = os.ReadFile(path)
	return err
}
func cachedRollbackAllowed(p workload.Policy, version string) bool {
	current, previous, err := retainedRevisions(p)
	// Stateful rollback remains disabled: a compatibility declaration is not
	// an independently exercised post-write rollback proof.
	return err == nil && (version == current || !p.RequireStatefulContract && version == previous)
}
func statefulRetryAllowed(p workload.Policy, version, dir string, candidate workload.ReleaseAcceptance) error {
	if !p.RequireStatefulContract {
		return nil
	}
	current, _, err := retainedRevisions(p)
	if err != nil {
		return err
	}
	if current == version {
		return nil
	}
	var installed workload.ReleaseAcceptance
	if err := readPrivateRelease(filepath.Join(dir, current+".json"), &installed); err != nil {
		return err
	}
	if err := installed.Check(p, current); err != nil {
		return err
	}
	if candidate.VerifiedAt.IsZero() || installed.VerifiedAt.IsZero() || !candidate.VerifiedAt.After(installed.VerifiedAt) {
		return errors.New("historical stateful release requires explicit verified post-write recovery; use a forward fix")
	}
	return nil // Fresh proof may retry an admitted, newer failed candidate.
}
