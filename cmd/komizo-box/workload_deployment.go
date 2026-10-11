package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/internal/workload"
)

type deploymentCredentials struct {
	Registry string `json:"registry"`
	User     string `json:"user"`
	Password string `json:"password"`
}

var registryUser = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,256}$`)

func (c deploymentCredentials) check(p workload.Policy) error {
	if c.Registry == "" && c.User == "" && c.Password == "" {
		return nil
	}
	if c.Registry != "ghcr.io" || !strings.HasPrefix(p.ImagePrefix, "ghcr.io/") || (!registryUser.MatchString(c.User) && c.User != "github-actions[bot]") || len(c.Password) == 0 || len(c.Password) > 16384 || strings.ContainsAny(c.Password, "\x00\r\n") {
		return errors.New("invalid operation-private registry credential")
	}
	return nil
}

func deploymentCredentialPath(dir, id string) string {
	return filepath.Join(dir, "credentials-"+id, "input.json")
}
func deploymentHash(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }

func runWorkloadDeployment(args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("typed deployment requires the local root operator")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	policyPath := fs.String("policy", "", "installed root policy")
	version := fs.String("version", "", "candidate revision")
	registry := fs.String("registry", "", "registry")
	user := fs.String("registry-user", "", "registry username")
	generation := fs.String("generation", "", "scoped generation")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("deployment accepts no positional arguments")
	}
	p, err := readWorkloadPolicy(*policyPath)
	if err != nil {
		return err
	}
	if *policyPath != filepath.Join(workloadPolicyDirectory, p.App+".json") || p.Deployment == nil {
		return errors.New("typed deployment is not enabled in the installed root policy")
	}
	if args[0] == "deployment-enabled" {
		return nil
	}
	if args[0] != "deployment-submit" || len(*version) != 40 || strings.Trim(*version, "0123456789abcdef") != "" {
		return errors.New("deployment needs an exact source revision")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	unlock, err := box.LockDeployment(ctx, "", p.App)
	if err != nil {
		return err
	}
	defer unlock()
	if err := activationIdle(activationDirectory); err != nil {
		return err
	}
	if err := protectedReleaseDirectory(activationDirectory); err != nil {
		return err
	}
	reader := bufio.NewReaderSize(io.LimitReader(os.Stdin, 160<<10+1), 16386)
	credentials := deploymentCredentials{Registry: *registry, User: *user}
	if *registry != "" {
		line, e := reader.ReadSlice('\n')
		if e != nil || len(line) > 16385 {
			return errors.New("registry token is missing or exceeds its bound")
		}
		credentials.Password = strings.TrimSuffix(string(line), "\n")
	}
	if err := credentials.check(p); err != nil {
		return err
	}
	proof, err := io.ReadAll(io.LimitReader(reader, 128<<10+1))
	if err != nil || len(proof) > 128<<10 {
		return errors.New("release proof exceeds its bound")
	}
	env, err := protectedActivationBytes(filepath.Join(p.AppDir, ".env"))
	if err != nil {
		return err
	}
	previous, err := deploymentVersion(env)
	if err != nil {
		return err
	}
	// Verify the release before registry login, config extraction or file swaps.
	dir := filepath.Join(releaseDirectory, p.App)
	if err := protectedReleaseDirectory(dir); err != nil {
		return err
	}
	output, err := os.CreateTemp(dir, ".admitted-")
	if err != nil {
		return err
	}
	outPath := output.Name()
	output.Close()
	os.Remove(outPath)
	defer os.Remove(outPath)
	if err := admitWorkloadReleaseFrom(p, *version, dir, outPath, bytes.NewReader(proof)); err != nil {
		return err
	}
	if err := workload.RecordOperation(filepath.Join(dir, "operation.json"), p.App, *version, previous, "admitted", time.Now().UTC()); err != nil {
		return err
	}
	var op workload.Operation
	if err := protectedActivationJSON(filepath.Join(dir, "operation.json"), &op); err != nil {
		return err
	}
	policyBytes, err := protectedActivationBytes(*policyPath)
	if err != nil {
		return err
	}
	slot := deploymentCredentialPath(activationDirectory, op.ID)
	if err := protectedReleaseDirectory(filepath.Dir(slot)); err != nil {
		return err
	}
	if err := workload.WritePrivateJSON(slot, credentials); err != nil {
		return err
	}
	// WritePrivateJSON emits an indented document. Bind the stored bytes.
	body, err := protectedActivationBytes(slot)
	if err != nil {
		return err
	}
	r := workload.ActivationRequest{Version: 2, ID: op.ID, App: p.App, Candidate: *version, Previous: previous, PolicySHA256: deploymentHash(policyBytes), RoutePath: p.Deployment.RoutePath, Proxy: p.Deployment.Proxy, Deadline: op.Deadline, Stage: &workload.DeploymentStage{CredentialSHA256: deploymentHash(body), Generation: *generation}}
	if err := r.Check(time.Now()); err != nil {
		os.RemoveAll(filepath.Dir(slot))
		return err
	}
	if err := workload.WritePrivateJSON(filepath.Join(activationDirectory, "pending.json"), r); err != nil {
		os.RemoveAll(filepath.Dir(slot))
		return err
	}
	// No registry credential, token, proof or environment is returned.
	fmt.Printf("deploy: previous-version=%s\ndeploy: submitted=%s\n", previous, op.ID)
	fmt.Println(op.ID)
	return nil
}

func deploymentVersion(env []byte) (string, error) {
	var version string
	seen := false
	for _, line := range strings.Split(string(env), "\n") {
		if strings.HasPrefix(line, "APP_VERSION=") {
			if seen {
				return "", errors.New("duplicate installed revision")
			}
			seen = true
			version = strings.TrimPrefix(line, "APP_VERSION=")
		}
	}
	if version != "" && (len(version) != 40 || strings.Trim(version, "0123456789abcdef") != "") {
		return "", errors.New("installed revision is not a source identity")
	}
	return version, nil
}

type deploymentDockerConfigKey struct{}

func deploymentDockerEnv(ctx context.Context) []string {
	var env []string
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "DOCKER_CONFIG=") {
			env = append(env, v)
		}
	}
	if dir, ok := ctx.Value(deploymentDockerConfigKey{}).(string); ok {
		env = append(env, "DOCKER_CONFIG="+dir)
	}
	return env
}
func loginDeployment(ctx context.Context, c deploymentCredentials, dir string) error {
	if c.Registry == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "login", c.Registry, "--username", c.User, "--password-stdin")
	cmd.Env = deploymentDockerEnv(context.WithValue(ctx, deploymentDockerConfigKey{}, dir))
	cmd.Stdin = strings.NewReader(c.Password)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Run(); err != nil {
		return errors.New("operation-private registry login failed")
	}
	return nil
}

type stagedFile struct {
	Path   string `json:"path"`
	Body   []byte `json:"body,omitempty"`
	Exists bool   `json:"exists"`
	Mode   uint32 `json:"mode"`
}
type deploymentSnapshot struct {
	Version int          `json:"version"`
	ID      string       `json:"operation_id"`
	Files   []stagedFile `json:"files"`
}

func (h *hostActivation) stageDeployment(parent context.Context, r workload.ActivationRequest, queue string) (configured workload.ActivationRequest, err error) {
	configured = r
	if err := r.Check(time.Now()); err != nil {
		return configured, err
	}
	op, err := h.operation(r)
	if err != nil {
		return configured, err
	}
	if op.Phase != "admitted" {
		return configured, workload.ErrActivationReconciliation
	}
	ctx, cancel := context.WithDeadline(parent, r.Deadline)
	defer cancel()
	policyBytes, err := h.readBytes(filepath.Join(h.policies, r.App+".json"))
	if err != nil || deploymentHash(policyBytes) != r.PolicySHA256 {
		return configured, errors.New("staging policy changed")
	}
	p, err := workload.ReadPolicy(bytes.NewReader(policyBytes))
	if err != nil {
		return configured, err
	}
	if p.App != r.App || p.Deployment == nil || p.Deployment.RoutePath != r.RoutePath || p.Deployment.Proxy != r.Proxy {
		return configured, errors.New("staging authority changed")
	}
	h.policy = p
	env, err := h.readBytes(filepath.Join(p.AppDir, ".env"))
	if err != nil {
		return configured, err
	}
	previous, err := deploymentVersion(env)
	if err != nil || previous != r.Previous {
		return configured, errors.New("installed revision changed before staging")
	}
	if err := h.deploymentCapacity(); err != nil {
		return configured, err
	}
	var accepted workload.ReleaseAcceptance
	if err := h.readJSON(filepath.Join(h.releases, r.App, r.Candidate+".json"), &accepted); err != nil {
		return configured, err
	}
	if err := accepted.Check(p, r.Candidate); err != nil {
		return configured, err
	}
	slot := deploymentCredentialPath(queue, r.ID)
	credentialsBody, err := h.readBytes(slot)
	if err != nil || deploymentHash(credentialsBody) != r.Stage.CredentialSHA256 {
		return configured, errors.New("staging credential slot changed")
	}
	var credentials deploymentCredentials
	if err := h.readJSON(slot, &credentials); err != nil {
		return configured, err
	}
	if err := credentials.check(p); err != nil {
		return configured, err
	}
	defer os.RemoveAll(filepath.Dir(slot))
	if err := h.Phase(r, "staging"); err != nil {
		return configured, err
	}
	h.deploymentCheckpoint("journal-staging")
	mutated := false
	var snapshot deploymentSnapshot
	defer func() {
		if err != nil {
			if mutated {
				if restoreErr := restoreDeploymentSnapshot(snapshot, h.writeDeployment); restoreErr != nil {
					err = errors.Join(err, restoreErr)
				}
			}
			if phaseErr := h.Phase(r, "staging_failed"); phaseErr != nil {
				err = errors.Join(err, phaseErr)
			}
		}
	}()
	dockerDir := filepath.Join(filepath.Dir(slot), "docker")
	if err := os.Mkdir(dockerDir, 0700); err != nil {
		return configured, err
	}
	ctx = context.WithValue(ctx, deploymentDockerConfigKey{}, dockerDir)
	login := h.deploymentLogin
	if login == nil {
		login = loginDeployment
	}
	if err := login(ctx, credentials, dockerDir); err != nil {
		return configured, err
	}
	credentials.Password = ""
	credentialsBody = nil
	if err := os.Remove(slot); err != nil {
		return configured, err
	}
	h.deploymentCheckpoint("registry-login")
	configRef := p.ImagePrefix + "config:" + r.Candidate
	if _, err := h.run(ctx, "pull", "-q", configRef); err != nil {
		return configured, errors.New("configuration image pull failed")
	}
	// Validate its configuration identity before allowing even a stopped copy.
	if _, err := workload.BindLocalRelease(ctx, h.run, p, accepted, r.Candidate, configRef, []byte(`{"services":{}}`)); err != nil {
		return configured, err
	}
	volumes, err := h.run(ctx, "image", "inspect", "--format", "{{json .Config.Volumes}}", configRef)
	if err != nil || (strings.TrimSpace(volumes) != "null" && strings.TrimSpace(volumes) != "{}") {
		return configured, errors.New("configuration image may not allocate declared volumes")
	}
	immutable, err := h.run(ctx, "image", "inspect", "--format", "{{.Id}}", configRef)
	immutable = strings.TrimSpace(immutable)
	if err != nil || len(immutable) != 71 || !strings.HasPrefix(immutable, "sha256:") || strings.Trim(strings.TrimPrefix(immutable, "sha256:"), "0123456789abcdef") != "" {
		return configured, errors.New("configuration image has no immutable local identity")
	}
	id, err := h.run(ctx, "create", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--entrypoint", "/komizo-copy-never-run", immutable)
	if err != nil {
		return configured, err
	}
	id = strings.TrimSpace(id)
	if len(id) != 64 || strings.Trim(id, "0123456789abcdef") != "" {
		return configured, errors.New("invalid owned configuration container identity")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		h.run(cleanup, "rm", "--force", "--volumes", id)
	}()
	copyConfig := h.deploymentCopy
	if copyConfig == nil {
		copyConfig = copyDeploymentConfiguration
	}
	compose, hostnames, err := copyConfig(ctx, id)
	if err != nil {
		return configured, err
	}
	h.deploymentCheckpoint("configuration-copy")
	canonical, err := workload.Validate(bytes.NewReader(compose), p, r.Candidate)
	if err != nil {
		return configured, err
	}
	canonical, err = workload.BindRelease(ctx, h.run, p, accepted, r.Candidate, configRef, canonical)
	if err != nil {
		return configured, err
	}
	// Pull pinned upstream/profile images before any installed configuration changes.
	work, err := os.MkdirTemp(filepath.Dir(slot), "validated-")
	if err != nil {
		return configured, err
	}
	defer os.RemoveAll(work)
	validated := filepath.Join(work, "compose.json")
	if err := writePrivateText(validated, canonical); err != nil {
		return configured, err
	}
	if err := h.verifyDeploymentSecrets(ctx, p, r.Stage.Generation, validated); err != nil {
		return configured, err
	}
	if _, err := h.run(ctx, "compose", "--project-name", p.App, "--project-directory", p.AppDir, "-f", validated, "--profile", "*", "pull"); err != nil {
		return configured, errors.New("complete approved image pull failed")
	}
	proxyConfig, err := h.readBytes(filepath.Join(p.Deployment.ProxyDir, "Caddyfile"))
	if err != nil && len(bytes.TrimSpace(hostnames)) > 0 {
		return configured, errors.New("route requires the installed proxy configuration")
	}
	route, recorded, names, err := workload.DeploymentRoute(p.App, r.Candidate, hostnames, bytes.Contains(proxyConfig, []byte("ask ")))
	if err != nil {
		return configured, err
	}
	if err := h.deploymentHostnames(p, names); err != nil {
		return configured, err
	}
	if err := h.deploymentIngress(ctx, p, r.Proxy); err != nil {
		return configured, err
	}
	files := []string{filepath.Join(p.AppDir, "compose.yml"), r.RoutePath, filepath.Join(p.AppDir, "hostnames"), filepath.Join(p.AppDir, ".env")}
	snapshot = deploymentSnapshot{Version: 1, ID: r.ID}
	for _, path := range files {
		file := stagedFile{Path: path}
		info, e := os.Lstat(path)
		if e == nil {
			file.Body, e = h.readBytes(path)
			if e != nil {
				return configured, e
			}
			file.Exists = true
			file.Mode = uint32(info.Mode().Perm())
		} else if !os.IsNotExist(e) {
			return configured, e
		}
		snapshot.Files = append(snapshot.Files, file)
	}
	if err := workload.WritePrivateJSON(filepath.Join(h.releases, p.App, "staging-"+r.ID+".json"), snapshot); err != nil {
		return configured, err
	}
	h.deploymentCheckpoint("snapshot")
	mutated = true
	// Retain the same bounded rollback files the activation adapter owns.
	for _, file := range snapshot.Files[:3] {
		if file.Exists {
			if err := h.writeDeployment(file.Path+".prev", file.Body, os.FileMode(file.Mode)); err != nil {
				return configured, err
			}
		} else {
			if err := os.Remove(file.Path + ".prev"); err != nil && !os.IsNotExist(err) {
				return configured, err
			}
		}
	}
	if err := h.writeDeployment(files[0], canonical, 0600); err != nil {
		return configured, err
	}
	h.deploymentCheckpoint("compose-swap")
	// An empty root-generated route is a valid no-hostname configuration.
	if err := h.writeDeployment(r.RoutePath, route, 0644); err != nil {
		return configured, err
	}
	h.deploymentCheckpoint("route-swap")
	if err := h.writeDeployment(files[2], recorded, 0644); err != nil {
		return configured, err
	}
	h.deploymentCheckpoint("hostname-swap")
	if _, err := h.run(ctx, "exec", r.Proxy, "caddy", "validate", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"); err != nil {
		return configured, errors.New("complete candidate proxy configuration is invalid")
	}
	newEnv, err := deploymentEnv(env, r.Candidate)
	if err != nil {
		return configured, err
	}
	if err := h.writeDeployment(files[3], newEnv, 0600); err != nil {
		return configured, err
	}
	h.deploymentCheckpoint("revision-swap")
	if err := h.Phase(r, "configured"); err != nil {
		return configured, err
	}
	configured.Version = 1
	configured.Stage = nil
	configured.ComposeSHA256 = deploymentHash(canonical)
	configured.RouteSHA256 = deploymentHash(route)
	if err := configured.Check(time.Now()); err != nil {
		return configured, err
	}
	if err := workload.WritePrivateJSON(filepath.Join(queue, "pending.json"), configured); err != nil {
		return configured, err
	}
	h.deploymentCheckpoint("configured-submission")
	return configured, nil
}

func deploymentEnv(env []byte, version string) ([]byte, error) {
	if _, err := deploymentVersion(env); err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSuffix(string(env), "\n"), "\n")
	found := false
	for i, line := range lines {
		if strings.HasPrefix(line, "APP_VERSION=") {
			lines[i] = "APP_VERSION=" + version
			found = true
		}
	}
	if !found {
		lines = append(lines, "APP_VERSION="+version)
	}
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}
func writeDeploymentFile(path string, body []byte, mode os.FileMode) error {
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || !workloadRootOwner(info)) {
		return errors.New("unsafe deployment destination")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := writePrivateText(path, body); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
func (h *hostActivation) writeDeployment(path string, body []byte, mode os.FileMode) error {
	if h.deploymentWrite != nil {
		return h.deploymentWrite(path, body, mode)
	}
	return writeDeploymentFile(path, body, mode)
}
func restoreDeploymentSnapshot(snapshot deploymentSnapshot, write func(string, []byte, os.FileMode) error) error {
	for _, f := range snapshot.Files {
		if f.Exists {
			if err := write(f.Path, f.Body, os.FileMode(f.Mode)); err != nil {
				return err
			}
		} else {
			if err := os.Remove(f.Path); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}
func copyDeploymentConfiguration(ctx context.Context, id string) (compose, hostnames []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "cp", id+":/config/.", "-")
	cmd.Env = deploymentDockerEnv(ctx)
	cmd.Stderr = io.Discard
	cmd.WaitDelay = 2 * time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	compose, hostnames, err = workload.ReadConfiguration(stdout)
	if err == nil {
		tail, e := io.ReadAll(io.LimitReader(stdout, 1<<20+1))
		if e != nil || len(tail) > 1<<20 || len(bytes.Trim(tail, "\x00")) > 0 {
			err = errors.New("configuration archive has an oversized or nonzero tail")
		}
	}
	if err != nil {
		cancel()
	}
	waitErr := cmd.Wait()
	if err != nil {
		return nil, nil, err
	}
	return compose, hostnames, waitErr
}

func (h *hostActivation) deploymentCheckpoint(boundary string) {
	if h.deploymentBoundary != nil {
		h.deploymentBoundary(boundary)
	}
}
func (h *hostActivation) deploymentCapacity() error {
	path := filepath.Join(h.root, box.DeployFloorsPath)
	body, err := h.readBytes(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.New("operator deployment floors are not readable")
	}
	floors, present, err := box.ParsePreviewFloors(string(body))
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	reportPath := filepath.Join(h.root, box.ReportPath)
	if err := workloadReportFresh(reportPath, time.Now()); err != nil {
		return err
	}
	report, err := h.readBytes(reportPath)
	if err != nil {
		return err
	}
	refuse, _, err := box.PreviewCheckFloors(floors, present, report)
	if err != nil {
		return err
	}
	if refuse != "" {
		return errors.New("operator capacity floor is not met")
	}
	return nil
}
func (h *hostActivation) deploymentHostnames(p workload.Policy, names []string) error {
	entries, err := os.ReadDir(filepath.Join(h.root, box.AppsDir))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		other := strings.TrimSuffix(entry.Name(), ".env")
		if other == entry.Name() || other == p.App {
			continue
		}
		state, err := h.readBytes(filepath.Join(h.root, box.AppsDir, entry.Name()))
		if err != nil {
			return err
		}
		dir := deploymentStateValue(state, "APP_DIR")
		if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || dir == "/" {
			return errors.New("invalid neighboring app record")
		}
		metadata, err := h.readBytes(filepath.Join(dir, "hostnames"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(metadata), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			for _, name := range names {
				if strings.EqualFold(name, fields[0]) {
					return errors.New("hostname is already claimed by another app")
				}
			}
		}
	}
	return nil
}
func deploymentStateValue(body []byte, key string) string {
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, key+"=") {
			return strings.TrimPrefix(line, key+"=")
		}
	}
	return ""
}
func (h *hostActivation) verifyDeploymentSecrets(ctx context.Context, p workload.Policy, generation, compose string) error {
	state, err := h.readBytes(filepath.Join(h.root, box.AppsDir, p.App+".env"))
	if err != nil {
		return err
	}
	if deploymentStateValue(state, "APP_DIR") != p.AppDir {
		return errors.New("app state differs from protected policy")
	}
	profile := deploymentStateValue(state, "SCOPED_ENV")
	if profile != "fields-postgres-v2" {
		if generation != "" {
			return errors.New("generation is not applicable to this app")
		}
		return nil
	}
	if len(generation) != 32 || strings.Trim(generation, "0123456789abcdef") != "" || deploymentStateValue(state, "SCOPED_GENERATION") != generation {
		return errors.New("scoped generation differs from root app state")
	}
	secrets := filepath.Join(p.AppDir, "secrets")
	info, err := os.Lstat(secrets)
	owner := h.deploymentOwner
	if owner == nil {
		owner = workloadRootOwner
	}
	if err != nil || !info.IsDir() || !owner(info) || info.Mode().Perm()&0022 != 0 {
		return errors.New("unsafe scoped secret directory")
	}
	current := filepath.Join(secrets, "current")
	target, err := os.Readlink(current)
	if err != nil || target != "generations/"+generation {
		return errors.New("scoped generation link differs")
	}
	dir := filepath.Join(secrets, "generations", generation)
	parent, parentErr := os.Lstat(filepath.Dir(dir))
	if parentErr != nil || !parent.IsDir() || !owner(parent) || parent.Mode().Perm()&0022 != 0 {
		return errors.New("unsafe scoped generations directory")
	}
	info, err = os.Lstat(dir)
	if err != nil || !info.IsDir() || !owner(info) || info.Mode().Perm()&0022 != 0 {
		return errors.New("unsafe scoped generation")
	}
	for _, name := range []string{"postgres.env", "migrate.env", "api.env", "godot-api.env", "provenance"} {
		info, err := os.Lstat(filepath.Join(dir, name))
		mode := os.FileMode(0600)
		if name == "provenance" {
			mode = 0400
		}
		if err != nil || !info.Mode().IsRegular() || !owner(info) || info.Mode().Perm() != mode {
			return errors.New("scoped secret metadata is not protected")
		}
	}
	marker, err := h.readBytes(filepath.Join(dir, "provenance"))
	if err != nil || string(marker) != "profile=fields-postgres-v2\nschema=11\ngeneration="+generation+"\n" {
		return errors.New("scoped provenance differs")
	}
	// This existing root-owned primitive only checks secret mounts; it does not
	// mint credentials or decide the deployment transaction.
	check := h.deploymentSecretCheck
	if check == nil {
		check = func(ctx context.Context, path, compose string) error {
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || !workloadRootOwner(info) || info.Mode().Perm()&0022 != 0 {
				return errors.New("unsafe scoped checker")
			}
			cmd := exec.CommandContext(ctx, path, "--check-compose", compose)
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
			cmd.WaitDelay = 2 * time.Second
			return cmd.Run()
		}
	}
	return check(ctx, filepath.Join(h.root, "/usr/local/bin/provision-scoped-env-"+p.App), compose)
}
func (h *hostActivation) deploymentIngress(ctx context.Context, p workload.Policy, proxy string) error {
	if p.IngressNetwork == "" || p.IngressNetwork == p.SharedNetwork {
		return nil
	}
	label, err := h.run(ctx, "network", "inspect", p.IngressNetwork, "--format", `{{index .Labels "io.komizo.app"}}`)
	if err != nil {
		if _, err := h.run(ctx, "network", "create", "--internal", "--label", "io.komizo.app="+p.App, p.IngressNetwork); err != nil {
			return errors.New("app ingress creation failed")
		}
	} else if strings.TrimSpace(label) != p.App {
		return errors.New("app ingress lacks the approved ownership label")
	}
	networks, err := h.run(ctx, "inspect", "--format", `{{range $name, $cfg := .NetworkSettings.Networks}}{{$name}}{{println}}{{end}}`, proxy)
	if err != nil {
		return err
	}
	for _, name := range strings.Fields(networks) {
		if name == p.IngressNetwork {
			return nil
		}
	}
	_, err = h.run(ctx, "network", "connect", p.IngressNetwork, proxy)
	return err
}
