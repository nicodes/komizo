package rollout

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Docker is a local-only executor. It never inherits DOCKER_HOST/CONTEXT, grants
// new doas rights, mounts the Docker socket into application candidates, or
// invokes arbitrary shell hooks. Compose must be an explicit versioned binary.
type Docker struct {
	App, Network                  string
	ComposeBinary, ComposeVersion string
	EnvFile                       string
	DockerConfig                  string
	Store                         *Store
	MinFreeMemory, MinFreeDisk    uint64
}

type container struct {
	HostConfig   struct{ RestartPolicy struct{ Name string } }
	ID           string
	Name         string
	Created      string
	RestartCount int
	Config       struct {
		Labels map[string]string
		Env    []string
	}
	State struct {
		StartedAt  string
		FinishedAt string
		Running    bool
		Status     string
		ExitCode   int
		OOMKilled  bool
		Dead       bool
		Restarting bool
	}
	NetworkSettings struct {
		Networks map[string]struct{ IPAddress string }
	}
}

func (d *Docker) InspectRecovery(ctx context.Context, old, candidate Instance) (RecoverySnapshot, error) {
	failed, err := d.inspect(ctx, old)
	if err != nil || failed == nil {
		return RecoverySnapshot{}, errors.New("failed recovery incarnation is absent or unconfirmed")
	}
	standby, err := d.inspect(ctx, candidate)
	if err != nil || standby == nil {
		return RecoverySnapshot{}, errors.New("standby recovery incarnation is absent or unconfirmed")
	}
	if failed.HostConfig.RestartPolicy.Name != "no" || failed.RestartCount != 0 || failed.State.Running || failed.State.Status != "exited" || failed.State.ExitCode == 0 ||
		failed.State.Restarting || failed.State.Dead || failed.State.OOMKilled || failed.State.FinishedAt == "" {
		return RecoverySnapshot{}, errors.New("failed recovery incarnation has ambiguous exit or restart state")
	}
	created, createdErr := time.Parse(time.RFC3339Nano, failed.Created)
	started, startedErr := time.Parse(time.RFC3339Nano, failed.State.StartedAt)
	finished, finishedErr := time.Parse(time.RFC3339Nano, failed.State.FinishedAt)
	if createdErr != nil || startedErr != nil || finishedErr != nil || started.Before(created) || !finished.After(started) {
		return RecoverySnapshot{}, errors.New("failed recovery incarnation chronology is invalid")
	}
	if standby.HostConfig.RestartPolicy.Name != "no" || standby.RestartCount != 0 || !standby.State.Running || standby.State.Status != "running" ||
		standby.State.Restarting || standby.State.Dead || standby.State.OOMKilled || !exactEnvironment(standby.Config.Env, "KOMIZO_CANDIDATE", "standby") {
		return RecoverySnapshot{}, errors.New("recovery candidate is not the healthy declared standby incarnation")
	}
	candidateCreated, candidateCreatedErr := time.Parse(time.RFC3339Nano, standby.Created)
	candidateStarted, candidateStartedErr := time.Parse(time.RFC3339Nano, standby.State.StartedAt)
	if candidateCreatedErr != nil || candidateStartedErr != nil || candidateStarted.Before(candidateCreated) {
		return RecoverySnapshot{}, errors.New("recovery candidate chronology is invalid")
	}
	return RecoverySnapshot{
		Old:       RecoveryIncarnation{ID: failed.ID, StartedAt: failed.State.StartedAt, FinishedAt: failed.State.FinishedAt, ExitCode: failed.State.ExitCode},
		Candidate: RecoveryIncarnation{ID: standby.ID, StartedAt: standby.State.StartedAt, Running: true},
	}, nil
}

func exactEnvironment(environment []string, name, value string) bool {
	want, found := name+"="+value, 0
	for _, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		if key == name {
			found++
			if entry != want {
				return false
			}
		}
	}
	return found == 1
}

func (d *Docker) RemoveRecovered(ctx context.Context, old, candidate Instance, proof VerifiedRecovery) error {
	if proof.ProvedAt.IsZero() || proof.ActivatedAt.IsZero() || proof.ReleasedAt.IsZero() || proof.Old.ID == "" || proof.Old.StartedAt == "" || proof.Old.FinishedAt == "" || proof.Old.ExitCode == 0 {
		return errors.New("distinct verified recovery proof is incomplete")
	}
	standby, err := d.inspect(ctx, candidate)
	if err != nil || standby == nil || standby.ID != proof.Candidate.ID || standby.State.StartedAt != proof.Candidate.StartedAt || standby.RestartCount != 0 || standby.HostConfig.RestartPolicy.Name != "no" || !standby.State.Running || standby.State.Status != "running" || standby.State.Restarting || standby.State.Dead || standby.State.OOMKilled {
		return errors.New("activated recovery candidate identity or health changed")
	}
	failed, err := d.inspect(ctx, old)
	if err != nil {
		return err
	}
	if failed != nil {
		if failed.ID != proof.Old.ID || failed.State.StartedAt != proof.Old.StartedAt || failed.State.FinishedAt != proof.Old.FinishedAt || failed.State.ExitCode != proof.Old.ExitCode ||
			failed.RestartCount != 0 || failed.HostConfig.RestartPolicy.Name != "no" || failed.State.Running || failed.State.Status != "exited" || failed.State.Restarting || failed.State.Dead || failed.State.OOMKilled {
			return errors.New("failed incarnation changed before non-forced recovery cleanup")
		}
		if _, err := d.docker(ctx, "rm", "--volumes", proof.Old.ID); err != nil {
			return err
		}
	}
	return d.removeArtifact(old)
}

func command(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd, err := executorCommand(ctx, name, args...)
	if err != nil {
		return nil, err
	}
	var output cappedBuffer
	cmd.Stdout, cmd.Stderr = &output, io.Discard
	if err := cmd.Run(); err != nil {
		return nil, errors.New("local executor command failed")
	}
	return output.Bytes(), nil
}

func executorCommand(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, errors.New("executor operation requires a deadline")
	}
	cmd := exec.CommandContext(ctx, name, args...)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		switch key {
		case "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION":
			continue
		}
		cmd.Env = append(cmd.Env, entry)
	}
	return cmd, nil
}

type cappedBuffer struct{ bytes.Buffer }

func (b *cappedBuffer) Write(data []byte) (int, error) {
	if b.Len()+len(data) > 16<<20 {
		return 0, errors.New("executor output limit")
	}
	return b.Buffer.Write(data)
}

// diagnosticBuffer retains only enough private daemon output to select a fixed
// safe category. Its bytes are never returned or persisted.
type diagnosticBuffer struct{ bytes.Buffer }

func (b *diagnosticBuffer) Write(data []byte) (int, error) {
	written := len(data)
	if remaining := (64 << 10) - b.Len(); remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		_, _ = b.Buffer.Write(data)
	}
	return written, nil
}

var (
	errImagePullDeadline        = errors.New("candidate image pull exceeded the configured operation deadline")
	errImageRegistryAccess      = errors.New("candidate image registry authentication or access was refused")
	errImageRegistryNetwork     = errors.New("candidate image registry network request failed")
	errImageDigestUnavailable   = errors.New("candidate image digest or platform is unavailable")
	errImagePullUnknown         = errors.New("candidate image pull failed without a recognized safe diagnostic")
	errCandidateStartDeadline   = errors.New("candidate start exceeded the configured operation deadline")
	errCandidateStartDaemon     = errors.New("candidate start could not reach the local container runtime")
	errCandidateStartImage      = errors.New("candidate start could not use the staged image")
	errCandidateStartDefinition = errors.New("candidate start definition was refused")
	errCandidateStartResource   = errors.New("candidate start was refused by local resource or network allocation")
	errCandidateStartProcess    = errors.New("candidate process exited during startup")
	errCandidateStartUnknown    = errors.New("candidate start failed without a recognized safe diagnostic")
)

func (d *Docker) pullImage(ctx context.Context, image string) error {
	cmd, err := executorCommand(ctx, "docker", "--host", "unix:///var/run/docker.sock", "pull", "--quiet", image)
	if err != nil {
		return errImagePullUnknown
	}
	overrideCommandEnv(cmd, "DOCKER_CONFIG", d.DockerConfig)
	var diagnostic diagnosticBuffer
	cmd.Stdout, cmd.Stderr = io.Discard, &diagnostic
	if err := cmd.Run(); err == nil {
		return nil
	}
	return classifyImagePullFailure(ctx, diagnostic.Bytes())
}

func overrideCommandEnv(cmd *exec.Cmd, key, value string) {
	if value == "" {
		return
	}
	environment := cmd.Env[:0]
	for _, entry := range cmd.Env {
		name, _, _ := strings.Cut(entry, "=")
		if name != key {
			environment = append(environment, entry)
		}
	}
	cmd.Env = append(environment, key+"="+value)
}

func (d *Docker) authenticate(ctx context.Context, registry, username string, token []byte) error {
	if d.DockerConfig == "" || !registryHost(registry) || !registryUsername(username) || len(token) == 0 || len(token) > 16<<10 || bytes.ContainsAny(token, "\x00\r\n") {
		return errors.New("invalid bounded registry authentication input")
	}
	cmd, err := executorCommand(ctx, "docker", "--host", "unix:///var/run/docker.sock", "login", registry, "--username", username, "--password-stdin")
	if err != nil {
		return errImagePullUnknown
	}
	overrideCommandEnv(cmd, "DOCKER_CONFIG", d.DockerConfig)
	password := make([]byte, len(token)+1)
	copy(password, token)
	password[len(token)] = '\n'
	defer clear(password)
	cmd.Stdin = bytes.NewReader(password)
	var diagnostic diagnosticBuffer
	cmd.Stdout, cmd.Stderr = io.Discard, &diagnostic
	if err := cmd.Run(); err == nil {
		return nil
	}
	return classifyImagePullFailure(ctx, diagnostic.Bytes())
}

func registryHost(value string) bool {
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "\x00\r\n/@") {
		return false
	}
	for _, c := range value {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == ':' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func registryUsername(value string) bool {
	if value == "" || len(value) > 255 {
		return false
	}
	for _, c := range value {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '@' || c == '-') {
			return false
		}
	}
	return true
}

// classifyImagePullFailure deliberately returns only fixed strings. Docker's
// raw response can contain a private registry path or credential-bearing URL.
func classifyImagePullFailure(ctx context.Context, diagnostic []byte) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errImagePullDeadline
	}
	message := strings.ToLower(string(diagnostic))
	for _, marker := range []string{"unauthorized", "authentication required", "no basic auth credentials", "failed to authorize", "access denied", "pull access denied", "requested access", "forbidden", "insufficient_scope", "denied: denied", "status code: 401", "status code: 403"} {
		if strings.Contains(message, marker) {
			return errImageRegistryAccess
		}
	}
	for _, marker := range []string{"manifest unknown", "manifest invalid", "unknown blob", "digest invalid", "no matching manifest", "not found"} {
		if strings.Contains(message, marker) {
			return errImageDigestUnavailable
		}
	}
	for _, marker := range []string{"dial tcp", "i/o timeout", "tls handshake timeout", "connection reset", "connection refused", "temporary failure in name resolution", "no such host", "network is unreachable", "context deadline exceeded", "failed to do request", "unexpected eof"} {
		if strings.Contains(message, marker) {
			return errImageRegistryNetwork
		}
	}
	return errImagePullUnknown
}

// candidateStartCommand retains a bounded diagnostic only long enough to pick
// a fixed category. Raw Compose or daemon output can contain private paths,
// image identities, container names, environment values, or credential-bearing
// URLs, so it is never returned or persisted.
func candidateStartCommand(ctx context.Context, name string, args ...string) error {
	cmd, err := executorCommand(ctx, name, args...)
	if err != nil {
		return errCandidateStartUnknown
	}
	var diagnostic diagnosticBuffer
	cmd.Stdout, cmd.Stderr = &diagnostic, &diagnostic
	if err := cmd.Run(); err == nil {
		return nil
	}
	return classifyCandidateStartFailure(ctx, diagnostic.Bytes())
}

func classifyCandidateStartFailure(ctx context.Context, diagnostic []byte) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errCandidateStartDeadline
	}
	message := strings.ToLower(string(diagnostic))
	for _, marker := range []string{"cannot connect to the docker daemon", "error during connect", "is the docker daemon running", "permission denied while trying to connect", "connection refused"} {
		if strings.Contains(message, marker) {
			return errCandidateStartDaemon
		}
	}
	for _, marker := range []string{"no such image", "image is missing", "unable to find image", "image not known"} {
		if strings.Contains(message, marker) {
			return errCandidateStartImage
		}
	}
	for _, marker := range []string{"validating ", "invalid compose project", "invalid project", "no such service", "additional properties are not allowed", "service must be a mapping"} {
		if strings.Contains(message, marker) {
			return errCandidateStartDefinition
		}
	}
	for _, marker := range []string{"no space left on device", "cannot allocate memory", "resource temporarily unavailable", "failed to create endpoint", "failed to set up container networking", "address already in use", "network ", "is already in use by container"} {
		if strings.Contains(message, marker) {
			return errCandidateStartResource
		}
	}
	for _, marker := range []string{"dependency failed to start", "exited (", "failed to start: container", "did not complete successfully"} {
		if strings.Contains(message, marker) {
			return errCandidateStartProcess
		}
	}
	return errCandidateStartUnknown
}

func (d *Docker) docker(ctx context.Context, args ...string) ([]byte, error) {
	return command(ctx, "docker", append([]string{"--host", "unix:///var/run/docker.sock"}, args...)...)
}

func (d *Docker) Preflight(ctx context.Context, app, network string) error {
	if d.Store == nil || d.App != app || d.Network != network || !scopeName(app) || !scopeName(network) || !filepath.IsAbs(d.ComposeBinary) || d.ComposeVersion == "" {
		return errors.New("invalid local Docker executor scope")
	}
	version, err := command(ctx, d.ComposeBinary, "version", "--short")
	if err != nil || strings.TrimSpace(string(version)) != d.ComposeVersion {
		return errors.New("Compose version does not match the explicit pin")
	}
	if err := d.Capacity(ctx); err != nil {
		return err
	}
	body, err := d.docker(ctx, "network", "inspect", network)
	if err != nil {
		return err
	}
	return validateApplicationNetwork(body, app, network)
}

// Capacity is a measurement, not a reservation. It is called both before any
// staging and after all declared immutable images have been pulled/unpacked.
func (d *Docker) Capacity(ctx context.Context) error {
	if ctx.Err() != nil || d.Store == nil {
		return errors.New("host capacity cannot be established")
	}
	if d.MinFreeMemory == 0 && d.MinFreeDisk == 0 {
		return nil
	}
	memory, disk, err := availableCapacity(d.Store.root.Name())
	if err != nil {
		return errors.New("host capacity cannot be established")
	}
	if memory < d.MinFreeMemory || disk < d.MinFreeDisk {
		return errors.New("host capacity is below the profile's configured floor")
	}
	return nil
}

// App-private means a scoped user-defined bridge with no published candidate
// ports, not necessarily Docker's no-egress Internal mode. The existing Compose
// control uses bridge NAT for outbound service dependencies. Internal bridges
// remain useful for isolated tests and applications that need no outbound access.
func validateApplicationNetwork(body []byte, app, name string) error {
	var networks []struct {
		Name     string
		Driver   string
		Scope    string
		Internal *bool
		Labels   map[string]string
		Options  map[string]string
	}
	if json.Unmarshal(body, &networks) != nil || len(networks) != 1 {
		return errors.New("invalid application network inspection")
	}
	network := networks[0]
	if network.Name != name || network.Driver != "bridge" || network.Scope != "local" || network.Internal == nil || network.Labels["io.komizo.app"] != app {
		return errors.New("network is not an owned local application bridge")
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		mode := network.Options["com.docker.network.bridge.gateway_mode_"+family]
		if mode != "" && mode != "nat" && !(mode == "isolated" && *network.Internal) {
			return errors.New("application network must not expose unpublished ports through direct routing")
		}
	}
	return nil
}

func (d *Docker) inspect(ctx context.Context, instance Instance) (*container, error) {
	if instance.App != d.App || !strings.HasPrefix(instance.Name, "kmz-") || !scopeName(instance.Name) {
		return nil, errors.New("instance is outside executor scope")
	}
	// A successful scoped list distinguishes absence from daemon failure.
	listed, err := d.docker(ctx, "container", "ls", "--all", "--filter", "name=^/"+instance.Name+"$", "--format", "{{.ID}}")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(listed)) == "" {
		return nil, nil
	}
	body, err := d.docker(ctx, "container", "inspect", instance.Name)
	if err != nil {
		return nil, err
	}
	var entries []container
	if json.Unmarshal(body, &entries) != nil || len(entries) != 1 {
		return nil, errors.New("invalid container inspection")
	}
	for key, value := range labels(instance) {
		if entries[0].Config.Labels[key] != value {
			return nil, errors.New("container ownership or immutable identity does not match")
		}
	}
	if entries[0].ID == "" || entries[0].State.StartedAt == "" {
		return nil, errors.New("container incarnation is unknown")
	}
	return &entries[0], nil
}

// Lifecycle uses only the declared argv inside the owned container, at its
// configured user. No host shell, added capabilities, or published admin port.
func (d *Docker) Lifecycle(ctx context.Context, instance Instance, action string, proof Retirement) (Retirement, error) {
	deadline, bounded := ctx.Deadline()
	if !bounded || ctx.Err() != nil {
		return proof, errors.New("lifecycle operation requires a live deadline")
	}
	stage := action
	if action == "abort-quiesce" {
		stage = "quiesce"
	}
	previous := map[string]string{"quiesce": "", "seal": "quiesce", "drain": "seal", "stop": "drain", "remove": "stop"}
	want, known := previous[stage]
	if !known || proof.Stage != want {
		return proof, errors.New("invalid application lifecycle transition")
	}
	current, err := d.inspect(ctx, instance)
	if err != nil {
		return proof, err
	}
	if current == nil {
		if action == "abort-quiesce" && proof.Stage == "" {
			proof.Absent = true
		}
		if !proof.Absent && action != "remove" {
			return proof, errors.New("retiring instance disappeared without stop proof")
		}
		if action == "remove" {
			if err := d.removeArtifact(instance); err != nil {
				return proof, err
			}
		}
		proof.Stage = stage
		return proof, nil
	}
	if err := instance.Lifecycle.Validate(); err != nil {
		return proof, err
	}
	if proof.Absent {
		return proof, errors.New("previously absent candidate appeared during abort")
	}
	if current.HostConfig.RestartPolicy.Name != "" && current.HostConfig.RestartPolicy.Name != "no" {
		return proof, errors.New("automatic restart policy invalidates retirement proof")
	}
	if proof.Stage == "" {
		proof.ID, proof.StartedAt = current.ID, current.State.StartedAt
		proof.NotStarted = action == "abort-quiesce" && current.State.Status == "created"
	}
	if err := sameIncarnation(current, proof); err != nil {
		return proof, err
	}
	if proof.NotStarted {
		if current.State.Status != "created" {
			return proof, errors.New("candidate started after never-started proof")
		}
		if _, err := removalArguments(instance, current); err != nil {
			return proof, err
		}
		if action != "remove" {
			proof.Stage = stage
			return proof, nil
		}
	}
	if action == "remove" {
		args, err := removalArguments(instance, current)
		if err != nil {
			return proof, err
		}
		args[len(args)-1] = proof.ID // never resolve a mutable name at the destructive call
		if _, err := d.docker(ctx, args...); err != nil {
			return proof, err
		}
		if err := d.removeArtifact(instance); err != nil {
			return proof, err
		}
	} else if action == "stop" {
		if current.State.Running {
			if current.State.Status != "running" || current.State.Restarting || current.State.Dead || current.State.OOMKilled {
				return proof, errors.New("unsafe stop state")
			}
			// Unlike docker stop's finite timeout, TERM alone has no SIGKILL
			// fallback. Cancelling the CLI cannot schedule a later forced kill.
			if _, err := d.docker(ctx, "kill", "--signal", "SIGTERM", proof.ID); err != nil {
				return proof, err
			}
		}
		for {
			current, err = d.inspect(ctx, instance)
			if err != nil {
				return proof, err
			}
			if err := sameIncarnation(current, proof); err != nil {
				return proof, err
			}
			if !current.State.Running {
				if current.State.Status != "exited" {
					return proof, errors.New("graceful stop has no exit proof")
				}
				if _, err := removalArguments(instance, current); err != nil {
					return proof, err
				}
				break
			}
			if err := pause(ctx, 20*time.Millisecond); err != nil {
				return proof, err
			}
		}
	} else {
		if !current.State.Running || current.State.Status != "running" || current.State.Restarting || current.State.Dead || current.State.OOMKilled {
			return proof, errors.New("application lifecycle requires a healthy running incarnation")
		}
		nonce := rand.Text()
		args := append([]string{"exec", proof.ID}, instance.Lifecycle.Command...)
		args = append(args, stage, nonce, instance.Generation, instance.Identity, strconv.FormatInt(deadline.UnixMilli(), 10))
		body, err := d.docker(ctx, args...)
		if err != nil || string(body) != "komizo-lifecycle-v1 "+stage+" "+nonce+"\n" {
			return proof, errors.New("application did not positively acknowledge lifecycle request")
		}
		current, err = d.inspect(ctx, instance)
		if err != nil {
			return proof, err
		}
		if err := sameIncarnation(current, proof); err != nil {
			return proof, err
		}
		if !current.State.Running {
			return proof, errors.New("application exited during lifecycle proof")
		}
	}
	proof.Stage = stage
	return proof, nil
}

func sameIncarnation(current *container, proof Retirement) error {
	if current == nil || proof.ID == "" || proof.StartedAt == "" || current.ID != proof.ID || current.State.StartedAt != proof.StartedAt {
		return errors.New("container incarnation changed; retirement proof invalid")
	}
	return nil
}

// Stage authenticates and pulls/unpacks the declared immutable image and writes
// only the private journal artifact. It never creates or starts a candidate.
func (d *Docker) Stage(ctx context.Context, instance Instance, compose []byte) error {
	if _, err := d.inspect(ctx, instance); err != nil {
		return err
	}
	if err := d.checkImageVolumes(ctx, instance, compose, true); err != nil {
		return err
	}
	return d.Store.WritePrivate(instance.Name+".json", compose)
}

func (d *Docker) Prepare(ctx context.Context, instance Instance, compose []byte) error {
	existing, err := d.inspect(ctx, instance)
	if err != nil {
		return err
	}
	if existing != nil {
		if existing.State.Running {
			return nil
		}
		if instance.Mode == "one-shot" && existing.State.Status == "exited" && existing.State.ExitCode == 0 && !existing.State.OOMKilled && !existing.State.Dead {
			return nil
		}
		return candidateStartCommand(ctx, "docker", "--host", "unix:///var/run/docker.sock", "start", instance.Name)
	}
	if err := d.checkImageVolumes(ctx, instance, compose, false); err != nil {
		return err
	}
	file := instance.Name + ".json"
	// Stage wrote the generation-unique private artifact before the post-pull
	// capacity gate. Candidate start performs no further journal or image write.
	args := []string{"--host", "unix:///var/run/docker.sock", "--project-name", d.App, "--project-directory", d.Store.root.Name()}
	if d.EnvFile != "" {
		args = append(args, "--env-file", d.EnvFile)
	}
	args = append(args, composeStartArguments(d.Store.Path(file), instance.Name)...)
	if err := candidateStartCommand(ctx, d.ComposeBinary, args...); err != nil {
		return err
	}
	created, err := d.inspect(ctx, instance)
	completedOneShot := instance.Mode == "one-shot" && created != nil && created.State.Status == "exited" && created.State.ExitCode == 0 && !created.State.OOMKilled && !created.State.Dead
	if err != nil || created == nil || (!created.State.Running && !completedOneShot) {
		return errCandidateStartProcess
	}
	return nil
}

func composeStartArguments(file, instance string) []string {
	return []string{"--file", file, "up", "--detach", "--no-deps", "--no-recreate", "--pull", "never", instance}
}

func (d *Docker) Ready(ctx context.Context, instance Instance) error {
	if instance.Mode == "worker" {
		return d.Candidate(ctx, instance, "ready")
	}
	if instance.Mode == "one-shot" {
		current, err := d.inspect(ctx, instance)
		if err != nil || current == nil || current.State.Running || current.State.Status != "exited" || current.State.ExitCode != 0 || current.State.OOMKilled || current.State.Dead || current.State.Restarting {
			return errors.New("one-shot completion is not positively established")
		}
		return nil
	}
	if instance.Port < 1 || instance.Port > 65535 || !strings.HasPrefix(instance.ReadyPath, "/") || strings.HasPrefix(instance.ReadyPath, "//") || strings.ContainsAny(instance.ReadyPath, "\r\n?#") {
		return errors.New("invalid persisted readiness declaration")
	}
	current, err := d.inspect(ctx, instance)
	if err != nil || current == nil || !current.State.Running {
		return errors.New("instance is not running")
	}
	address := current.NetworkSettings.Networks[d.Network].IPAddress
	if net.ParseIP(address) == nil {
		return errors.New("candidate has no address on its private network")
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer transport.CloseIdleConnections()
	url := "http://" + net.JoinHostPort(address, strconv.Itoa(instance.Port)) + instance.ReadyPath
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return errors.New("invalid readiness request")
	}
	if instance.ReadyHost != "" {
		request.Host = instance.ReadyHost
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("candidate readiness request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("candidate is not ready")
	}
	return nil
}

// Candidate performs non-retirement lifecycle operations. Worker images start
// with KOMIZO_CANDIDATE=standby; ready must prove that state and activate is a
// monotonic, idempotent handoff after the old worker has quiesced.
func (d *Docker) Candidate(ctx context.Context, instance Instance, action string) error {
	deadline, bounded := ctx.Deadline()
	if !bounded || instance.Mode != "worker" || (action != "ready" && action != "activate") {
		return errors.New("invalid worker candidate lifecycle request")
	}
	if err := instance.Lifecycle.Validate(); err != nil {
		return err
	}
	current, err := d.inspect(ctx, instance)
	if err != nil || current == nil || !current.State.Running || current.State.Status != "running" || current.State.Restarting || current.State.Dead || current.State.OOMKilled {
		return errors.New("worker candidate incarnation is not healthy")
	}
	nonce := rand.Text()
	args := append([]string{"exec", current.ID}, instance.Lifecycle.Command...)
	args = append(args, action, nonce, instance.Generation, instance.Identity, strconv.FormatInt(deadline.UnixMilli(), 10))
	body, err := d.docker(ctx, args...)
	if err != nil || string(body) != "komizo-lifecycle-v1 "+action+" "+nonce+"\n" {
		return errors.New("worker did not positively acknowledge candidate lifecycle request")
	}
	after, err := d.inspect(ctx, instance)
	if err != nil || after == nil || after.ID != current.ID || after.State.StartedAt != current.State.StartedAt || !after.State.Running {
		return errors.New("worker candidate incarnation changed during lifecycle proof")
	}
	return nil
}

func (d *Docker) Remove(ctx context.Context, instance Instance) error {
	current, err := d.inspect(ctx, instance)
	if err != nil {
		return err
	}
	// Gateway accounting alone does not authorize killing application work.
	// Removal is a final cleanup operation, never a substitute for app drain and
	// graceful stop. Non-forced removal also refuses a concurrent restart.
	if current != nil {
		args, err := removalArguments(instance, current)
		if err != nil {
			return err
		}
		args[len(args)-1] = current.ID
		if _, err := d.docker(ctx, args...); err != nil {
			return err
		}
	}
	return d.removeArtifact(instance)
}

func (d *Docker) removeArtifact(instance Instance) error {
	if err := d.Store.root.Remove(instance.Name + ".json"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot remove retired private candidate artifact")
	}
	return nil
}

func removalArguments(instance Instance, current *container) ([]string, error) {
	if current == nil || current.State.Running || current.State.Restarting || current.State.Dead || current.State.OOMKilled {
		return nil, errors.New("instance has not stopped cleanly; refusing removal")
	}
	if current.State.Status != "created" && (current.State.Status != "exited" || current.State.ExitCode != 0) {
		return nil, errors.New("instance exit cannot authorize cleanup; operator recovery required")
	}
	return []string{"rm", "--volumes", instance.Name}, nil
}

var _ Backend = (*Docker)(nil)
var _ RecoveryBackend = (*Docker)(nil)

// Image-declared VOLUMEs are otherwise absent from Compose input and can
// silently introduce writable state. Require explicit mounts or tmpfs targets.
func (d *Docker) checkImageVolumes(ctx context.Context, instance Instance, compose []byte, allowPull bool) error {
	var document struct {
		Services map[string]struct {
			Image   string   `json:"image"`
			Tmpfs   []string `json:"tmpfs"`
			Volumes []struct {
				Target string `json:"target"`
			} `json:"volumes"`
		} `json:"services"`
	}
	if json.Unmarshal(compose, &document) != nil {
		return errors.New("invalid private candidate document")
	}
	service, ok := document.Services[instance.Name]
	if !ok || service.Image == "" {
		return errors.New("candidate image is unresolved")
	}
	body, err := d.docker(ctx, "image", "inspect", service.Image)
	if err != nil {
		if !allowPull {
			return errors.New("candidate image is absent after the post-pull capacity gate")
		}
		if err := d.pullImage(ctx, service.Image); err != nil {
			return err
		}
		body, err = d.docker(ctx, "image", "inspect", service.Image)
		if err != nil {
			return err
		}
	}
	var images []struct {
		Config struct{ Volumes map[string]json.RawMessage }
	}
	if json.Unmarshal(body, &images) != nil || len(images) != 1 {
		return errors.New("invalid candidate image metadata")
	}
	covered := map[string]bool{}
	for _, tmpfs := range service.Tmpfs {
		covered[strings.SplitN(tmpfs, ":", 2)[0]] = true
	}
	for _, mount := range service.Volumes {
		covered[mount.Target] = true
	}
	for target := range images[0].Config.Volumes {
		if !covered[target] {
			return errors.New("image declares writable volume state absent from the lifecycle definition")
		}
	}
	return nil
}
