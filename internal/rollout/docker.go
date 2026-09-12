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
	Store                         *Store
	MinFreeMemory, MinFreeDisk    uint64
}

type container struct {
	HostConfig struct{ RestartPolicy struct{ Name string } }
	ID         string
	Name       string
	Config     struct {
		Labels map[string]string
	}
	State struct {
		StartedAt  string
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

func command(ctx context.Context, name string, args ...string) ([]byte, error) {
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
	var output cappedBuffer
	cmd.Stdout, cmd.Stderr = &output, io.Discard
	if err := cmd.Run(); err != nil {
		return nil, errors.New("local executor command failed")
	}
	return output.Bytes(), nil
}

type cappedBuffer struct{ bytes.Buffer }

func (b *cappedBuffer) Write(data []byte) (int, error) {
	if b.Len()+len(data) > 16<<20 {
		return 0, errors.New("executor output limit")
	}
	return b.Buffer.Write(data)
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
	if err := instance.Lifecycle.Validate(); err != nil {
		return proof, err
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
		_, err := d.docker(ctx, "start", instance.Name)
		return err
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
	_, err = command(ctx, d.ComposeBinary, args...)
	if err != nil {
		return err
	}
	created, err := d.inspect(ctx, instance)
	completedOneShot := instance.Mode == "one-shot" && created != nil && created.State.Status == "exited" && created.State.ExitCode == 0 && !created.State.OOMKilled && !created.State.Dead
	if err != nil || created == nil || (!created.State.Running && !completedOneShot) {
		return errors.New("candidate did not start with expected ownership")
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
		if _, err := d.docker(ctx, "pull", "--quiet", service.Image); err != nil {
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
