package rollout

import (
	"bytes"
	"context"
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
)

// Docker is a local-only executor. It never inherits DOCKER_HOST/CONTEXT, grants
// new doas rights, mounts the Docker socket into application candidates, or
// invokes arbitrary shell hooks. Compose must be an explicit versioned binary.
type Docker struct {
	App, Network                  string
	ComposeBinary, ComposeVersion string
	Store                         *Store
}

type container struct {
	Name   string
	Config struct {
		Labels map[string]string
	}
	State           struct{ Running bool }
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
	body, err := d.docker(ctx, "network", "inspect", network)
	if err != nil {
		return err
	}
	var networks []struct {
		Internal bool
		Labels   map[string]string
	}
	if json.Unmarshal(body, &networks) != nil || len(networks) != 1 || !networks[0].Internal || networks[0].Labels["io.komizo.app"] != app {
		return errors.New("network is not an owned internal application network")
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
	return &entries[0], nil
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
		_, err := d.docker(ctx, "start", instance.Name)
		return err
	}
	if err := d.checkImageVolumes(ctx, instance, compose); err != nil {
		return err
	}
	file := instance.Name + ".json"
	if err := d.Store.WritePrivate(file, compose); err != nil {
		return err
	}
	_, err = command(ctx, d.ComposeBinary, "--host", "unix:///var/run/docker.sock", "--project-name", d.App,
		"--project-directory", d.Store.root.Name(), "--file", d.Store.Path(file),
		"up", "--detach", "--no-deps", "--no-recreate", "--pull", "missing", instance.Name)
	if err != nil {
		return err
	}
	created, err := d.inspect(ctx, instance)
	if err != nil || created == nil || !created.State.Running {
		return errors.New("candidate did not start with expected ownership")
	}
	return nil
}

func (d *Docker) Ready(ctx context.Context, instance Instance) error {
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

func (d *Docker) Remove(ctx context.Context, instance Instance) error {
	current, err := d.inspect(ctx, instance)
	if err != nil {
		return err
	}
	// Engine has persisted positive drain/abort evidence before this call.
	if current != nil {
		if _, err := d.docker(ctx, "rm", "--force", "--volumes", instance.Name); err != nil {
			return err
		}
	}
	if err := d.Store.root.Remove(instance.Name + ".json"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot remove retired private candidate artifact")
	}
	return nil
}

var _ Backend = (*Docker)(nil)

// Image-declared VOLUMEs are otherwise absent from Compose input and can
// silently introduce writable state. Require explicit mounts or tmpfs targets.
func (d *Docker) checkImageVolumes(ctx context.Context, instance Instance, compose []byte) error {
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
