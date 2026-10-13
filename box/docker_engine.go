package box

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Reports need no mutations, credentials, CLI plugins or persistent cache.
// API 1.45 provides the metadata used here. Newer/older incompatible daemons
// and customized CLI contexts retain the existing CLI implementation. API 1.45
// preserves the explicit alias list; older APIs inject legacy short-ID aliases.
const reportDockerAPI = "1.45"

type engineVersion struct {
	Version, GitCommit, ApiVersion, MinAPIVersion string
}

type dockerEngine struct {
	client    *http.Client
	version   engineVersion
	available bool
	remaining int64
}

func (p *Probe) localEngineEligible() bool {
	if p.Root != "" || p.Docker != nil || runtime.GOOS != "linux" {
		return false
	}
	for _, key := range []string{"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION", "DOCKER_CONFIG"} {
		if os.Getenv(key) != "" {
			return false
		}
	}
	// Preserve customized wrappers, including the shell fixtures. Komizo's
	// ordinary Alpine installation uses the packaged CLI at /usr/bin/docker.
	path, err := exec.LookPath("docker")
	if err != nil || (path != "/usr/bin/docker" && path != "/usr/local/bin/docker") {
		return false
	}
	cli, err := os.Open(path)
	if err != nil {
		return false
	}
	var magic [4]byte
	_, err = io.ReadFull(cli, magic[:])
	cli.Close()
	if err != nil || string(magic[:]) != "\x7fELF" {
		return false
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	return defaultDockerContext(filepath.Join(home, ".docker", "config.json"))
}

func defaultDockerContext(path string) bool {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return true
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	// Inspect only context selection; never retain or expose registry auth.
	var config struct{ CurrentContext string }
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(data) > 1<<20 || json.Unmarshal(data, &config) != nil {
		return false
	}
	return config.CurrentContext == "" || config.CurrentContext == "default"
}

func localDockerEngine(ctx context.Context) *dockerEngine {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", "/var/run/docker.sock")
		},
		DisableCompression: true,
		MaxIdleConns:       1,
		MaxConnsPerHost:    1,
	}
	return newDockerEngine(ctx, &http.Client{Transport: transport, Timeout: 8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("Docker metadata redirect refused") }})
}

func newDockerEngine(ctx context.Context, client *http.Client) *dockerEngine {
	e := &dockerEngine{client: client, remaining: 64 << 20}
	if e.read(ctx, "/version", &e.version, 64<<10) != nil {
		return e // stopped/unavailable; do not retry through an unbounded CLI
	}
	if !apiContains(e.version.MinAPIVersion, e.version.ApiVersion, reportDockerAPI) {
		e.client.CloseIdleConnections()
		return nil // protocol compatibility retains the existing CLI path
	}
	if e.version.Version == "" || len(e.version.Version) > 128 || len(e.version.GitCommit) > 128 || strings.ContainsAny(e.version.Version+e.version.GitCommit, "\r\n\t") {
		return e
	}
	e.available = true
	return e
}

func apiContains(minimum, maximum, target string) bool {
	parse := func(s string) int {
		major, minor, ok := strings.Cut(s, ".")
		n, err := strconv.Atoi(minor)
		if !ok || major != "1" || err != nil || n < 0 || n > 999 {
			return -1
		}
		return n
	}
	lo, hi, want := parse(minimum), parse(maximum), parse(target)
	return lo >= 0 && hi >= lo && want >= lo && want <= hi
}

func (e *dockerEngine) read(ctx context.Context, path string, result any, maximum int64) error {
	if e.remaining < maximum {
		maximum = e.remaining
	}
	if maximum <= 0 {
		return errors.New("Docker metadata reading exhausted its byte budget")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	response, err := e.client.Do(req)
	if err != nil {
		return errors.New("Docker metadata unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("Docker metadata request refused")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	e.remaining -= int64(len(body))
	if err != nil || int64(len(body)) > maximum {
		return errors.New("Docker metadata response exceeds its bound or was interrupted")
	}
	if json.Unmarshal(body, result) != nil {
		return errors.New("Docker metadata response is invalid")
	}
	return nil
}

func (e *dockerEngine) inventory(ctx context.Context) dockerInventory {
	inv := dockerInventory{status: "current", byID: map[string]*containerInfo{}, byDir: map[string][]*containerInfo{}}
	var rows []struct {
		Id, State, Status, Image string
		Names                    []string
		Labels                   map[string]string
	}
	if e.read(ctx, "/v"+reportDockerAPI+"/containers/json?all=1", &rows, 8<<20) != nil || len(rows) > 1024 {
		inv.status, inv.failure = "unavailable", "list_unavailable"
		return inv
	}
	for _, row := range rows {
		if len(row.Id) != 64 || strings.Trim(row.Id, "0123456789abcdef") != "" || len(row.Names) == 0 {
			return dockerInventory{status: "unavailable", failure: "list_invalid", byID: map[string]*containerInfo{}, byDir: map[string][]*containerInfo{}}
		}
		c := &containerInfo{inspectionUnavailable: true, id: row.Id, name: strings.TrimPrefix(row.Names[0], "/"), state: row.State, status: row.Status,
			image: row.Image, service: row.Labels["com.docker.compose.service"], workingDir: row.Labels["com.docker.compose.project.working_dir"]}
		if inv.byID[c.id] != nil {
			return dockerInventory{status: "unavailable", failure: "list_invalid", byID: map[string]*containerInfo{}, byDir: map[string][]*containerInfo{}}
		}
		inv.byID[c.id] = c
		if c.workingDir != "" {
			inv.byDir[filepath.Clean(c.workingDir)] = append(inv.byDir[filepath.Clean(c.workingDir)], c)
		}
	}
	for _, c := range inv.sorted() {
		var detail struct {
			Id     string
			Config struct{ Tty bool }
			State  *struct {
				Status                string
				StartedAt, FinishedAt string
				ExitCode, Pid         *int
				Health                *struct{ Status string }
			}
			NetworkSettings struct {
				Networks map[string]struct{ Aliases []string }
			}
			Mounts []struct{ Type, Name, Source string }
		}
		if e.read(ctx, "/v"+reportDockerAPI+"/containers/"+c.id+"/json", &detail, 4<<20) != nil || detail.Id != c.id || detail.State == nil || detail.State.ExitCode == nil || detail.State.Pid == nil || detail.State.Status == "" {
			inv.status, inv.failure = "partial", "inspection_unavailable"
			continue // vanished/unavailable metadata remains unknown, not invented
		}
		c.inspectionUnavailable = false
		c.tty = detail.Config.Tty
		c.state = detail.State.Status
		c.startedAt, c.finishedAt = parseStamp(detail.State.StartedAt), parseStamp(detail.State.FinishedAt)
		c.exitCode, c.pid = *detail.State.ExitCode, *detail.State.Pid
		if detail.State.Health != nil {
			c.health = detail.State.Health.Status
		}
		c.networks = map[string][]string{}
		for name, network := range detail.NetworkSettings.Networks {
			c.networks[name] = network.Aliases
		}
		for _, mount := range detail.Mounts {
			if mount.Type == "volume" {
				c.mounts = append(c.mounts, mountInfo{name: mount.Name, source: mount.Source})
			}
		}
	}
	return inv
}

func (e *dockerEngine) network(ctx context.Context, name string) (string, error) {
	if name == "" || name == "." || name == ".." || len(name) > 256 || strings.Trim(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != "" {
		return "", errors.New("Docker network metadata name is invalid")
	}
	var detail struct {
		Driver string
		IPAM   struct{ Config []struct{ Subnet string } }
	}
	if err := e.read(ctx, "/v"+reportDockerAPI+"/networks/"+url.PathEscape(name), &detail, 1<<20); err != nil {
		return "", err
	}
	out := detail.Driver + dsep
	for _, config := range detail.IPAM.Config {
		out += config.Subnet
	}
	return out, nil
}
