package workload

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

type ReadinessPolicy struct {
	Probes []ReadinessProbe `json:"probes"`
}
type ReadinessProbe struct {
	URL           string `json:"url"`
	RevisionField string `json:"revision_field,omitempty"`
}

func (p ReadinessPolicy) Check() error {
	if len(p.Probes) == 0 || len(p.Probes) > 8 {
		return errors.New("readiness requires 1..8 operator-owned probes")
	}
	for _, probe := range p.Probes {
		u, err := url.Parse(probe.URL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (probe.RevisionField != "" && !identifier.MatchString(probe.RevisionField)) {
			return errors.New("invalid operator readiness probe")
		}
	}
	return nil
}

var containerID = regexp.MustCompile(`^[a-f0-9]{12,64}$`)

type readyService struct {
	Image    string   `json:"image"`
	Profiles []string `json:"profiles"`
	Restart  string   `json:"restart"`
}
type readyContainer struct {
	Service  string
	Project  string
	Image    string
	Status   string
	ExitCode int
	Health   string
}

// VerifyReadiness never pulls images, executes product commands or mutates a
// database. It joins the protected desired configuration to active image IDs
// and probes the route carrying the proxy's deferred candidate header.
func VerifyReadiness(ctx context.Context, run ImageRun, client *http.Client, p Policy, candidate, composePath string, compose []byte) error {
	if !commitID.MatchString(candidate) || p.Readiness == nil {
		return errors.New("candidate readiness policy is required")
	}
	if err := p.Readiness.Check(); err != nil {
		return err
	}
	if len(compose) > MaxBytes {
		return errors.New("approved workload exceeds limit")
	}
	var doc struct {
		Services map[string]readyService `json:"services"`
	}
	if json.Unmarshal(compose, &doc) != nil || len(doc.Services) == 0 || len(doc.Services) > 32 {
		return errors.New("invalid approved workload")
	}
	ids, err := run(ctx, "compose", "--project-name", p.App, "--project-directory", p.AppDir, "--file", composePath, "ps", "--all", "--quiet")
	if err != nil || len(ids) > 4096 {
		return errors.New("candidate container inventory unavailable")
	}
	containers := map[string]readyContainer{}
	for _, id := range strings.Fields(ids) {
		if !containerID.MatchString(id) || len(containers) >= 32 {
			return errors.New("invalid candidate container inventory")
		}
		format := `{"Service":{{json (index .Config.Labels "com.docker.compose.service")}},"Project":{{json (index .Config.Labels "com.docker.compose.project")}},"Image":{{json .Image}},"Status":{{json .State.Status}},"ExitCode":{{json .State.ExitCode}},"Health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}""{{end}}}`
		body, err := run(ctx, "inspect", "--format", format, id)
		var container readyContainer
		if err != nil || len(body) > 8192 || json.Unmarshal([]byte(body), &container) != nil || container.Project != p.App {
			return errors.New("candidate container identity unavailable")
		}
		if _, duplicate := containers[container.Service]; duplicate {
			return errors.New("duplicate candidate service")
		}
		containers[container.Service] = container
	}
	for name, service := range doc.Services {
		container, exists := containers[name]
		if !exists && len(service.Profiles) > 0 {
			continue
		}
		if !exists {
			return fmt.Errorf("candidate service %s is absent", name)
		}
		id, err := run(ctx, "image", "inspect", "--format", "{{.Id}}", service.Image)
		if err != nil || strings.TrimSpace(id) != container.Image {
			return fmt.Errorf("candidate service %s serves a different image", name)
		}
		completed := service.Restart == "no" && container.Status == "exited" && container.ExitCode == 0
		if !completed && (container.Status != "running" || (container.Health != "" && container.Health != "healthy")) {
			return fmt.Errorf("candidate service %s is unready", name)
		}
	}
	for _, probe := range p.Readiness.Probes {
		if err := probeReady(ctx, client, candidate, probe); err != nil {
			return err
		}
	}
	return nil
}

func probeReady(ctx context.Context, client *http.Client, candidate string, probe ReadinessProbe) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, probe.URL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Cache-Control", "no-cache")
	response, err := client.Do(request)
	if err != nil {
		return errors.New("candidate route unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Komizo-Revision") != candidate {
		return errors.New("route does not identify the ready candidate")
	}
	if probe.RevisionField != "" {
		body, err := io.ReadAll(io.LimitReader(response.Body, MaxBytes+1))
		var document map[string]json.RawMessage
		var revision string
		if err != nil || len(body) > MaxBytes || json.Unmarshal(body, &document) != nil || json.Unmarshal(document[probe.RevisionField], &revision) != nil || revision != candidate {
			return errors.New("product readiness revision differs from candidate")
		}
	} else {
		prefix := make([]byte, 512)
		n, err := response.Body.Read(prefix)
		if (err != nil && err != io.EOF) || len(bytes.TrimSpace(prefix[:n])) == 0 {
			return errors.New("candidate core read returned no content")
		}
	}
	return nil
}
