package box

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// CollectNativeLogs uses one bounded metadata connection, without Compose
// startup per application. Unsupported custom contexts retain the CLI path;
// transport failures preserve the last collected logs and never retry via CLI.
func CollectNativeLogs(ctx context.Context, root, dir string) bool {
	p := &Probe{Root: root}
	if !p.localEngineEligible() {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	e := localDockerEngine(ctx)
	if e == nil {
		return false
	}
	defer e.client.CloseIdleConnections()
	if e.available {
		collectEngineLogs(ctx, p, e, dir)
	}
	return true
}

func collectEngineLogs(ctx context.Context, p *Probe, e *dockerEngine, dir string) {
	inv := e.inventory(ctx)
	if inv.status != "current" {
		return
	}
	states, err := p.appStatesAvailable()
	if err != nil {
		return
	}
	names := make([]string, 0, len(states))
	for _, app := range states {
		if _, err := LogPath(dir, app.name); err != nil {
			continue
		}
		names = append(names, app.name)
		// Static/stopped apps keep their previous tail for diagnosis.
		if app.st["STOPPED"] == "1" {
			continue
		}
		var collected []byte
		failed := false
		containers := inv.forDir(app.dir())
		sort.Slice(containers, func(i, j int) bool { return containers[i].name < containers[j].name })
		for _, c := range containers {
			if c.name == proxyContainer || c.state != "running" {
				continue
			}
			body, err := e.logs(ctx, c)
			if err != nil {
				failed = true
				break
			}
			lines := make([]LogLine, 0, 64)
			for _, line := range strings.Split(strings.TrimSuffix(string(body), "\n"), "\n") {
				if line != "" {
					lines = append(lines, LogLine{Service: c.service, Text: line})
				}
			}
			collected = append(collected, FormatLog(lines)...)
			if len(collected) > LogsMax {
				collected = collected[len(collected)-LogsMax:]
				if i := bytes.IndexByte(collected, '\n'); i >= 0 {
					collected = collected[i+1:]
				}
			}
		}
		if !failed && len(bytes.TrimSpace(collected)) > 0 {
			_ = WriteLog(dir, app.name, collected)
		}
	}
	// Prune only after both registry enumeration and metadata collection succeed.
	_ = PruneLogs(dir, names)
}

func (e *dockerEngine) logs(ctx context.Context, c *containerInfo) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/v"+reportDockerAPI+"/containers/"+c.id+"/logs?stdout=1&stderr=1&tail=500", nil)
	if err != nil {
		return nil, errors.New("invalid log request")
	}
	response, err := e.client.Do(req)
	if err != nil {
		return nil, errors.New("log metadata unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("log metadata refused")
	}
	maximum := int64(LogsMax + 8*500)
	if maximum > e.remaining {
		maximum = e.remaining
	}
	if maximum <= 0 {
		return nil, errors.New("log reading budget exhausted")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	e.remaining -= int64(len(body))
	if err != nil || int64(len(body)) > maximum {
		return nil, errors.New("log reading exceeded its bound or was interrupted")
	}
	if c.tty {
		return body, nil
	}
	var output []byte
	for len(body) > 0 {
		if len(body) < 8 || (body[0] != 1 && body[0] != 2) || body[1] != 0 || body[2] != 0 || body[3] != 0 {
			return nil, errors.New("invalid log frame")
		}
		size := int(binary.BigEndian.Uint32(body[4:8]))
		body = body[8:]
		if size > len(body) || len(output)+size > LogsMax {
			return nil, errors.New("invalid or oversized log frame")
		}
		output = append(output, body[:size]...)
		body = body[size:]
	}
	return output, nil
}
