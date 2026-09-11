// Package rollout contains bounded rollout execution primitives. A primitive is
// not a complete deploy: callers still own authorization, durable state and
// host-wide serialization of shared resources.
package rollout

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
)

const maxConfigBytes = 8 << 20

// Caddy applies complete, caller-generated configurations and verifies the
// authoritative config after every load. A reset/lost response is an ambiguous
// outcome, not evidence that nothing changed. It never retries application work.
type Caddy struct {
	endpoint string
	client   *http.Client
	poll     time.Duration
	lock     chan struct{}
}

// NewCaddy requires an explicit reconciliation interval. Callers must supply
// deadlines to Apply; no production latency/retirement policy is invented here.
// The transport may dial an operator-private Unix socket. A nil transport uses
// direct connections with no environment proxy and no reused admin connections.
func NewCaddy(endpoint string, transport http.RoundTripper, poll time.Duration) (*Caddy, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Scheme != "http" && u.Scheme != "https") || (u.Path != "" && u.Path != "/") || poll <= 0 {
		return nil, errors.New("invalid Caddy admin endpoint or reconciliation interval")
	}
	if transport == nil {
		transport = &http.Transport{Proxy: nil, DisableKeepAlives: true}
	}
	return &Caddy{
		endpoint: strings.TrimSuffix(endpoint, "/"), poll: poll, lock: make(chan struct{}, 1),
		client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}, nil
}

// Apply is idempotent for identical effective JSON. It refuses unbounded calls.
// Errors are value-free: config bodies, credentials and admin diagnostics never
// reach a deployment log. A failure requires caller reconciliation before any
// destructive cleanup; it is not permission to assume the previous route is live.
func (c *Caddy) Apply(ctx context.Context, config []byte) error {
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("Caddy update requires a context deadline")
	}
	wanted, err := configObject(config)
	if err != nil {
		return errors.New("invalid Caddy configuration document")
	}
	select {
	case c.lock <- struct{}{}:
		defer func() { <-c.lock }()
	case <-ctx.Done():
		return errors.New("Caddy update cancelled while waiting for serialization")
	}
	ticker := time.NewTicker(c.poll)
	defer ticker.Stop()
	for {
		current, err := c.current(ctx)
		if err == nil {
			if reflect.DeepEqual(current, wanted) {
				return nil
			}
			// A failed Caddy app load can still replace its admin listener.
			// A rollout must not move/disable the control plane it needs for
			// reconciliation. Administrative changes need a separate operation.
			if !reflect.DeepEqual(current["admin"], wanted["admin"]) {
				return errors.New("rollout cannot change Caddy admin configuration")
			}
			break
		}
		select {
		case <-ctx.Done():
			return errors.New("Caddy current state was not confirmed before deadline")
		case <-ticker.C:
		}
	}
	for {
		// /load is a desired-state replacement. Repeating the same generated
		// config is safe after an ambiguous transport failure, provided the
		// caller serializes all writers to this router (not just this object).
		status, postErr := c.load(ctx, config)
		if current, err := c.current(ctx); err == nil && reflect.DeepEqual(current, wanted) {
			return nil
		}
		if postErr == nil && status >= 400 && status < 500 {
			return errors.New("Caddy rejected configuration; desired state not confirmed")
		}
		select {
		case <-ctx.Done():
			return errors.New("Caddy desired state was not confirmed before deadline")
		case <-ticker.C:
		}
	}
}

func (c *Caddy) current(ctx context.Context) (map[string]any, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+"/config/", nil)
	if err != nil {
		return nil, err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("cannot inspect Caddy configuration")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	return configObject(body)
}

func (c *Caddy) load(ctx context.Context, config []byte) (int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/load", bytes.NewReader(config))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, maxConfigBytes+1))
	return response.StatusCode, err
}

func configObject(data []byte) (map[string]any, error) {
	if len(data) > maxConfigBytes || !json.Valid(data) {
		return nil, errors.New("invalid configuration")
	}
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, errors.New("configuration must be an object")
	}
	return object, nil
}
