package rollout

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"

	"github.com/nicodes/komizo/internal/gateway"
)

// GatewayClient uses only an operator-private local Unix socket. It never sends
// management requests through the application's public HTTP listener.
type GatewayClient struct {
	client *http.Client
}

func NewGatewayClient(socket string) (*GatewayClient, error) {
	if !filepath.IsAbs(socket) {
		return nil, errors.New("gateway admin socket must be absolute")
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}}
	return &GatewayClient{client: &http.Client{Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (g *GatewayClient) request(ctx context.Context, method, path string, body []byte, into any) error {
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("gateway operation requires a deadline")
	}
	r, err := http.NewRequestWithContext(ctx, method, "http://gateway"+path, bytes.NewReader(body))
	if err != nil {
		return errors.New("invalid gateway request")
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := g.client.Do(r)
	if err != nil {
		return errors.New("gateway management connection failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("gateway management operation was refused")
	}
	if into == nil {
		_, err := io.Copy(io.Discard, io.LimitReader(response.Body, gateway.MaxConfigBytes+1))
		if err != nil {
			return errors.New("gateway response was interrupted")
		}
		return nil
	}
	d := json.NewDecoder(io.LimitReader(response.Body, gateway.MaxConfigBytes+1))
	if err := d.Decode(into); err != nil {
		return errors.New("invalid gateway response")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("gateway response has trailing data")
	}
	return nil
}

func (g *GatewayClient) Current(ctx context.Context) (gateway.Config, string, error) {
	var state struct {
		Config gateway.Config `json:"config"`
		Epoch  string         `json:"epoch"`
	}
	if err := g.request(ctx, http.MethodGet, "/routes", nil, &state); err != nil {
		return gateway.Config{}, "", err
	}
	encoded, _ := json.Marshal(state.Config)
	config, err := gateway.Decode(bytes.NewReader(encoded))
	if err != nil || state.Epoch == "" {
		return gateway.Config{}, "", errors.New("invalid gateway state")
	}
	return config, state.Epoch, nil
}

func (g *GatewayClient) Apply(ctx context.Context, config gateway.Config) (string, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return "", errors.New("cannot encode gateway routes")
	}
	wanted, err := gateway.Decode(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	if current, epoch, err := g.Current(ctx); err == nil && reflect.DeepEqual(current, wanted) {
		return epoch, nil
	}
	writeErr := g.request(ctx, http.MethodPut, "/routes", data, nil)
	// Readback is required even after an apparent failure: the response can
	// disappear after the gateway has atomically committed admission state.
	current, epoch, err := g.Current(ctx)
	if err == nil && reflect.DeepEqual(current, wanted) {
		return epoch, nil
	}
	if writeErr != nil {
		return "", errors.New("gateway route update outcome is unconfirmed")
	}
	return "", errors.New("gateway did not confirm the desired generation")
}

func (g *GatewayClient) Status(ctx context.Context, id string) (gateway.Status, error) {
	var status gateway.Status
	err := g.request(ctx, http.MethodGet, "/generations/"+url.PathEscape(id), nil, &status)
	if err != nil || status.Generation != id || status.Epoch == "" {
		return gateway.Status{}, errors.New("gateway drain status is unknown")
	}
	return status, nil
}

func (g *GatewayClient) Forget(ctx context.Context, id string) error {
	return g.request(ctx, http.MethodDelete, "/generations/"+url.PathEscape(id), nil, nil)
}

var _ RouteController = (*GatewayClient)(nil)
