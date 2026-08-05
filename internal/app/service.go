package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/nicodes/komizo/box"
)

// Talking to the komizo service.
//
// Four calls, and they are all a person doing something: starting a sign-in,
// finishing one, and creating a server. There is nothing here that reads a box
// -- that is SSH, and it stays SSH, because the service holds no credential for
// anybody's infrastructure and must not start.

// DefaultAPI is the service a session belongs to unless somebody says otherwise.
const DefaultAPI = "https://api.komizo.dev"

// serviceTimeout bounds one call. Short, because every one of these is a person
// waiting at a prompt.
const serviceTimeout = 20 * time.Second

type deviceStart struct {
	UserCode        string `json:"user_code"`
	DeviceCode      string `json:"device_code"`
	VerificationURL string `json:"verification_url"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type devicePoll struct {
	Status string `json:"status"`
	Token  string `json:"token"`
}

type createdServer struct {
	ServerID string `json:"server_id"`
	Token    string `json:"enrolment_token"`
}

// call is one request to the service.
//
// The bearer is optional: the device routes are reached before anybody has a
// credential, which is the whole reason they exist.
func call[T any](ctx context.Context, api, method, path, bearer string, body any) (T, error) {
	var zero T
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return zero, err
		}
		buf = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, api+path, buf)
	if err != nil {
		return zero, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "komizo/"+versionText())
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	res, err := (&http.Client{Timeout: serviceTimeout}).Do(req)
	if err != nil {
		return zero, fmt.Errorf("could not reach %s: %w", api, err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		// The service's own message when it sent one -- it is written for a
		// person and is more use than a status code.
		var msg struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &msg)
		if msg.Message != "" {
			return zero, fmt.Errorf("%s", msg.Message)
		}
		return zero, fmt.Errorf("%s: %s", res.Status, firstLine(raw))
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return zero, nil
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		return zero, fmt.Errorf("could not read what %s said: %w", api, err)
	}
	return out, nil
}

func startSignIn(ctx context.Context, api string) (deviceStart, error) {
	return call[deviceStart](ctx, api, http.MethodPost, "/v1/device/start", "", struct{}{})
}

func pollSignIn(ctx context.Context, api, deviceCode string) (devicePoll, error) {
	return call[devicePoll](ctx, api, http.MethodPost, "/v1/device/poll", "",
		map[string]string{"device_code": deviceCode})
}

// createServer files a box under whoever is signed in, and returns the
// enrolment token it will exchange.
//
// This is the whole point of the CLI having an account: the token is minted and
// used inside one command, so nobody carries it between two surfaces.
func createServer(ctx context.Context, s Session, name string) (createdServer, error) {
	return call[createdServer](ctx, s.API, http.MethodPost, "/v1/servers", s.Token,
		map[string]string{"name": name})
}

func firstLine(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	return string(bytes.TrimSpace(b))
}

// validateAPI is box.ValidateAPI, which refuses a URL a credential should not
// be sent to. Shared so the CLI and the agent refuse the same things.
func validateAPI(raw string) (string, error) { return box.ValidateAPI(raw) }
