package workload

import (
	"context"
	"errors"
	"path/filepath"
	"regexp"
	"time"
)

var operationIdentity = regexp.MustCompile(`^[a-f0-9]{32}$`)
var contentIdentity = regexp.MustCompile(`^[a-f0-9]{64}$`)
var ErrReadinessUnspecified = errors.New("activation readiness is not configured")
var ErrActivationReconciliation = errors.New("interrupted activation requires reconciliation")
var ErrActivationStopped = errors.New("owner stopped the workload during readiness")

// ActivationRequest describes one already admitted, configured host operation.
// It contains identities and hashes, never a shell command or registry secret.
type ActivationRequest struct {
	Version       int       `json:"version"`
	ID            string    `json:"operation_id"`
	App           string    `json:"app"`
	Candidate     string    `json:"candidate"`
	Previous      string    `json:"previous,omitempty"`
	PolicySHA256  string    `json:"policy_sha256"`
	ComposeSHA256 string    `json:"compose_sha256"`
	RouteSHA256   string    `json:"route_sha256"`
	RoutePath     string    `json:"route_path"`
	Proxy         string    `json:"proxy"`
	Deadline      time.Time `json:"deadline"`
}

type ActivationResult struct {
	Version   int       `json:"version"`
	ID        string    `json:"operation_id"`
	App       string    `json:"app"`
	Candidate string    `json:"candidate"`
	At        time.Time `json:"at"`
	Phase     string    `json:"phase"`
	OK        bool      `json:"ok"`
	Started   *bool     `json:"started,omitempty"`
}

func (r ActivationRequest) Check(now time.Time) error {
	if err := r.CheckIdentity(); err != nil {
		return err
	}
	if !r.Deadline.After(now) || r.Deadline.After(now.Add(25*time.Minute)) {
		return errors.New("expired or unbounded host activation deadline")
	}
	return nil
}

func (r ActivationRequest) CheckIdentity() error {
	if r.Version != 1 || !operationIdentity.MatchString(r.ID) || !identifier.MatchString(r.App) || !revision.MatchString(r.Candidate) ||
		(r.Previous != "" && !revision.MatchString(r.Previous)) || !contentIdentity.MatchString(r.PolicySHA256) || !contentIdentity.MatchString(r.ComposeSHA256) ||
		!contentIdentity.MatchString(r.RouteSHA256) || !identifier.MatchString(r.Proxy) || !filepath.IsAbs(r.RoutePath) || filepath.Clean(r.RoutePath) != r.RoutePath || filepath.Base(r.RoutePath) != r.App+".caddy" || r.Deadline.IsZero() {
		return errors.New("invalid or expired host activation request")
	}
	return nil
}

// ActivationRuntime is the single host adapter for mutation and observation.
// Every method is bounded by the operation context, except durable failure
// acknowledgement which must still be attempted after cancellation.
type ActivationRuntime interface {
	Verify(context.Context, ActivationRequest) error
	Stopped(context.Context, ActivationRequest) (bool, error)
	Compose(context.Context, ActivationRequest, string) error
	ReloadProxy(context.Context, ActivationRequest) error
	Retain(context.Context, ActivationRequest) error
	Ready(context.Context, ActivationRequest) error
	Phase(ActivationRequest, string) error
}

// Activate runs independently of a submitting client's connection. Rootd owns
// its context. A journal in activating/activation_failed is never replayed by
// Verify; an interrupted external effect requires explicit reconciliation.
func Activate(parent context.Context, request ActivationRequest, runtime ActivationRuntime) (result ActivationResult, err error) {
	result = ActivationResult{Version: 1, ID: request.ID, App: request.App, Candidate: request.Candidate, Phase: "refused", At: time.Now().UTC()}
	if err = request.Check(time.Now()); err != nil {
		return result, err
	}
	ctx, cancel := context.WithDeadline(parent, request.Deadline)
	defer cancel()
	if err = runtime.Verify(ctx, request); err != nil {
		if errors.Is(err, ErrActivationReconciliation) {
			result.Phase = "reconciliation_required"
		}
		return result, err
	}
	phase := "configured"
	defer func() {
		result.At = time.Now().UTC()
		if err != nil {
			// A static adapter may restore its previous serving route without
			// changing an image or any application data. Other workloads never
			// acquire rollback authority from this optional hook.
			if recovery, ok := runtime.(interface {
				AbortStatic(context.Context, ActivationRequest) error
			}); ok {
				cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
				err = errors.Join(err, recovery.AbortStatic(cleanup, request))
				stop()
			}
			failure := "failed"
			if phase == "activating" {
				failure = "activation_failed"
			}
			if phase == "activated" {
				failure = "readiness_failed"
			}
			result.Phase = failure
			if ackErr := runtime.Phase(request, failure); ackErr != nil {
				result.Phase = "acknowledgement_failed"
				err = errors.Join(err, ackErr)
			}
		}
	}()
	stopped, err := runtime.Stopped(ctx, request)
	if err != nil {
		return result, err
	}
	if !stopped {
		if err = runtime.Phase(request, "activating"); err != nil {
			return result, err
		}
		phase = "activating"
		if err = runtime.Compose(ctx, request, "up"); err != nil {
			return result, err
		}
		stopped, err = runtime.Stopped(ctx, request)
		if err != nil {
			return result, err
		}
		if stopped {
			if err = runtime.Compose(ctx, request, "stop"); err != nil {
				return result, err
			}
		}
	}
	if err = runtime.ReloadProxy(ctx, request); err != nil {
		return result, err
	}
	if err = runtime.Retain(ctx, request); err != nil {
		return result, err
	}
	if stopped {
		phase = "prepared_stopped"
		if err = runtime.Phase(request, phase); err != nil {
			return result, err
		}
	} else {
		readyVerified := true
		phase = "activated"
		if err = runtime.Phase(request, phase); err != nil {
			return result, err
		}
		if err = runtime.Ready(ctx, request); errors.Is(err, ErrActivationStopped) {
			stopped = true
			err = nil
		} else if errors.Is(err, ErrReadinessUnspecified) {
			err = nil
			readyVerified = false
		} else {
			if err != nil {
				return result, err
			}
		}
		// A stop can arrive while probes run. Acknowledging readiness must never
		// overrule the owner's marker or leave running containers behind it.
		stopped, err = runtime.Stopped(ctx, request)
		if err != nil {
			return result, err
		}
		if stopped {
			if err = runtime.Compose(ctx, request, "stop"); err != nil {
				return result, err
			}
			phase = "prepared_stopped"
		} else if readyVerified {
			phase = "ready"
		}
		if err = runtime.Phase(request, phase); err != nil {
			return result, err
		}
	}
	started := !stopped
	result.Phase, result.OK, result.Started = phase, true, &started
	return result, nil
}
