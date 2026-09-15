package rollout

import (
	"context"
	"crypto/rand"
	"errors"
	"maps"
	"path/filepath"
	"reflect"
	"slices"
	"time"
)

const recoveryPhase = "verified-recovery"

var ErrRecoveryBudget = errors.New("verified recovery budget expired; state and application fence preserved")

// RecoveryAuthorization is installed by root for exactly one pending
// transaction and service. None of its authority is accepted from the remote
// caller. Digest binds the exact private authorization document.
type RecoveryAuthorization struct {
	Version        int                    `json:"version"`
	App            string                 `json:"app"`
	Transaction    string                 `json:"transaction"`
	Service        string                 `json:"service"`
	Old            RecoveryIncarnationPin `json:"old"`
	Candidate      RecoveryIncarnationPin `json:"candidate"`
	VerifierPath   string                 `json:"verifier_path"`
	VerifierSHA256 string                 `json:"verifier_sha256"`
	VerifierArgs   []string               `json:"verifier_args,omitempty"`
	UID            uint32                 `json:"uid"`
	GID            uint32                 `json:"gid"`
	Overall        time.Duration          `json:"-"`
	Retire         time.Duration          `json:"-"`
	Digest         string                 `json:"-"`
}

type RecoveryIncarnationPin struct {
	ID         string `json:"id"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at,omitempty"`
	ExitCode   int    `json:"exit_code,omitempty"`
	Generation string `json:"generation"`
	Identity   string `json:"identity"`
}

// RecoveryIncarnation is an executor-established fact, not application input.
type RecoveryIncarnation struct {
	ID         string `json:"id"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at,omitempty"`
	ExitCode   int    `json:"exit_code,omitempty"`
	Running    bool   `json:"running,omitempty"`
}

type RecoverySnapshot struct {
	Old       RecoveryIncarnation `json:"old"`
	Candidate RecoveryIncarnation `json:"candidate"`
}

// VerifiedRecovery is deliberately separate from Retirement. It never claims
// application quiesce, drain, graceful stop, or exit zero for the failed old
// incarnation.
type VerifiedRecovery struct {
	AuthorizationDigest string              `json:"authorization_digest"`
	Service             string              `json:"service"`
	Old                 RecoveryIncarnation `json:"old"`
	Candidate           RecoveryIncarnation `json:"candidate"`
	StartedAt           time.Time           `json:"started_at"`
	OverallDeadline     time.Time           `json:"overall_deadline"`
	RetirementDeadline  time.Time           `json:"retirement_deadline"`
	ProvedAt            time.Time           `json:"proved_at,omitempty"`
	ActivatedAt         time.Time           `json:"activated_at,omitempty"`
	ReleasedAt          time.Time           `json:"released_at,omitempty"`
	RemovedAt           time.Time           `json:"removed_at,omitempty"`
	Expired             bool                `json:"expired,omitempty"`
}

type RecoveryChallenge struct {
	Version                   int                    `json:"version"`
	Nonce                     string                 `json:"nonce"`
	App                       string                 `json:"app"`
	Transaction               string                 `json:"transaction"`
	Service                   string                 `json:"service"`
	Old                       RecoveryIncarnationPin `json:"old"`
	Candidate                 RecoveryIncarnationPin `json:"candidate"`
	DeadlineUnixMillis        int64                  `json:"deadline_unix_ms"`
	OverallDeadlineUnixMillis int64                  `json:"overall_deadline_unix_ms"`
	AlreadyActivated          bool                   `json:"already_activated"`
}

// RecoveryVerifier owns application semantics. Open must durably fence
// producers, establish empty work/provider/file state, and keep the fence safe
// if the process or platform connection disappears. Release may enable
// producers only after the platform has durably recorded positive activation.
type RecoveryVerifier interface {
	Open(context.Context, RecoveryChallenge) (RecoverySession, error)
}

type RecoverySession interface {
	Release(context.Context) error
	Preserve()
}

type RecoveryBackend interface {
	InspectRecovery(context.Context, Instance, Instance) (RecoverySnapshot, error)
	RemoveRecovered(context.Context, Instance, Instance, VerifiedRecovery) error
}

func (e *Engine) Recover(parent context.Context, app string, key []byte, auth RecoveryAuthorization, verifier RecoveryVerifier) (Result, error) {
	if !scopeName(app) || len(key) != 32 || e.Store == nil || e.Backend == nil || e.Router == nil || verifier == nil {
		return Result{}, errors.New("verified recovery requires fixed scoped executors")
	}
	backend, ok := e.Backend.(RecoveryBackend)
	if !ok {
		return Result{}, errors.New("backend does not support verified recovery")
	}
	state, err := e.Store.Load()
	if err != nil || state == nil || state.Pending == nil {
		return Result{}, ErrNoPending
	}
	if state.App != app || state.KeyID != hash(key) {
		return Result{}, errors.New("recovery scope or identity key does not match")
	}
	tx := state.Pending
	old, oldExists := state.Bindings[auth.Service]
	candidate, candidateExists := tx.Candidates[auth.Service]
	if err := validateRecoveryAuthorization(auth, state, old, oldExists, candidate, candidateExists); err != nil {
		return Result{}, err
	}
	if err := validateRecoveryTransaction(state, auth.Service); err != nil {
		return Result{}, err
	}
	if tx.Recovery == nil {
		if tx.Phase != "quiesce" {
			return Result{}, errors.New("verified recovery requires the recorded quiesce boundary")
		}
		now := time.Now().UTC()
		tx.Recovery = &VerifiedRecovery{AuthorizationDigest: auth.Digest, Service: auth.Service, StartedAt: now,
			OverallDeadline: now.Add(auth.Overall), RetirementDeadline: now.Add(auth.Retire)}
		tx.Phase = recoveryPhase
		if err := e.Store.Save(state); err != nil {
			return Result{}, err
		}
	} else if tx.Phase != recoveryPhase || tx.Recovery.AuthorizationDigest != auth.Digest || tx.Recovery.Service != auth.Service {
		return Result{}, errors.New("recovery authorization is stale, changed, or already consumed")
	}
	recovery := tx.Recovery
	result := Result{Generation: tx.ID, Changed: len(tx.Candidates)}
	if err := e.recoveryBudget(state); err != nil {
		return result, err
	}
	{
		op, cancel := recoveryOperation(parent, recovery.OverallDeadline, tx.Limits.Operation)
		preflightErr := e.Backend.Preflight(op, app, tx.Network)
		cancel()
		if preflightErr != nil {
			return result, errors.New("verified recovery runtime, network, or capacity preflight failed")
		}
	}

	var session RecoverySession
	if recovery.ReleasedAt.IsZero() {
		if err := e.confirmRecoveryBoundary(parent, state); err != nil {
			return result, err
		}
		if recovery.ActivatedAt.IsZero() {
			if err := e.confirmRecoveryStandby(parent, tx, candidate); err != nil {
				return result, err
			}
		}
		snapshot, err := e.inspectRecovery(parent, backend, tx, old, candidate, auth)
		if err != nil {
			return result, err
		}
		handshakeDeadline := time.Now().Add(tx.Limits.Operation)
		if recovery.OverallDeadline.Before(handshakeDeadline) {
			handshakeDeadline = recovery.OverallDeadline
		}
		challenge := RecoveryChallenge{Version: 1, Nonce: recoveryNonce(), App: app, Transaction: tx.ID, Service: auth.Service,
			Old: auth.Old, Candidate: auth.Candidate, DeadlineUnixMillis: handshakeDeadline.UnixMilli(), OverallDeadlineUnixMillis: recovery.OverallDeadline.UnixMilli(), AlreadyActivated: !recovery.ActivatedAt.IsZero()}
		sessionContext, sessionCancel := context.WithDeadline(parent, recovery.RetirementDeadline)
		session, err = verifier.Open(sessionContext, challenge)
		if err != nil || session == nil {
			sessionCancel()
			return result, errors.New("application recovery verifier did not establish a durable fenced empty state")
		}
		defer sessionCancel()
		defer session.Preserve()
		// The application acknowledgement is not enough: repeat every platform
		// fact after the fence is established to close inspection races.
		if err := e.confirmRecoveryBoundary(parent, state); err != nil {
			return result, err
		}
		after, err := e.inspectRecovery(parent, backend, tx, old, candidate, auth)
		if err != nil || after != snapshot {
			return result, errors.New("container incarnation changed while application recovery was fenced")
		}
		if recovery.ProvedAt.IsZero() {
			recovery.Old, recovery.Candidate, recovery.ProvedAt = snapshot.Old, snapshot.Candidate, time.Now().UTC()
			if err := e.Store.Save(state); err != nil {
				return result, err
			}
		} else if recovery.Old != snapshot.Old || recovery.Candidate != snapshot.Candidate {
			return result, errors.New("recovery incarnation proof changed on retry")
		}
		if recovery.ActivatedAt.IsZero() {
			if err := e.confirmRecoveryStandby(parent, tx, candidate); err != nil {
				return result, err
			}
			op, cancel := recoveryOperation(parent, recovery.RetirementDeadline, tx.Limits.Operation)
			err := e.Backend.Candidate(op, candidate, "activate")
			cancel()
			if err != nil {
				return result, errors.New("standby activation is unconfirmed; application fence preserved")
			}
			recovery.ActivatedAt = time.Now().UTC()
			if err := e.Store.Save(state); err != nil {
				return result, err
			}
		}
		if err := e.confirmRecoveryBoundary(parent, state); err != nil {
			return result, err
		}
		activatedSnapshot, err := e.inspectRecovery(parent, backend, tx, old, candidate, auth)
		if err != nil || activatedSnapshot.Old != recovery.Old || activatedSnapshot.Candidate != recovery.Candidate {
			return result, errors.New("container or gateway proof changed after standby activation; application fence preserved")
		}
		op, cancel := recoveryOperation(parent, recovery.RetirementDeadline, tx.Limits.Operation)
		err = session.Release(op)
		cancel()
		if err != nil {
			return result, errors.New("application recovery fence release is unconfirmed; retry verified recovery")
		}
		recovery.ReleasedAt = time.Now().UTC()
		if err := e.Store.Save(state); err != nil {
			return result, err
		}
	}

	if err := e.confirmRecoveryBoundary(parent, state); err != nil {
		return result, err
	}
	until := recovery.ActivatedAt.Add(tx.Limits.Stabilize)
	if err := e.checkRecoveryReady(parent, state); err != nil {
		return result, err
	}
	for time.Now().Before(until) {
		if err := e.recoveryBudget(state); err != nil {
			return result, err
		}
		op, cancel := recoveryOperation(parent, recovery.OverallDeadline, tx.Limits.Operation)
		err := e.checkReady(op, tx.Next)
		cancel()
		if err != nil {
			return result, errors.New("replacement health failed during verified recovery; state preserved")
		}
		if err := pauseUntil(parent, recovery.OverallDeadline, tx.Limits.Poll); err != nil {
			return result, err
		}
		if err := e.checkRecoveryReady(parent, state); err != nil {
			return result, err
		}
	}
	if err := e.confirmRecoveryBoundary(parent, state); err != nil {
		return result, err
	}
	for _, service := range slices.Sorted(maps.Keys(state.Bindings)) {
		instance := state.Bindings[service]
		if service == auth.Service {
			continue
		}
		if _, changed := tx.Candidates[service]; !changed {
			continue
		}
		if err := e.retireInstanceRecovery(parent, state, instance); err != nil {
			return result, err
		}
	}
	if recovery.RemovedAt.IsZero() {
		if err := e.confirmRecoveryBoundary(parent, state); err != nil {
			return result, err
		}
		op, cancel := recoveryOperation(parent, recovery.RetirementDeadline, tx.Limits.Operation)
		err := backend.RemoveRecovered(op, old, candidate, *recovery)
		cancel()
		if err != nil {
			return result, errors.New("failed incarnation recovery cleanup was refused; state preserved")
		}
		recovery.RemovedAt = time.Now().UTC()
		if err := e.Store.Save(state); err != nil {
			return result, err
		}
	}
	if err := e.confirmRecoveryBoundary(parent, state); err != nil {
		return result, err
	}
	op, cancel := recoveryOperation(parent, recovery.RetirementDeadline, tx.Limits.Operation)
	err = backend.RemoveRecovered(op, old, candidate, *recovery)
	cancel()
	if err != nil {
		return result, errors.New("final recovered incarnation revalidation failed; state preserved")
	}
	if err := e.recoveryBudget(state); err != nil {
		return result, err
	}
	oldGeneration := tx.Before.Generation
	result.Recovered = true
	state.Active, state.Bindings, state.Routes, state.Pending, state.Last = tx.Source, tx.Next, tx.After, nil, result
	if err := e.Store.Save(state); err != nil {
		return result, err
	}
	op, cancel = recoveryOperation(parent, recovery.OverallDeadline, tx.Limits.Operation)
	_ = e.Router.Forget(op, oldGeneration)
	cancel()
	return result, nil
}

func validateRecoveryTransaction(state *State, target string) error {
	tx := state.Pending
	if tx == nil || tx.SwitchStartedAt.IsZero() || tx.SwitchedAt.Before(tx.SwitchStartedAt) || tx.Before.Generation == "" || tx.After.Generation != tx.ID || tx.After.Parent != tx.Before.Generation || tx.Candidates[target].Mode != "worker" {
		return errors.New("pending transaction is not a complete post-switch worker handoff")
	}
	for service, candidate := range tx.Candidates {
		old, replacing := state.Bindings[service]
		if !replacing {
			continue
		}
		proof := tx.Retirements[old.Name]
		if service == target {
			if proof.Stage != "" {
				return errors.New("recovery target has an incompatible normal lifecycle proof")
			}
			continue
		}
		if candidate.Mode == "worker" {
			return errors.New("one authorization cannot recover or activate multiple changed workers")
		}
		if proof.ID == "" || proof.StartedAt == "" || proof.Absent || proof.NotStarted || !slices.Contains([]string{"quiesce", "seal", "drain", "stop", "remove"}, proof.Stage) {
			return errors.New("another changed service lacks its normal incarnation-bound quiesce proof")
		}
	}
	return nil
}

func (e *Engine) checkRecoveryReady(parent context.Context, state *State) error {
	if err := e.recoveryBudget(state); err != nil {
		return err
	}
	tx := state.Pending
	op, cancel := recoveryOperation(parent, tx.Recovery.OverallDeadline, tx.Limits.Operation)
	err := e.checkReady(op, tx.Next)
	cancel()
	if err != nil {
		return errors.New("replacement health failed during verified recovery; state preserved")
	}
	return nil
}

func (e *Engine) confirmRecoveryStandby(parent context.Context, tx *Transaction, candidate Instance) error {
	op, cancel := recoveryOperation(parent, tx.Recovery.RetirementDeadline, tx.Limits.Operation)
	err := e.Backend.Candidate(op, candidate, "ready")
	cancel()
	if err != nil {
		return errors.New("replacement is not positively confirmed as the exact standby incarnation")
	}
	return nil
}

func validateRecoveryAuthorization(auth RecoveryAuthorization, state *State, old Instance, oldExists bool, candidate Instance, candidateExists bool) error {
	tx := state.Pending
	if auth.Version != 1 || auth.App != state.App || auth.Transaction != tx.ID || !scopeName(auth.Service) || !oldExists || !candidateExists ||
		!lowerHex(auth.Digest, 64) || !filepath.IsAbs(auth.VerifierPath) || !lowerHex(auth.VerifierSHA256, 64) || auth.UID == 0 || auth.GID == 0 ||
		auth.Overall <= 0 || auth.Overall > 8*time.Minute || auth.Retire <= tx.Limits.Stabilize || auth.Retire > 5*time.Minute ||
		old.Mode != "worker" || candidate.Mode != "worker" || old.Service != auth.Service || candidate.Service != auth.Service || !reflect.DeepEqual(tx.Next[auth.Service], candidate) || old.Generation != auth.Old.Generation || old.Identity != auth.Old.Identity ||
		candidate.Generation != auth.Candidate.Generation || candidate.Identity != auth.Candidate.Identity || auth.Old.ExitCode == 0 ||
		auth.Old.ID == "" || auth.Old.StartedAt == "" || auth.Old.FinishedAt == "" || auth.Candidate.ID == "" || auth.Candidate.StartedAt == "" {
		return errors.New("recovery authorization does not bind the exact pending failed-worker transition")
	}
	if proof := tx.Retirements[old.Name]; proof.Stage != "" {
		return errors.New("normal lifecycle proof already exists for the recovery target")
	}
	return nil
}

func (e *Engine) inspectRecovery(parent context.Context, backend RecoveryBackend, tx *Transaction, old, candidate Instance, auth RecoveryAuthorization) (RecoverySnapshot, error) {
	op, cancel := recoveryOperation(parent, tx.Recovery.OverallDeadline, tx.Limits.Operation)
	snapshot, err := backend.InspectRecovery(op, old, candidate)
	cancel()
	if err != nil || snapshot.Old.ID != auth.Old.ID || snapshot.Old.StartedAt != auth.Old.StartedAt || snapshot.Old.FinishedAt != auth.Old.FinishedAt || snapshot.Old.ExitCode != auth.Old.ExitCode || snapshot.Old.Running ||
		snapshot.Candidate.ID != auth.Candidate.ID || snapshot.Candidate.StartedAt != auth.Candidate.StartedAt || !snapshot.Candidate.Running {
		return RecoverySnapshot{}, errors.New("recovery container identity, chronology, or health is unconfirmed")
	}
	finished, parseErr := time.Parse(time.RFC3339Nano, snapshot.Old.FinishedAt)
	if parseErr != nil || !finished.Before(tx.SwitchStartedAt) {
		return RecoverySnapshot{}, errors.New("old incarnation did not positively exit before route switching")
	}
	return snapshot, nil
}

func (e *Engine) confirmRecoveryBoundary(parent context.Context, state *State) error {
	tx := state.Pending
	if err := e.recoveryBudget(state); err != nil {
		return err
	}
	op, cancel := recoveryOperation(parent, tx.Recovery.OverallDeadline, tx.Limits.Operation)
	current, epoch, err := e.Router.Current(op)
	cancel()
	if err != nil || epoch != tx.Epoch || !reflect.DeepEqual(current, tx.After) {
		return errors.New("gateway route or epoch changed; verified recovery refused")
	}
	op, cancel = recoveryOperation(parent, tx.Recovery.RetirementDeadline, tx.Limits.Operation)
	status, err := e.Router.Status(op, tx.Before.Generation)
	cancel()
	if err != nil || status.Epoch != tx.Epoch || status.Active || status.Requests != 0 {
		return errors.New("old generation is active, busy, or unconfirmed; verified recovery refused")
	}
	op, cancel = recoveryOperation(parent, tx.Recovery.OverallDeadline, tx.Limits.Operation)
	active, err := e.Router.Status(op, tx.After.Generation)
	cancel()
	if err != nil || active.Epoch != tx.Epoch || !active.Active {
		return errors.New("new generation gateway accounting is inactive or unconfirmed; verified recovery refused")
	}
	return nil
}

func (e *Engine) recoveryBudget(state *State) error {
	r := state.Pending.Recovery
	now := time.Now()
	if r.Expired || !now.Before(r.OverallDeadline) || !now.Before(r.RetirementDeadline) {
		r.Expired = true
		if e.Store != nil && state.App != "" {
			if err := e.Store.Save(state); err != nil {
				return err
			}
		}
		return ErrRecoveryBudget
	}
	return nil
}

func recoveryOperation(parent context.Context, absolute time.Time, operation time.Duration) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(operation)
	if absolute.Before(deadline) {
		deadline = absolute
	}
	return context.WithDeadline(parent, deadline)
}

func pauseUntil(parent context.Context, deadline time.Time, duration time.Duration) error {
	ctx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	return pause(ctx, duration)
}

func recoveryNonce() string { return rand.Text() }

func (e *Engine) retireInstanceRecovery(parent context.Context, state *State, instance Instance) error {
	tx := state.Pending
	for {
		if err := e.recoveryBudget(state); err != nil {
			return err
		}
		proof := tx.Retirements[instance.Name]
		var action string
		switch proof.Stage {
		case "quiesce":
			action = "seal"
		case "seal":
			action = "drain"
		case "drain":
			action = "stop"
		case "stop":
			action = "remove"
		case "remove":
			return nil
		default:
			return errors.New("non-target service lacks normal quiesce proof")
		}
		if err := e.confirmRecoveryBoundary(parent, state); err != nil {
			return err
		}
		op, cancel := recoveryOperation(parent, tx.Recovery.RetirementDeadline, tx.Limits.Operation)
		next, err := e.Backend.Lifecycle(op, instance, action, proof)
		cancel()
		if err != nil || next.Stage != action || next.ID != proof.ID || next.StartedAt != proof.StartedAt || next.Absent != proof.Absent || next.NotStarted != proof.NotStarted {
			return errors.New("normal retirement during verified recovery was not positively acknowledged")
		}
		tx.Retirements[instance.Name] = next
		if err := e.Store.Save(state); err != nil {
			return err
		}
	}
}
