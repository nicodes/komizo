package rollout

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/nicodes/komizo/internal/gateway"
	"github.com/nicodes/komizo/internal/release"
)

type Limits struct {
	Ready     time.Duration `json:"ready"`
	Stabilize time.Duration `json:"stabilize"`
	Retire    time.Duration `json:"retire"`
	Operation time.Duration `json:"operation"`
	Poll      time.Duration `json:"poll"`
}

type Instance struct {
	Lifecycle  *release.Lifecycle `json:"lifecycle,omitempty"`
	Name       string             `json:"name"`
	App        string             `json:"app"`
	Service    string             `json:"service"`
	Generation string             `json:"generation"`
	Identity   string             `json:"identity"`
	Port       int                `json:"port"`
	ReadyPath  string             `json:"ready_path"`
	ReadyHost  string             `json:"ready_host,omitempty"`
}

type State struct {
	Version  int                 `json:"version"`
	App      string              `json:"app"`
	KeyID    string              `json:"key_id"`
	Active   json.RawMessage     `json:"active"`
	Bindings map[string]Instance `json:"bindings"`
	Routes   gateway.Config      `json:"routes"`
	Pending  *Transaction        `json:"pending,omitempty"`
	Last     Result              `json:"last_result"`
}

type Transaction struct {
	Retirements        map[string]Retirement `json:"retirements,omitempty"`
	ID                 string                `json:"id"`
	Goal               string                `json:"goal"`
	Source             json.RawMessage       `json:"source"`
	Phase              string                `json:"phase"`
	Limits             Limits                `json:"limits"`
	Network            string                `json:"network"`
	Epoch              string                `json:"epoch"`
	Before             gateway.Config        `json:"before"`
	After              gateway.Config        `json:"after"`
	Candidates         map[string]Instance   `json:"candidates"`
	Next               map[string]Instance   `json:"next"`
	SwitchedAt         time.Time             `json:"switched_at,omitempty"`
	SwitchStartedAt    time.Time             `json:"switch_started_at,omitempty"`
	RetirementExceeded bool                  `json:"retirement_exceeded,omitempty"`
}

// Backend methods must be idempotent and verify instance ownership before any
// destructive operation. They may not infer permission from a container name.
type Backend interface {
	Preflight(context.Context, string, string) error
	Prepare(context.Context, Instance, []byte) error
	Ready(context.Context, Instance) error
	Remove(context.Context, Instance) error
	Lifecycle(context.Context, Instance, string, Retirement) (Retirement, error)
}

type RouteController interface {
	Current(context.Context) (gateway.Config, string, error)
	Apply(context.Context, gateway.Config) (string, error)
	Status(context.Context, string) (gateway.Status, error)
	Forget(context.Context, string) error
}

type Engine struct {
	Store   *Store
	Backend Backend
	Router  RouteController
}

type Result struct {
	Generation         string `json:"generation"`
	Changed            int    `json:"changed"`
	NoOp               bool   `json:"no_op"`
	RetirementExceeded bool   `json:"retirement_exceeded,omitempty"`
	Aborted            bool   `json:"aborted,omitempty"`
}

var ErrRetirementBudget = errors.New("retirement budget exceeded; transaction incomplete and instances preserved")

// Abort cancels only a transaction that has never attempted a route switch.
// Post-switch recovery must resume; it must not rewind data or delete a possibly
// serving candidate just because an operator requests another release.
func (e *Engine) Abort(ctx context.Context, app string, key []byte, operation time.Duration) (Result, error) {
	if _, ok := ctx.Deadline(); !ok || operation <= 0 || e.Store == nil || e.Backend == nil || e.Router == nil || len(key) != 32 {
		return Result{}, errors.New("abort requires a bounded scoped executor")
	}
	state, err := e.Store.Load()
	if err != nil || state == nil {
		return Result{}, errors.New("no valid rollout journal to abort")
	}
	if state.App != app || state.KeyID != hash(key) {
		return Result{}, errors.New("abort scope or identity key does not match")
	}
	if state.Pending == nil {
		return Result{Generation: state.Routes.Generation, NoOp: true}, nil
	}
	tx := state.Pending
	if tx.Phase != "prepare" && tx.Phase != "ready" && tx.Phase != "abort" {
		return Result{}, errors.New("route switch may have occurred; resume instead of aborting")
	}
	op, cancel := context.WithTimeout(ctx, operation)
	current, _, err := e.Router.Current(op)
	cancel()
	if err != nil || !reflect.DeepEqual(current, tx.Before) {
		return Result{}, errors.New("previous routing is not confirmed; abort refused")
	}
	if err := e.phase(state, "abort"); err != nil {
		return Result{}, err
	}
	for _, name := range slices.Sorted(maps.Keys(tx.Candidates)) {
		op, cancel := context.WithTimeout(ctx, operation)
		err := e.retireInstance(op, state, tx.Candidates[name], true, false)
		cancel()
		if err != nil {
			return Result{}, errors.New("abort cleanup interrupted; repeat abort")
		}
	}
	result := Result{Generation: tx.ID, Aborted: true}
	state.Pending, state.Last = nil, result
	if err := e.Store.Save(state); err != nil {
		return Result{}, err
	}
	return result, nil
}

// Run requires an already acquired private Store and an overall deadline.
// It never falls back to in-place deployment or restores a database snapshot.
func (e *Engine) Run(ctx context.Context, app, network string, source, key []byte, limits Limits) (result Result, runErr error) {
	if _, bounded := ctx.Deadline(); !bounded || limits.Ready <= 0 || limits.Stabilize <= 0 || limits.Retire <= limits.Stabilize || limits.Operation <= 0 || limits.Poll <= 0 {
		return Result{}, errors.New("rollout requires an overall deadline and explicit positive operation budgets")
	}
	if !scopeName(app) || !scopeName(network) || e.Store == nil || e.Backend == nil || e.Router == nil {
		return Result{}, errors.New("invalid rollout scope or executor")
	}
	model, err := release.Resolve(source, key)
	if err != nil {
		return Result{}, err
	}
	if err := model.CheckApp(app); err != nil {
		return Result{}, err
	}
	state, err := e.Store.Load()
	if err != nil {
		return Result{}, err
	}
	keyID := hash(key)
	if state != nil && (state.App != app || state.KeyID != keyID) {
		return Result{}, errors.New("journal belongs to a different application or identity key")
	}
	goalData, _ := json.Marshal(struct {
		Inventory release.Inventory
		Network   string
		Limits    Limits
	}{model.Inventory, network, limits})
	goal := hash(goalData)
	if state != nil && state.Pending != nil {
		if state.Pending.Goal != goal || state.Pending.Network != network || state.Pending.Limits != limits {
			return Result{}, errors.New("resume the pending rollout before submitting a different release or policy")
		}
		op, cancel := context.WithTimeout(ctx, limits.Operation)
		preflightErr := e.Backend.Preflight(op, app, network)
		cancel()
		if preflightErr != nil {
			return Result{}, errors.New("pending rollout runtime/network preflight failed")
		}
		// Persisted source is authoritative on resume; no artifact/path can be
		// swapped underneath a previously authorized transition.
		source = state.Pending.Source
		model, err = release.Resolve(source, key)
		if err != nil {
			return Result{}, errors.New("pending rollout source is invalid")
		}
		if err := model.CheckApp(app); err != nil {
			return Result{}, err
		}
	} else {
		state, err = e.begin(ctx, state, app, network, keyID, goal, source, key, model, limits)
		if err != nil {
			return Result{}, err
		}
		if state.Pending == nil {
			return Result{Generation: state.Routes.Generation, NoOp: true}, nil
		}
	}
	tx := state.Pending
	result = Result{Generation: tx.ID, Changed: len(tx.Candidates), RetirementExceeded: tx.RetirementExceeded}
	defer func() { result.RetirementExceeded = tx.RetirementExceeded }()
	for {
		if err := ctx.Err(); err != nil {
			return result, errors.New("rollout interrupted; resume the recorded transaction")
		}
		switch tx.Phase {
		case "prepare":
			for _, service := range slices.Sorted(maps.Keys(tx.Candidates)) {
				instance := tx.Candidates[service]
				body, err := model.CandidateCompose(service, instance.Name, app, network, labels(instance))
				if err != nil {
					return result, err
				}
				op, cancel := context.WithTimeout(ctx, limits.Operation)
				err = e.Backend.Prepare(op, instance, body)
				cancel()
				if err != nil {
					return result, errors.New("candidate preparation failed; transaction retained for resume")
				}
			}
			if err := e.phase(state, "ready"); err != nil {
				return result, err
			}
		case "ready":
			ready, cancel := context.WithTimeout(ctx, limits.Ready)
			err := e.waitReady(ready, tx.Candidates, limits.Poll)
			cancel()
			if err != nil {
				if err := e.phase(state, "abort"); err != nil {
					return result, err
				}
				continue
			}
			if err := e.phase(state, "switch"); err != nil {
				return result, err
			}
		case "switch":
			if tx.SwitchStartedAt.IsZero() {
				tx.SwitchStartedAt = time.Now().UTC()
				if err := e.Store.Save(state); err != nil {
					return result, err
				}
			}
			op, cancel := context.WithTimeout(ctx, limits.Operation)
			current, epoch, err := e.Router.Current(op)
			cancel()
			if err != nil || epoch != tx.Epoch || (!reflect.DeepEqual(current, tx.Before) && !reflect.DeepEqual(current, tx.After)) {
				return result, errors.New("gateway state or epoch changed; refusing an unverified switch")
			}
			// A gateway process restarted during this transaction must load this
			// durable desired state; epoch mismatch still forbids guessing drain.
			routes, _ := json.Marshal(tx.After)
			if err := e.Store.PublishGateway(routes); err != nil {
				return result, err
			}
			op, cancel = context.WithTimeout(ctx, limits.Operation)
			epoch, err = e.Router.Apply(op, tx.After)
			cancel()
			if err != nil || epoch != tx.Epoch {
				return result, errors.New("gateway switch outcome is unconfirmed; no containers were retired")
			}
			tx.SwitchedAt = time.Now().UTC()
			if err := e.phase(state, "quiesce"); err != nil {
				return result, err
			}
		case "quiesce":
			if err := e.retirementBudget(state); err != nil {
				return result, err
			}
			if err := e.confirmRoutes(ctx, tx); err != nil {
				return result, err
			}
			for _, service := range slices.Sorted(maps.Keys(tx.Candidates)) {
				if old, exists := state.Bindings[service]; exists {
					op, cancel := context.WithDeadline(ctx, tx.SwitchStartedAt.Add(limits.Retire))
					err := e.retireInstance(op, state, old, false, true)
					cancel()
					if err != nil {
						_ = e.retirementBudget(state)
						return result, err
					}
				}
			}
			if err := e.phase(state, "stabilize"); err != nil {
				return result, err
			}
		case "stabilize":
			until := tx.SwitchedAt.Add(limits.Stabilize)
			for time.Now().Before(until) {
				op, cancel := context.WithTimeout(ctx, limits.Operation)
				err := e.checkReady(op, tx.Next)
				cancel()
				if err != nil {
					return result, errors.New("replacement health failed; no automatic data or application rollback performed")
				}
				if err := pause(ctx, limits.Poll); err != nil {
					return result, err
				}
			}
			if err := e.phase(state, "drain"); err != nil {
				return result, err
			}
		case "drain":
			if err := e.retirementBudget(state); err != nil {
				return result, err
			}
			deadline := tx.SwitchStartedAt.Add(limits.Retire)
			for {
				op, cancel := context.WithTimeout(ctx, limits.Operation)
				status, err := e.Router.Status(op, tx.Before.Generation)
				cancel()
				if err != nil || status.Epoch != tx.Epoch || status.Active {
					return result, errors.New("old generation drain cannot be established; refusing destructive cleanup")
				}
				if status.Requests == 0 {
					break
				}
				if !time.Now().Before(deadline) {
					tx.RetirementExceeded, result.RetirementExceeded = true, true
					if err := e.Store.Save(state); err != nil {
						return result, err
					}
					return result, errors.New("retirement budget exceeded by live requests; app resumption or operator recovery required")
				}
				if err := pause(ctx, limits.Poll); err != nil {
					return result, err
				}
			}
			if err := e.phase(state, "retire"); err != nil {
				return result, err
			}
		case "retire":
			if err := e.retirementBudget(state); err != nil {
				return result, err
			}
			op, cancel := context.WithTimeout(ctx, limits.Operation)
			current, epoch, err := e.Router.Current(op)
			cancel()
			if err != nil || epoch != tx.Epoch || !reflect.DeepEqual(current, tx.After) {
				return result, errors.New("routing changed before retirement; no containers were removed")
			}
			// This checkpoint records positive drain evidence. An interruption
			// midway through removals resumes idempotently, never reopens old routes.
			for _, service := range slices.Sorted(maps.Keys(tx.Candidates)) {
				if old, exists := state.Bindings[service]; exists {
					op, cancel := context.WithDeadline(ctx, tx.SwitchStartedAt.Add(limits.Retire))
					err := e.retireInstance(op, state, old, false, false)
					cancel()
					if err != nil {
						_ = e.retirementBudget(state)
						return result, errors.New("old instance cleanup failed; resume recorded retirement")
					}
				}
			}
			if err := e.phase(state, "commit"); err != nil {
				return result, err
			}
		case "commit":
			if err := e.retirementBudget(state); err != nil {
				return result, err
			}
			oldGeneration := tx.Before.Generation
			state.Active, state.Bindings, state.Routes, state.Pending = tx.Source, tx.Next, tx.After, nil
			state.Last = result
			if err := e.Store.Save(state); err != nil {
				return result, err
			}
			op, cancel := context.WithTimeout(ctx, limits.Operation)
			_ = e.Router.Forget(op, oldGeneration) // accounting GC only, never container deletion
			cancel()
			if result.RetirementExceeded {
				return result, ErrRetirementBudget
			}
			return result, nil
		case "abort":
			// Candidates never received gateway traffic, but may have background work.
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), limits.Operation)
			for _, service := range slices.Sorted(maps.Keys(tx.Candidates)) {
				if err := e.retireInstance(cleanup, state, tx.Candidates[service], true, false); err != nil {
					cancel()
					return result, errors.New("failed candidate cleanup incomplete; resume abort")
				}
			}
			cancel()
			state.Pending = nil
			if err := e.Store.Save(state); err != nil {
				return result, err
			}
			return result, errors.New("candidate readiness failed; previous release kept active")
		default:
			return result, errors.New("unknown rollout journal phase")
		}
	}
}

func (e *Engine) begin(ctx context.Context, state *State, app, network, keyID, goal string, source, key []byte, model *release.Model, limits Limits) (*State, error) {
	old := &release.Model{Inventory: release.Inventory{}, Policies: map[string]release.Policy{}}
	if state != nil {
		var err error
		old, err = release.Resolve(state.Active, key)
		if err != nil || state.Bindings == nil {
			return nil, errors.New("active journal model is invalid")
		}
	}
	op, cancel := context.WithTimeout(ctx, limits.Operation)
	if err := e.Backend.Preflight(op, app, network); err != nil {
		cancel()
		return nil, errors.New("rollout runtime/network preflight failed")
	}
	current, epoch, err := e.Router.Current(op)
	cancel()
	if err != nil {
		return nil, errors.New("cannot establish current gateway state")
	}
	if current.App != app {
		return nil, errors.New("gateway belongs to another application")
	}
	if state == nil {
		if len(current.Routes) != 0 {
			return nil, errors.New("gateway already routes traffic; explicit legacy conversion is required")
		}
		state = &State{Version: 1, App: app, KeyID: keyID,
			Active:   json.RawMessage(`{"services":{},"x-komizo":{"version":1,"services":{}}}`),
			Bindings: map[string]Instance{}, Routes: current}
	} else if !reflect.DeepEqual(current, state.Routes) {
		return nil, errors.New("gateway differs from the committed journal; reconcile before rollout")
	}
	changes, err := release.Compare(old.Inventory, model.Inventory)
	if err != nil {
		return nil, err
	}
	tx := &Transaction{ID: strings.ToLower(rand.Text()), Goal: goal, Source: slices.Clone(source), Phase: "prepare",
		Limits: limits, Network: network, Epoch: epoch, Before: current, Candidates: map[string]Instance{}, Next: maps.Clone(state.Bindings)}
	for _, change := range changes {
		if change.Kind == release.Unchanged {
			continue
		}
		if change.Kind == release.Removed {
			return nil, fmt.Errorf("service %q removal requires a separate lifecycle operation", change.Service)
		}
		policy := model.Policies[change.Service]
		if err := policy.Lifecycle.Validate(); err != nil {
			return nil, err
		}
		if previous, exists := state.Bindings[change.Service]; exists {
			if err := previous.Lifecycle.Validate(); err != nil {
				return nil, errors.New("active instance lacks lifecycle capability; explicit operator conversion required")
			}
		}
		if policy.Mode != "http" || (change.Kind == release.Changed && old.Policies[change.Service].Mode != "http") {
			return nil, fmt.Errorf("service %q requires its persistent/job lifecycle integration", change.Service)
		}
		fingerprint, _ := json.Marshal(model.Inventory[change.Service])
		instance := Instance{Name: "kmz-" + hash([]byte(app + "\x00" + change.Service + "\x00" + tx.ID))[:40],
			App: app, Service: change.Service, Generation: tx.ID, Identity: hash(fingerprint), Port: policy.Port, ReadyPath: policy.ReadyPath, ReadyHost: policy.ReadyHost, Lifecycle: policy.Lifecycle}
		// Validate every candidate document before persisting intent or starting
		// any container; a later unsupported service must not leave earlier ones.
		if _, err := model.CandidateCompose(change.Service, instance.Name, app, network, labels(instance)); err != nil {
			return nil, err
		}
		tx.Candidates[change.Service], tx.Next[change.Service] = instance, instance
	}
	if len(tx.Candidates) == 0 {
		op, cancel := context.WithTimeout(ctx, limits.Operation)
		err := e.checkReady(op, state.Bindings)
		cancel()
		if err != nil {
			return nil, errors.New("unchanged services are not ready; no-op is not a repair action")
		}
		state.Active = slices.Clone(source)
		if err := e.Store.Save(state); err != nil {
			return nil, err
		}
		return state, nil
	}
	after := gateway.Config{App: app, Generation: tx.ID, Parent: current.Generation, Routes: []gateway.Route{}, TrustedProxies: slices.Clone(current.TrustedProxies)}
	for _, service := range slices.Sorted(maps.Keys(model.Policies)) {
		policy := model.Policies[service]
		if policy.Mode != "http" {
			continue
		}
		instance, exists := tx.Next[service]
		if !exists || len(policy.Hosts) == 0 {
			return nil, errors.New("HTTP execution needs explicit host routes and a binding for every service")
		}
		after.Routes = append(after.Routes, gateway.Route{Service: service, Hosts: slices.Clone(policy.Hosts),
			Target: fmt.Sprintf("http://%s:%d", instance.Name, instance.Port)})
	}
	encoded, _ := json.Marshal(after)
	tx.After, err = gateway.Decode(strings.NewReader(string(encoded)))
	if err != nil {
		return nil, err
	}
	state.Pending = tx
	if err := e.Store.Save(state); err != nil {
		return nil, err
	}
	return state, nil
}

func (e *Engine) phase(state *State, phase string) error {
	state.Pending.Phase = phase
	return e.Store.Save(state)
}

func (e *Engine) checkReady(ctx context.Context, instances map[string]Instance) error {
	for _, name := range slices.Sorted(maps.Keys(instances)) {
		if err := e.Backend.Ready(ctx, instances[name]); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) waitReady(ctx context.Context, instances map[string]Instance, interval time.Duration) error {
	for {
		if err := e.checkReady(ctx, instances); err == nil {
			return nil
		}
		if err := pause(ctx, interval); err != nil {
			return err
		}
	}
}

func pause(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return errors.New("rollout operation cancelled or timed out")
	case <-timer.C:
		return nil
	}
}

func hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func scopeName(value string) bool {
	if value == "" || len(value) > 64 || !(value[0] >= 'a' && value[0] <= 'z' || value[0] >= '0' && value[0] <= '9') {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func labels(instance Instance) map[string]string {
	return map[string]string{"io.komizo.app": instance.App, "io.komizo.service": instance.Service,
		"io.komizo.generation": instance.Generation, "io.komizo.identity": instance.Identity}
}
