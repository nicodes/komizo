package rollout

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/internal/gateway"
)

type memoryBackend struct {
	instances        map[string]Instance
	created, removed []string
	events           []string
	failReady        bool
	failCapacity     bool
	failRemoveOnce   bool
	failPrepareOnce  bool
	lifecycleCalls   []string
	failLifecycle    string
	lifecycleHook    func(context.Context, string) error
}

func (b *memoryBackend) Lifecycle(ctx context.Context, i Instance, action string, p Retirement) (Retirement, error) {
	b.lifecycleCalls = append(b.lifecycleCalls, action+":"+i.Name)
	if b.lifecycleHook != nil {
		if err := b.lifecycleHook(ctx, action); err != nil {
			return p, err
		}
	}
	if action == b.failLifecycle {
		return p, errors.New("application refused lifecycle")
	}
	if action == "remove" {
		if err := b.Remove(ctx, i); err != nil {
			return p, err
		}
	}
	if action == "abort-quiesce" {
		action = "quiesce"
	}
	return Retirement{ID: i.Name, StartedAt: "boot", Stage: action}, nil
}

func (b *memoryBackend) Preflight(context.Context, string, string) error { return nil }
func (b *memoryBackend) Stage(_ context.Context, i Instance, _ []byte) error {
	b.events = append(b.events, "stage:"+i.Service)
	if b.failPrepareOnce {
		b.failPrepareOnce = false
		return errors.New("simulated preparation interruption")
	}
	return nil
}
func (b *memoryBackend) Capacity(context.Context) error {
	b.events = append(b.events, "capacity")
	if b.failCapacity {
		return errors.New("simulated post-pull floor refusal")
	}
	return nil
}
func (b *memoryBackend) Prepare(_ context.Context, i Instance, _ []byte) error {
	b.events = append(b.events, "start:"+i.Service)
	if _, exists := b.instances[i.Name]; !exists {
		b.created = append(b.created, i.Name)
		b.instances[i.Name] = i
	}
	return nil
}
func (b *memoryBackend) Ready(_ context.Context, i Instance) error {
	if b.failReady {
		return errors.New("not ready")
	}
	if _, exists := b.instances[i.Name]; !exists {
		return errors.New("missing instance")
	}
	if i.Mode == "worker" {
		b.lifecycleCalls = append(b.lifecycleCalls, "ready:"+i.Name)
	}
	return nil
}
func (b *memoryBackend) Candidate(_ context.Context, i Instance, action string) error {
	b.lifecycleCalls = append(b.lifecycleCalls, action+":"+i.Name)
	if b.failLifecycle == action {
		return errors.New("application refused candidate lifecycle")
	}
	return nil
}
func (b *memoryBackend) Remove(_ context.Context, i Instance) error {
	if b.failRemoveOnce {
		b.failRemoveOnce = false
		return errors.New("simulated cleanup interruption")
	}
	if _, exists := b.instances[i.Name]; exists {
		b.removed = append(b.removed, i.Name)
		delete(b.instances, i.Name)
	}
	return nil
}

type memoryRouter struct {
	g            *gateway.Gateway
	lostReply    bool
	blocked      string
	unknownDrain bool
}

func (r *memoryRouter) Current(context.Context) (gateway.Config, string, error) {
	c, epoch := r.g.Current()
	return c, epoch, nil
}
func (r *memoryRouter) Apply(_ context.Context, c gateway.Config) (string, error) {
	if err := r.g.Swap(c); err != nil {
		return "", err
	}
	if r.lostReply {
		r.lostReply = false
		return "", errors.New("response lost after switch")
	}
	_, epoch := r.g.Current()
	return epoch, nil
}
func (r *memoryRouter) Status(_ context.Context, id string) (gateway.Status, error) {
	if r.unknownDrain {
		return gateway.Status{}, errors.New("lost gateway state")
	}
	status, err := r.g.Status(id)
	if id == r.blocked {
		status.Requests = 1
	}
	return status, err
}
func (r *memoryRouter) Forget(_ context.Context, id string) error { return r.g.Forget(id) }

func sourceModel(ui string) []byte {
	model := map[string]any{
		"name": "app",
		"services": map[string]any{
			"api": map[string]any{"image": "example/api@sha256:" + strings.Repeat("a", 64), "networks": map[string]any{"private": nil}},
			"ui":  map[string]any{"image": "example/ui@sha256:" + strings.Repeat(ui, 64), "networks": map[string]any{"private": nil}},
		},
		"networks": map[string]any{"private": map[string]any{"internal": true, "name": "app-private"}},
		"x-komizo": map[string]any{"version": 1, "services": map[string]any{
			"api": map[string]any{"mode": "request", "port": 8080, "ready_path": "/readyz", "candidate_safe": true, "hosts": []string{"api.test"}},
			"ui":  map[string]any{"mode": "static", "port": 8080, "ready_path": "/readyz", "candidate_safe": true, "hosts": []string{"app.test"}},
		}},
	}
	for _, policy := range model["x-komizo"].(map[string]any)["services"].(map[string]any) {
		policy.(map[string]any)["lifecycle"] = map[string]any{"version": 1, "command": []string{"/fixture", "lifecycle"}}
	}
	data, _ := json.Marshal(model)
	return data
}

func nonRequestModel(mode, digest string) []byte {
	policy := map[string]any{"mode": mode}
	if mode == "worker" {
		policy["candidate_safe"] = true
		policy["lifecycle"] = map[string]any{"version": 1, "command": []string{"/fixture", "lifecycle"}}
	}
	if mode == "one-shot" {
		policy["candidate_safe"] = true
	}
	model := map[string]any{
		"name":     "app",
		"services": map[string]any{"task": map[string]any{"image": "example/task@sha256:" + strings.Repeat(digest, 64), "networks": map[string]any{"private": nil}}},
		"networks": map[string]any{"private": map[string]any{"internal": true, "name": "app-private"}},
		"x-komizo": map[string]any{"version": 1, "services": map[string]any{"task": policy}},
	}
	data, _ := json.Marshal(model)
	return data
}

func newEngine(t *testing.T) (*Engine, *memoryBackend, *memoryRouter, []byte, Limits) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	store, err := OpenStore(ctx, filepath.Join(t.TempDir(), "private"), time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	g, err := gateway.New(gateway.Config{App: "app", Generation: "bootstrap", Routes: []gateway.Route{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := &memoryBackend{instances: map[string]Instance{}}
	r := &memoryRouter{g: g}
	limits := Limits{Ready: 10 * time.Millisecond, Stabilize: time.Millisecond, Retire: time.Second, Operation: time.Second, Poll: time.Millisecond}
	return &Engine{store, b, r}, b, r, bytes.Repeat([]byte{1}, 32), limits
}

func runEngine(t *testing.T, engine *Engine, source, key []byte, limits Limits) (Result, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return engine.Run(ctx, "app", "app-private", source, key, limits)
}

func TestEngineInitialNoOpAndSelectiveRetirement(t *testing.T) {
	e, backend, _, key, limits := newEngine(t)
	first, err := runEngine(t, e, sourceModel("b"), key, limits)
	if err != nil || first.NoOp || first.Changed != 2 {
		t.Fatalf("initial rollout: %+v, %v", first, err)
	}
	state, err := e.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	api, ui := state.Bindings["api"].Name, state.Bindings["ui"].Name
	noOp, err := runEngine(t, e, sourceModel("b"), key, limits)
	if err != nil || !noOp.NoOp || len(backend.created) != 2 {
		t.Fatalf("no-op: %+v, %v", noOp, err)
	}
	second, err := runEngine(t, e, sourceModel("c"), key, limits)
	if err != nil || second.Changed != 1 {
		t.Fatalf("UI rollout: %+v, %v", second, err)
	}
	state, err = e.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.Pending != nil || state.Bindings["api"].Name != api || state.Bindings["ui"].Name == ui {
		t.Fatal("unchanged API replaced or rollout not committed")
	}
	if len(backend.instances) != 2 || len(backend.removed) != 1 || backend.removed[0] != ui {
		t.Fatalf("unexpected retirement: %+v", backend.removed)
	}
	info, err := os.Stat(e.Store.Path("state.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("journal is not private")
	}
}

func TestEngineStagesEveryImageAndRechecksCapacityBeforeAnyCandidate(t *testing.T) {
	e, backend, _, key, limits := newEngine(t)
	first, err := runEngine(t, e, sourceModel("b"), key, limits)
	if err != nil {
		t.Fatal(err)
	}
	wantInitial := []string{"stage:api", "stage:ui", "capacity", "start:api", "start:ui"}
	if !slices.Equal(backend.events, wantInitial) {
		t.Fatalf("initial ordering = %v, want %v", backend.events, wantInitial)
	}
	before, err := e.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	oldUI := before.Bindings["ui"].Name
	backend.events = nil
	backend.failCapacity = true
	if _, err := runEngine(t, e, sourceModel("c"), key, limits); err == nil || !strings.Contains(err.Error(), "post-pull host capacity") {
		t.Fatalf("post-pull capacity refusal hidden: %v", err)
	}
	state, err := e.Store.Load()
	if err != nil || state.Pending == nil || state.Pending.Phase != "prepare" || state.Routes.Generation != first.Generation || state.Bindings["ui"].Name != oldUI || len(backend.instances) != 2 || len(backend.created) != 2 {
		t.Fatalf("capacity refusal created a candidate or lost intent: state=%+v created=%v err=%v", state, backend.created, err)
	}
	wantRefusal := []string{"stage:ui", "capacity"}
	if !slices.Equal(backend.events, wantRefusal) {
		t.Fatalf("capacity was not checked after every stage and before starts: %v", backend.events)
	}

	backend.failCapacity = false
	backend.events = nil
	result, err := runEngine(t, e, sourceModel("c"), key, limits)
	if err != nil || result.Changed != 1 {
		t.Fatalf("restored capacity did not resume: %+v %v", result, err)
	}
	wantResume := []string{"stage:ui", "capacity", "start:ui"}
	if !slices.Equal(backend.events, wantResume) {
		t.Fatalf("resume ordering = %v, want %v", backend.events, wantResume)
	}
}

func TestEngineResumesPreparationAndAmbiguousSwitch(t *testing.T) {
	e, backend, router, key, limits := newEngine(t)
	backend.failPrepareOnce = true
	if _, err := runEngine(t, e, sourceModel("b"), key, limits); err == nil {
		t.Fatal("preparation failure hidden")
	}
	state, _ := e.Store.Load()
	id := state.Pending.ID
	if _, err := runEngine(t, e, sourceModel("c"), key, limits); err == nil {
		t.Fatal("different release replaced pending transaction")
	}
	router.lostReply = true
	if _, err := runEngine(t, e, sourceModel("b"), key, limits); err == nil {
		t.Fatal("ambiguous switch reported complete")
	}
	state, _ = e.Store.Load()
	if state.Pending.Phase != "switch" || state.Pending.ID != id || len(backend.removed) != 0 {
		t.Fatal("ambiguous switch lost intent or deleted instances")
	}
	result, err := runEngine(t, e, sourceModel("b"), key, limits)
	if err != nil || result.Generation != id || len(backend.created) != 2 {
		t.Fatalf("resume: %+v, %v", result, err)
	}
}

func TestEngineFailedReadinessKeepsOldRelease(t *testing.T) {
	e, backend, _, key, limits := newEngine(t)
	first, err := runEngine(t, e, sourceModel("b"), key, limits)
	if err != nil {
		t.Fatal(err)
	}
	backend.failReady = true
	if _, err := runEngine(t, e, sourceModel("c"), key, limits); err == nil {
		t.Fatal("failed readiness accepted")
	}
	state, err := e.Store.Load()
	if err != nil || state.Pending != nil || state.Routes.Generation != first.Generation || len(backend.instances) != 2 {
		t.Fatalf("old release not preserved: %v", err)
	}
}

func TestEngineDrainTimeoutDoesNotKillWorkAndRecordsViolation(t *testing.T) {
	e, backend, router, key, limits := newEngine(t)
	limits.Retire = 100 * time.Millisecond
	first, err := runEngine(t, e, sourceModel("b"), key, limits)
	if err != nil {
		t.Fatal(err)
	}
	router.blocked = first.Generation
	if result, err := runEngine(t, e, sourceModel("c"), key, limits); !errors.Is(err, ErrRetirementBudget) || !result.RetirementExceeded {
		t.Fatalf("first gateway timeout lost budget identity: %+v %v", result, err)
	}
	state, _ := e.Store.Load()
	if state.Pending.Phase != "drain" || !state.Pending.RetirementExceeded || len(backend.removed) != 0 {
		t.Fatal("deadline caused destructive cleanup or lost violation")
	}
	router.blocked = ""
	result, err := runEngine(t, e, sourceModel("c"), key, limits)
	if !errors.Is(err, ErrRetirementBudget) || !result.RetirementExceeded || len(backend.removed) != 0 {
		t.Fatalf("late retirement: %+v, %v", result, err)
	}
}

func TestEngineUnknownDrainAndInterruptedCleanup(t *testing.T) {
	e, backend, router, key, limits := newEngine(t)
	if _, err := runEngine(t, e, sourceModel("b"), key, limits); err != nil {
		t.Fatal(err)
	}
	router.unknownDrain = true
	if _, err := runEngine(t, e, sourceModel("c"), key, limits); err == nil || len(backend.removed) != 0 {
		t.Fatal("unknown drain authorized cleanup")
	}
	router.unknownDrain = false
	backend.failRemoveOnce = true
	if _, err := runEngine(t, e, sourceModel("c"), key, limits); err == nil {
		t.Fatal("cleanup failure hidden")
	}
	state, _ := e.Store.Load()
	if state.Pending.Phase != "retire" {
		t.Fatal("positive drain checkpoint not retained")
	}
	if _, err := runEngine(t, e, sourceModel("c"), key, limits); err != nil {
		t.Fatal(err)
	}
	if len(backend.removed) != 1 {
		t.Fatal("retirement duplicated effects")
	}
}

func TestEngineRefusesStatefulChangeAndKeyMismatch(t *testing.T) {
	e, backend, _, key, limits := newEngine(t)
	var model map[string]any
	json.Unmarshal(sourceModel("b"), &model)
	model["x-komizo"].(map[string]any)["services"].(map[string]any)["api"] = map[string]any{"mode": "persistent"}
	body, _ := json.Marshal(model)
	if _, err := runEngine(t, e, body, key, limits); err == nil || len(backend.created) != 0 {
		t.Fatal("persistent change started a candidate")
	}
	if _, err := runEngine(t, e, sourceModel("b"), key, limits); err != nil {
		t.Fatal(err)
	}
	if _, err := runEngine(t, e, sourceModel("c"), bytes.Repeat([]byte{2}, 32), limits); err == nil {
		t.Fatal("cross-key state accepted")
	}
}

func TestJournalExclusionPrivacyAndCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	first, err := OpenStore(ctx, path, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	short, cancelShort := context.WithTimeout(ctx, 5*time.Millisecond)
	defer cancelShort()
	if second, err := OpenStore(short, path, time.Millisecond); err == nil {
		second.Close()
		t.Fatal("concurrent lock acquired")
	}
	if err := first.WritePrivate("../escape", []byte("x")); err == nil {
		t.Fatal("private artifact escaped root")
	}
	if err := first.WritePrivate("state.json", []byte(`{"private":"do-not-echo"`)); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Load(); err == nil || strings.Contains(err.Error(), "do-not-echo") {
		t.Fatal("corruption accepted or disclosed")
	}
	first.Close()
	second, err := OpenStore(ctx, path, time.Millisecond)
	if err != nil {
		t.Fatal("lock did not release")
	}
	second.Close()
}

func TestWorkerStartsStandbyThenActivatesAfterSwitch(t *testing.T) {
	engine, backend, _, key, limits := newEngine(t)
	result, err := runEngine(t, engine, nonRequestModel("worker", "a"), key, limits)
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed != 1 {
		t.Fatalf("changed=%d", result.Changed)
	}
	joined := strings.Join(backend.lifecycleCalls, "\n")
	ready := strings.Index(joined, "ready:")
	activate := strings.Index(joined, "activate:")
	if ready < 0 || activate <= ready {
		t.Fatalf("worker handoff order is not ready then activate: %s", joined)
	}
}

func TestOneShotCompletesOnceAndIsNotAnActiveBinding(t *testing.T) {
	engine, backend, _, key, limits := newEngine(t)
	model := nonRequestModel("one-shot", "a")
	if _, err := runEngine(t, engine, model, key, limits); err != nil {
		t.Fatal(err)
	}
	if len(backend.created) != 1 || len(backend.removed) != 1 {
		t.Fatalf("one-shot create/remove = %v/%v", backend.created, backend.removed)
	}
	if _, err := runEngine(t, engine, model, key, limits); err != nil {
		t.Fatal(err)
	}
	if len(backend.created) != 1 {
		t.Fatalf("no-op reran one-shot: %v", backend.created)
	}
	state, err := engine.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Bindings) != 0 {
		t.Fatalf("completed one-shot became a serving binding: %#v", state.Bindings)
	}
}

func TestPersistentBootstrapRefusesBeforeCandidateCreation(t *testing.T) {
	engine, backend, _, key, limits := newEngine(t)
	_, err := runEngine(t, engine, nonRequestModel("persistent", "a"), key, limits)
	if err == nil || !strings.Contains(err.Error(), "explicit maintenance") {
		t.Fatalf("persistent bootstrap was not refused: %v", err)
	}
	if len(backend.created) != 0 {
		t.Fatalf("persistent refusal created candidates: %v", backend.created)
	}
}
