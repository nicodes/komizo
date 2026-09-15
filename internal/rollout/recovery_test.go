package rollout

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/internal/gateway"
)

type recoveryBackend struct {
	*memoryBackend
	snapshot      RecoverySnapshot
	inspectErr    error
	removedFailed int
	removeCalls   int
	removeHook    func(int)
}

func TestRecoveryRequiresEveryOtherServiceNormalQuiesceProof(t *testing.T) {
	now := time.Now().UTC()
	workerOld := Instance{Name: "kmz-old-worker", Service: "worker", Mode: "worker"}
	apiOld := Instance{Name: "kmz-old-api", Service: "api", Mode: "request"}
	workerNew := Instance{Name: "kmz-new-worker", Service: "worker", Mode: "worker"}
	apiNew := Instance{Name: "kmz-new-api", Service: "api", Mode: "request"}
	state := &State{Bindings: map[string]Instance{"worker": workerOld, "api": apiOld}, Pending: &Transaction{
		ID: "new", SwitchStartedAt: now.Add(-time.Minute), SwitchedAt: now.Add(-time.Minute),
		Before: gateway.Config{Generation: "old"}, After: gateway.Config{Generation: "new", Parent: "old"},
		Candidates: map[string]Instance{"worker": workerNew, "api": apiNew}, Retirements: map[string]Retirement{},
	}}
	if err := validateRecoveryTransaction(state, "worker"); err == nil {
		t.Fatal("missing API quiesce proof accepted before worker recovery")
	}
	state.Pending.Retirements[apiOld.Name] = Retirement{ID: "api-incarnation", StartedAt: "boot", Stage: "quiesce"}
	if err := validateRecoveryTransaction(state, "worker"); err != nil {
		t.Fatalf("positive non-target quiesce proof refused: %v", err)
	}
	state.Pending.Candidates["second-worker"] = Instance{Name: "kmz-new-second", Service: "second-worker", Mode: "worker"}
	state.Bindings["second-worker"] = Instance{Name: "kmz-old-second", Service: "second-worker", Mode: "worker"}
	state.Pending.Retirements["kmz-old-second"] = Retirement{ID: "second-incarnation", StartedAt: "boot", Stage: "quiesce"}
	if err := validateRecoveryTransaction(state, "worker"); err == nil {
		t.Fatal("one recovery authorization activated multiple changed workers")
	}
}

func (b *recoveryBackend) InspectRecovery(context.Context, Instance, Instance) (RecoverySnapshot, error) {
	if b.inspectErr != nil {
		return RecoverySnapshot{}, b.inspectErr
	}
	return b.snapshot, nil
}

func (b *recoveryBackend) RemoveRecovered(_ context.Context, old, _ Instance, proof VerifiedRecovery) error {
	if proof.Old.ID != b.snapshot.Old.ID || proof.Old.StartedAt != b.snapshot.Old.StartedAt || proof.Old.FinishedAt != b.snapshot.Old.FinishedAt {
		return errors.New("recovery removal proof changed")
	}
	if proof.Candidate.ID != b.snapshot.Candidate.ID || proof.Candidate.StartedAt != b.snapshot.Candidate.StartedAt {
		return errors.New("recovery candidate proof changed")
	}
	if _, exists := b.instances[old.Name]; exists {
		b.removedFailed++
		delete(b.instances, old.Name)
	}
	b.removeCalls++
	if b.removeHook != nil {
		b.removeHook(b.removeCalls)
	}
	return nil
}

type verifierFixture struct {
	failOpen, failRelease bool
	opens                 int
	openHook              func()
	held                  bool
}

func (v *verifierFixture) Open(context.Context, RecoveryChallenge) (RecoverySession, error) {
	v.opens++
	if v.openHook != nil {
		v.openHook()
	}
	if v.failOpen {
		return nil, errors.New("application state is not fenced and empty")
	}
	v.held = true
	return &verifierSessionFixture{verifier: v, failRelease: v.failRelease}, nil
}

type verifierSessionFixture struct {
	verifier    *verifierFixture
	failRelease bool
}

func (s *verifierSessionFixture) Release(context.Context) error {
	if s.failRelease {
		return errors.New("verifier exited before release acknowledgement")
	}
	s.verifier.held = false
	return nil
}
func (*verifierSessionFixture) Preserve() {}

func pendingWorkerRecovery(t *testing.T) (*Engine, *recoveryBackend, *memoryRouter, *verifierFixture, []byte, RecoveryAuthorization) {
	t.Helper()
	e, memory, router, key, limits := newEngine(t)
	limits.Stabilize = time.Millisecond
	limits.Retire = 5 * time.Minute
	if _, err := runEngine(t, e, nonRequestModel("worker", "b"), key, limits); err != nil {
		t.Fatal(err)
	}
	state, _ := e.Store.Load()
	old := state.Bindings["task"]
	memory.failLifecycle = "quiesce"
	if _, err := runEngine(t, e, nonRequestModel("worker", "c"), key, limits); err == nil {
		t.Fatal("control did not stall on the old worker")
	}
	state, _ = e.Store.Load()
	candidate := state.Pending.Candidates["task"]
	oldStarted := state.Pending.SwitchStartedAt.Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano)
	candidateStarted := state.Pending.SwitchStartedAt.Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	finished := state.Pending.SwitchStartedAt.Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	rb := &recoveryBackend{memoryBackend: memory, snapshot: RecoverySnapshot{
		Old:       RecoveryIncarnation{ID: strings.Repeat("e", 64), StartedAt: oldStarted, FinishedAt: finished, ExitCode: 1},
		Candidate: RecoveryIncarnation{ID: strings.Repeat("f", 64), StartedAt: candidateStarted, Running: true},
	}}
	e.Backend = rb
	verifier := &verifierFixture{}
	memory.candidateHook = func(action string) error {
		if action == "activate" && !verifier.held {
			return errors.New("activation escaped the application producer fence")
		}
		return nil
	}
	auth := RecoveryAuthorization{Version: 1, App: "app", Transaction: state.Pending.ID, Service: "task",
		Old:            RecoveryIncarnationPin{ID: rb.snapshot.Old.ID, StartedAt: oldStarted, FinishedAt: finished, ExitCode: 1, Generation: old.Generation, Identity: old.Identity},
		Candidate:      RecoveryIncarnationPin{ID: rb.snapshot.Candidate.ID, StartedAt: candidateStarted, Generation: candidate.Generation, Identity: candidate.Identity},
		VerifierSHA256: strings.Repeat("a", 64), VerifierPath: "/usr/libexec/example-recovery", UID: 1000, GID: 1000,
		Overall: 8 * time.Minute, Retire: 5 * time.Minute, Digest: strings.Repeat("b", 64)}
	return e, rb, router, verifier, key, auth
}

func recoverEngine(t *testing.T, e *Engine, verifier RecoveryVerifier, key []byte, auth RecoveryAuthorization) (Result, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return e.Recover(ctx, "app", key, auth, verifier)
}

func TestVerifiedRecoveryRecordsDistinctProofAndNeverForgesLifecycleSuccess(t *testing.T) {
	e, backend, _, verifier, key, auth := pendingWorkerRecovery(t)
	pending, _ := e.Store.Load()
	oldName := pending.Bindings[auth.Service].Name
	beforeCalls := len(backend.lifecycleCalls)
	result, err := recoverEngine(t, e, verifier, key, auth)
	if err != nil || !result.Recovered {
		t.Fatalf("verified recovery failed: %+v %v", result, err)
	}
	state, loadErr := e.Store.Load()
	if loadErr != nil || state.Pending != nil || !state.Last.Recovered || backend.removedFailed != 1 || verifier.held {
		t.Fatalf("recovery did not commit exactly once: state=%+v removed=%d err=%v", state, backend.removedFailed, loadErr)
	}
	for _, call := range backend.lifecycleCalls[beforeCalls:] {
		if strings.HasSuffix(call, ":"+oldName) {
			t.Fatalf("failed old worker received forged lifecycle transition: %s", call)
		}
	}
	if _, err := recoverEngine(t, e, verifier, key, auth); !errors.Is(err, ErrNoPending) || backend.removedFailed != 1 {
		t.Fatalf("completed authorization replayed: removed=%d err=%v", backend.removedFailed, err)
	}
}

func TestVerifiedRecoveryFailsClosedBeforeActivation(t *testing.T) {
	tests := []struct {
		name    string
		breakIt func(*recoveryBackend, *memoryRouter, *verifierFixture, *RecoveryAuthorization)
	}{
		{"stale identity", func(_ *recoveryBackend, _ *memoryRouter, _ *verifierFixture, a *RecoveryAuthorization) {
			a.Old.ID = "replacement"
		}},
		{"unsafe container", func(b *recoveryBackend, _ *memoryRouter, _ *verifierFixture, _ *RecoveryAuthorization) {
			b.inspectErr = errors.New("old worker restarted or OOM killed")
		}},
		{"gateway mismatch", func(_ *recoveryBackend, r *memoryRouter, _ *verifierFixture, _ *RecoveryAuthorization) {
			r.wrongCurrent = true
		}},
		{"stale epoch", func(_ *recoveryBackend, r *memoryRouter, _ *verifierFixture, _ *RecoveryAuthorization) {
			r.wrongEpoch = true
		}},
		{"old requests", func(_ *recoveryBackend, r *memoryRouter, _ *verifierFixture, _ *RecoveryAuthorization) {
			r.blockAll = true
		}},
		{"gateway changed after fence", func(_ *recoveryBackend, r *memoryRouter, v *verifierFixture, _ *RecoveryAuthorization) {
			v.openHook = func() { r.wrongCurrent = true }
		}},
		{"identity changed after fence", func(b *recoveryBackend, _ *memoryRouter, v *verifierFixture, _ *RecoveryAuthorization) {
			v.openHook = func() { b.snapshot.Candidate.ID = strings.Repeat("1", 64) }
		}},
		{"nonempty or racy app", func(_ *recoveryBackend, _ *memoryRouter, v *verifierFixture, _ *RecoveryAuthorization) {
			v.failOpen = true
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e, backend, router, verifier, key, auth := pendingWorkerRecovery(t)
			test.breakIt(backend, router, verifier, &auth)
			state, _ := e.Store.Load()
			candidateName := state.Pending.Candidates["task"].Name
			beforeActivation := countLifecycleCall(backend.lifecycleCalls, "activate:"+candidateName)
			if result, err := recoverEngine(t, e, verifier, key, auth); err == nil || result.Recovered {
				t.Fatalf("unsafe recovery accepted: %+v %v", result, err)
			}
			state, _ = e.Store.Load()
			if state.Pending == nil || backend.removedFailed != 0 || countLifecycleCall(backend.lifecycleCalls, "activate:"+candidateName) != beforeActivation {
				t.Fatalf("failure activated or removed state: %+v calls=%v", state, backend.lifecycleCalls)
			}
		})
	}
}

func TestVerifiedRecoveryRequiresFreshStandbyProof(t *testing.T) {
	e, backend, _, verifier, key, auth := pendingWorkerRecovery(t)
	backend.failLifecycle = "ready"
	if result, err := recoverEngine(t, e, verifier, key, auth); err == nil || result.Recovered {
		t.Fatalf("recovery accepted an unconfirmed standby: %+v %v", result, err)
	}
	if verifier.opens != 0 || backend.removedFailed != 0 {
		t.Fatalf("unconfirmed standby reached verifier or cleanup: opens=%d removed=%d", verifier.opens, backend.removedFailed)
	}
}

func countLifecycleCall(values []string, value string) int {
	count := 0
	for _, item := range values {
		if item == value {
			count++
		}
	}
	return count
}

func TestActivationFailureKeepsFenceAndVerifiedRetryCompletes(t *testing.T) {
	e, backend, _, verifier, key, auth := pendingWorkerRecovery(t)
	backend.failLifecycle = "activate"
	if _, err := recoverEngine(t, e, verifier, key, auth); err == nil {
		t.Fatal("activation failure hidden")
	}
	state, _ := e.Store.Load()
	if state.Pending == nil || state.Pending.Recovery == nil || state.Pending.Recovery.ProvedAt.IsZero() || !state.Pending.Recovery.ActivatedAt.IsZero() || !state.Pending.Recovery.ReleasedAt.IsZero() || backend.removedFailed != 0 {
		t.Fatalf("activation failure lost fenced proof or retired state: %+v", state.Pending)
	}
	if !verifier.held {
		t.Fatal("activation failure dropped the durable application fence")
	}
	backend.failLifecycle = ""
	if result, err := recoverEngine(t, e, verifier, key, auth); err != nil || !result.Recovered || verifier.opens != 2 {
		t.Fatalf("restored activation did not safely complete: %+v %v opens=%d", result, err, verifier.opens)
	}
}

func TestChangedIncarnationAfterActivationKeepsFenceAndJournal(t *testing.T) {
	e, backend, _, verifier, key, auth := pendingWorkerRecovery(t)
	backend.candidateHook = func(action string) error {
		if action == "activate" {
			if !verifier.held {
				return errors.New("activation escaped the application producer fence")
			}
			backend.snapshot.Candidate.ID = strings.Repeat("1", 64)
		}
		return nil
	}
	if _, err := recoverEngine(t, e, verifier, key, auth); err == nil {
		t.Fatal("post-activation incarnation race accepted")
	}
	state, _ := e.Store.Load()
	if state.Pending == nil || state.Pending.Recovery.ActivatedAt.IsZero() || !state.Pending.Recovery.ReleasedAt.IsZero() || backend.removedFailed != 0 || !verifier.held {
		t.Fatalf("post-activation race released fence or journal: pending=%+v held=%t removed=%d", state.Pending, verifier.held, backend.removedFailed)
	}
}

func TestChangedCandidateAfterRemovalPreventsCommit(t *testing.T) {
	e, backend, _, verifier, key, auth := pendingWorkerRecovery(t)
	backend.removeHook = func(call int) {
		if call == 1 {
			backend.snapshot.Candidate.ID = strings.Repeat("1", 64)
		}
	}
	if result, err := recoverEngine(t, e, verifier, key, auth); err == nil || result.Recovered {
		t.Fatalf("post-removal candidate race committed: %+v %v", result, err)
	}
	state, _ := e.Store.Load()
	if state.Pending == nil || state.Pending.Recovery.RemovedAt.IsZero() || backend.removedFailed != 1 || verifier.held {
		t.Fatalf("post-removal race lost truthful state: pending=%+v held=%t removed=%d", state.Pending, verifier.held, backend.removedFailed)
	}
}

func TestVerifiedRecoveryBudgetCannotRenew(t *testing.T) {
	for _, budget := range []string{"overall", "retirement"} {
		t.Run(budget, func(t *testing.T) {
			e, backend, _, verifier, key, auth := pendingWorkerRecovery(t)
			verifier.failOpen = true
			if _, err := recoverEngine(t, e, verifier, key, auth); err == nil {
				t.Fatal("verifier refusal hidden")
			}
			state, _ := e.Store.Load()
			firstStarted := state.Pending.Recovery.StartedAt
			if budget == "overall" {
				state.Pending.Recovery.OverallDeadline = time.Now().Add(-time.Second)
			} else {
				state.Pending.Recovery.RetirementDeadline = time.Now().Add(-time.Second)
			}
			if err := e.Store.Save(state); err != nil {
				t.Fatal(err)
			}
			verifier.failOpen = false
			if _, err := recoverEngine(t, e, verifier, key, auth); !errors.Is(err, ErrRecoveryBudget) {
				t.Fatalf("expired recovery resumed: %v", err)
			}
			state, _ = e.Store.Load()
			if !state.Pending.Recovery.StartedAt.Equal(firstStarted) || !state.Pending.Recovery.Expired || backend.removedFailed != 0 {
				t.Fatalf("retry renewed or cleaned expired recovery: %+v", state.Pending.Recovery)
			}
		})
	}
}

func TestVerifierReleaseFailureLeavesDistinctActivatedButUnreleasedState(t *testing.T) {
	e, backend, _, verifier, key, auth := pendingWorkerRecovery(t)
	verifier.failRelease = true
	if _, err := recoverEngine(t, e, verifier, key, auth); err == nil {
		t.Fatal("early EOF/release failure hidden")
	}
	state, _ := e.Store.Load()
	if state.Pending.Recovery.ActivatedAt.IsZero() || !state.Pending.Recovery.ReleasedAt.IsZero() || backend.removedFailed != 0 {
		t.Fatalf("release failure claimed completion or removed failed worker: %+v", state.Pending.Recovery)
	}
	if !verifier.held {
		t.Fatal("release failure dropped the durable application fence")
	}
	verifier.failRelease = false
	if result, err := recoverEngine(t, e, verifier, key, auth); err != nil || !result.Recovered || verifier.opens != 2 {
		t.Fatalf("safe retry did not re-establish verifier session once: %+v %v opens=%d", result, err, verifier.opens)
	}
}

func TestStartedRecoveryRejectsChangedAuthorization(t *testing.T) {
	e, backend, _, verifier, key, auth := pendingWorkerRecovery(t)
	verifier.failOpen = true
	if _, err := recoverEngine(t, e, verifier, key, auth); err == nil {
		t.Fatal("control did not consume the first authorization")
	}
	state, _ := e.Store.Load()
	started := state.Pending.Recovery.StartedAt
	auth.Digest = strings.Repeat("c", 64)
	verifier.failOpen = false
	if result, err := recoverEngine(t, e, verifier, key, auth); err == nil || result.Recovered {
		t.Fatalf("changed authorization resumed recovery: %+v %v", result, err)
	}
	state, _ = e.Store.Load()
	if !state.Pending.Recovery.StartedAt.Equal(started) || backend.removedFailed != 0 || verifier.opens != 1 {
		t.Fatalf("changed authorization renewed or executed recovery: %+v opens=%d", state.Pending.Recovery, verifier.opens)
	}
}
