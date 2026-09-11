package rollout

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLifecycleInterruptionCheckpoints(t *testing.T) {
	for _, action := range []string{"quiesce", "seal", "drain", "stop", "remove"} {
		t.Run(action, func(t *testing.T) {
			e, b, _, key, limits := newEngine(t)
			if _, err := runEngine(t, e, sourceModel("b"), key, limits); err != nil {
				t.Fatal(err)
			}
			b.failLifecycle = action
			if _, err := runEngine(t, e, sourceModel("c"), key, limits); err == nil {
				t.Fatal("interruption hidden")
			}
			state, err := e.Store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if state.Pending == nil || len(b.removed) != 0 {
				t.Fatal("interruption committed or removed application")
			}
			old := state.Bindings["ui"]
			want := map[string]string{"quiesce": "", "seal": "quiesce", "drain": "seal", "stop": "drain", "remove": "stop"}[action]
			if state.Pending.Retirements[old.Name].Stage != want {
				t.Fatal("lost positive application checkpoint")
			}
			b.failLifecycle = ""
			if _, err := runEngine(t, e, sourceModel("c"), key, limits); err != nil {
				t.Fatal(err)
			}
			if len(b.removed) != 1 {
				t.Fatal("resume did not complete once")
			}
		})
	}
}

func TestQuiescePrecedesGatewayDrainAndSealFollowsProof(t *testing.T) {
	e, b, r, key, limits := newEngine(t)
	first, err := runEngine(t, e, sourceModel("b"), key, limits)
	if err != nil {
		t.Fatal(err)
	}
	r.blocked = first.Generation
	b.lifecycleHook = func(_ context.Context, action string) error {
		if action == "quiesce" {
			current, _ := r.g.Current()
			if current.Generation == first.Generation || r.blocked == "" {
				t.Fatal("quiesce did not follow flip before gateway drain")
			}
			r.blocked = "" // admitted work finishes only after application quiesce
		} else if r.blocked != "" {
			t.Fatal("sealed application with gateway work outstanding")
		}
		return nil
	}
	if _, err := runEngine(t, e, sourceModel("c"), key, limits); err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, call := range b.lifecycleCalls {
		action, _, _ := strings.Cut(call, ":")
		actions = append(actions, action)
	}
	if strings.Join(actions, ",") != "quiesce,seal,drain,stop,remove" {
		t.Fatalf("application order: %v", actions)
	}
}

func TestApplicationTimeoutPreservesOldInstanceAndCannotBecomeLateSuccess(t *testing.T) {
	for _, action := range []string{"quiesce", "drain", "stop"} {
		t.Run(action, func(t *testing.T) {
			e, b, _, key, limits := newEngine(t)
			limits.Retire = 40 * time.Millisecond
			if _, err := runEngine(t, e, sourceModel("b"), key, limits); err != nil {
				t.Fatal(err)
			}
			b.lifecycleHook = func(ctx context.Context, a string) error {
				if a == action {
					<-ctx.Done()
					return ctx.Err()
				}
				return nil
			}
			if _, err := runEngine(t, e, sourceModel("c"), key, limits); err == nil {
				t.Fatal("timeout hidden")
			}
			state, err := e.Store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if state.Pending == nil || !state.Pending.RetirementExceeded || len(b.removed) != 0 {
				t.Fatal("timeout lost incomplete retirement or removed work")
			}
			b.lifecycleHook = nil
			if _, err := runEngine(t, e, sourceModel("c"), key, limits); !errors.Is(err, ErrRetirementBudget) {
				t.Fatal("expired policy resumed as success", err)
			}
			if len(b.removed) != 0 {
				t.Fatal("expired policy authorized late deletion")
			}
		})
	}
}

func TestAbortDrainsCandidateBackgroundWorkAndResumes(t *testing.T) {
	e, b, _, key, limits := newEngine(t)
	if _, err := runEngine(t, e, sourceModel("b"), key, limits); err != nil {
		t.Fatal(err)
	}
	b.failReady = true
	b.failLifecycle = "drain"
	if _, err := runEngine(t, e, sourceModel("c"), key, limits); err == nil {
		t.Fatal("readiness failure hidden")
	}
	state, _ := e.Store.Load()
	if state.Pending == nil || state.Pending.Phase != "abort" || len(b.instances) != 3 || len(b.removed) != 0 {
		t.Fatal("background-working candidate removed without proof")
	}
	b.failLifecycle = ""
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := e.Abort(ctx, "app", key, time.Second); err != nil {
		t.Fatal(err)
	}
	if len(b.instances) != 2 || len(b.removed) != 1 {
		t.Fatal("abort did not retire only candidate")
	}
}

func TestContainerIncarnationProofRefusesNameReuseAndRestart(t *testing.T) {
	p := Retirement{ID: "original", StartedAt: "boot1", Stage: "drain"}
	c := &container{ID: p.ID}
	c.State.StartedAt = p.StartedAt
	if err := sameIncarnation(c, p); err != nil {
		t.Fatal(err)
	}
	c.ID = "replacement"
	if sameIncarnation(c, p) == nil {
		t.Fatal("name reuse accepted")
	}
	c.ID = p.ID
	c.State.StartedAt = "boot2"
	if sameIncarnation(c, p) == nil || sameIncarnation(nil, p) == nil {
		t.Fatal("restart or absence accepted")
	}
}
