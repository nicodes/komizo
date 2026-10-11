package main

import (
	"context"
	"errors"
	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/internal/workload"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTypedLifecyclePreservesNewerStop(t *testing.T) {
	f := newDeploymentFixture(t)
	if err := activationPass(context.Background(), f.queue, f.h); err != nil {
		t.Fatal(err)
	}
	sub := subject{app: f.r.App, root: f.h.root, dir: f.h.policy.AppDir}
	if err := box.MarkStopped(sub.root, sub.app, "fixture", time.Now()); err != nil {
		t.Fatal(err)
	}
	original := f.h.run
	f.h.run = func(ctx context.Context, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), " up -d ") {
			if err := box.MarkStopped(sub.root, sub.app, "newer-stop", time.Now()); err != nil {
				return "", err
			}
		}
		return original(ctx, args...)
	}
	if err := f.h.performTypedOwner(context.Background(), "start", sub, "", "fixture", f.queue); !errors.Is(err, workload.ErrActivationStopped) {
		t.Fatalf("start did not refuse newer stop: %v", err)
	}
	stopped, err := box.IsStopped(sub.root, sub.app)
	if err != nil || !stopped {
		t.Fatal("new stop disappeared")
	}
	if !strings.Contains(strings.Join(f.calls, "\n"), " stop") {
		t.Fatal("containers not stopped after race")
	}
}
func TestTypedLifecycleRefusesPendingStartupAndPreservesFailedStop(t *testing.T) {
	f := newDeploymentFixture(t)
	sub := subject{app: f.r.App, root: f.h.root, dir: filepath.Join(f.h.root, "srv/example")}
	if err := f.h.performTypedOwner(context.Background(), "start", sub, "", "fixture", f.queue); err == nil {
		t.Fatal("startup consumed pending deployment")
	}
	if len(f.calls) != 0 {
		t.Fatal("pending startup touched docker")
	}
	if err := activationPass(context.Background(), f.queue, f.h); err != nil {
		t.Fatal(err)
	}
	f.h.run = func(context.Context, ...string) (string, error) { return "", errors.New("synthetic docker failure") }
	if err := f.h.performTypedOwner(context.Background(), "stop", sub, "", "fixture", f.queue); err == nil {
		t.Fatal("failed docker stop reported success")
	}
	stopped, err := box.IsStopped(sub.root, sub.app)
	if err != nil || !stopped {
		t.Fatal("failed stop lost durable intent")
	}
}
func TestTypedLifecycleRejectsDuplicateRetention(t *testing.T) {
	f := newDeploymentFixture(t)
	if err := activationPass(context.Background(), f.queue, f.h); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.h.policy.AppDir, ".komizo-image-retention"), []byte("CURRENT="+f.r.Previous+"\nCURRENT="+f.r.Candidate+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	sub := subject{app: f.r.App, root: f.h.root, dir: f.h.policy.AppDir}
	if err := f.h.performTypedOwner(context.Background(), "start", sub, "", "fixture", f.queue); err == nil {
		t.Fatal("duplicate current retention accepted")
	}
}
