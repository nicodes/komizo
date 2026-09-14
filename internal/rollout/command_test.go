package rollout

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/internal/gateway"
)

func TestRolloutStatusDoesNotExposePrivateSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	store, err := OpenStore(ctx, path, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	state := &State{Version: 1, App: "app", KeyID: "private-key-id", Active: json.RawMessage(`{"secret":"private-config-value"}`),
		Routes:  gateway.Config{App: "app", Generation: "active", Routes: []gateway.Route{}},
		Pending: &Transaction{ID: "pending", Phase: "prepare", Source: json.RawMessage(`{"secret":"private-pending-value"}`), Candidates: map[string]Instance{"api": {Name: "private-container-name"}}}}
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	store.Close()
	var out, diag bytes.Buffer
	err = Command(ctx, []string{"status", "--app", "app", "--state-dir", path, "--timeout", "500ms", "--poll", "1ms"}, strings.NewReader(""), &out, &diag)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "private-") || !strings.Contains(out.String(), `"phase":"prepare"`) {
		t.Fatalf("unsafe/incomplete status: %s", out.String())
	}
}

func TestRolloutCommandRejectsBeforeCreatingState(t *testing.T) {
	state := filepath.Join(t.TempDir(), "not-created")
	for _, args := range [][]string{{}, {"--app", "app", "--state-dir", state}, {"status", "--app", "app", "--state-dir", state, "--timeout", "1s", "--poll", "1ms"}} {
		var out, diag bytes.Buffer
		if err := Command(context.Background(), args, strings.NewReader(""), &out, &diag); err == nil {
			t.Fatal("incomplete command accepted")
		}
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("invalid/status command created a directory")
	}
}

func TestPreSwitchAbortAndPostSwitchRefusal(t *testing.T) {
	e, b, r, key, limits := newEngine(t)
	b.failPrepareOnce = true
	if _, err := runEngine(t, e, sourceModel("b"), key, limits); err == nil {
		t.Fatal("missing fixture interruption")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := e.Abort(ctx, "app", key, time.Second)
	if err != nil || !result.Aborted {
		t.Fatalf("abort: %+v, %v", result, err)
	}
	if state, _ := e.Store.Load(); state.Pending != nil {
		t.Fatal("abort kept pending state")
	}
	r.lostReply = true
	if _, err := runEngine(t, e, sourceModel("c"), key, limits); err == nil {
		t.Fatal("missing ambiguous switch")
	}
	if _, err := e.Abort(ctx, "app", key, time.Second); err == nil {
		t.Fatal("abort allowed after possible switch")
	}
	if len(b.removed) != 0 {
		t.Fatal("post-switch abort deleted candidates")
	}
}
