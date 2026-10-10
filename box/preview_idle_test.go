package box

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestProvisionedPreviewDatabaseStartsWithoutCreatingInfrastructure(t *testing.T) {
	var calls []string
	run := func(ctx context.Context, stdin string, args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
		if args[0] == "inspect" {
			return "false", nil
		}
		return "", nil
	}
	if err := ensurePreviewDBReady(context.Background(), run, true); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 || calls[1] != "start "+PreviewDBContainer || !strings.Contains(calls[2], "pg_isready") {
		t.Fatalf("unexpected lifecycle: %v", calls)
	}
	missing := func(context.Context, string, ...string) (string, error) { return "", errors.New("absent") }
	if err := ensurePreviewDBReady(context.Background(), missing, true); err == nil {
		t.Fatal("missing infrastructure accepted")
	}
}

func TestIdlePreviewDatabaseStopsOnlyWithoutDatabaseRecords(t *testing.T) {
	root := t.TempDir()
	cfg := PreviewUpConfig{Root: root, ManageIdleDatabase: true, Knob: PreviewKnob{TTL: time.Hour, Max: 5}}
	var calls []string
	run := func(ctx context.Context, stdin string, args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
		if args[0] == "inspect" {
			return "true", nil
		}
		return "", nil
	}
	if _, err := PreviewGC(context.Background(), run, cfg, time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[1] != "stop --time 30 "+PreviewDBContainer {
		t.Fatalf("idle database not stopped: %v", calls)
	}
	rec := PreviewRecord{App: "example", Project: "example-pr-1", PR: 1, DBName: "example_pr_1", LastUsed: time.Now()}
	if err := writePreviewRecord(root, rec); err != nil {
		t.Fatal(err)
	}
	calls = nil
	if _, err := PreviewGC(context.Background(), run, cfg, time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 0 {
		t.Fatalf("active database stopped: %v", calls)
	}
	// An unreadable cleanup record refuses idle cleanup rather than discarding
	// state or stopping a database whose ownership cannot be established.
	rec.App = ""
	if err := writePreviewRecord(root, rec); err != nil {
		t.Fatal(err)
	}
	if _, err := PreviewGC(context.Background(), run, cfg, time.Now()); err == nil {
		t.Fatal("unreadable ownership record accepted")
	}
	if len(calls) != 0 {
		t.Fatalf("uncertain ownership stopped database: %v", calls)
	}
}
