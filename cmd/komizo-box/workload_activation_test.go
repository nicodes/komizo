package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nicodes/komizo/box"
	"github.com/nicodes/komizo/internal/workload"
)

// This fixture exercises the actual host adapter and durable queue. Only root
// ownership and Docker are substituted; CI's user cannot manufacture uid 0.
func activationFixture(t *testing.T) (string, *hostActivation, workload.ActivationRequest) {
	t.Helper()
	root := t.TempDir()
	appDir := filepath.Join(root, "srv", "example")
	policies := filepath.Join(root, "policies")
	releases := filepath.Join(root, "releases")
	queue := filepath.Join(root, "queue")
	for _, dir := range []string{appDir, policies, queue, filepath.Join(releases, "example"), filepath.Join(root, box.AppsDir)} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	p, err := workload.NewPolicy("example", appDir, "ghcr.io/example/example-config", "edge")
	if err != nil {
		t.Fatal(err)
	}
	if err := workload.WritePrivateJSON(filepath.Join(policies, "example.json"), p); err != nil {
		t.Fatal(err)
	}
	write := func(path, body string) {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(appDir, "compose.yml"), `{"name":"example","services":{}}`)
	write(filepath.Join(appDir, ".env"), "APP_VERSION=candidate\n")
	route := filepath.Join(root, "example.caddy")
	write(route, "example.test { respond ok }\n")
	opPath := filepath.Join(releases, "example", "operation.json")
	for _, phase := range []string{"admitted", "configured"} {
		if err := workload.RecordOperation(opPath, "example", "candidate", "previous", phase, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	read := func(path string, out any) error {
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return json.Unmarshal(body, out)
	}
	var op workload.Operation
	if err := read(opPath, &op); err != nil {
		t.Fatal(err)
	}
	r := workload.ActivationRequest{Version: 1, ID: op.ID, App: op.App, Candidate: op.Candidate, Previous: op.Previous, Deadline: op.Deadline, RoutePath: route, Proxy: "komizo-proxy"}
	hash := func(path string) string {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		return hex.EncodeToString(sum[:])
	}
	r.PolicySHA256 = hash(filepath.Join(policies, "example.json"))
	r.ComposeSHA256 = hash(filepath.Join(appDir, "compose.yml"))
	r.RouteSHA256 = hash(route)
	if err := workload.WritePrivateJSON(filepath.Join(queue, "pending.json"), r); err != nil {
		t.Fatal(err)
	}
	h := &hostActivation{policies: policies, releases: releases, root: root, readJSON: read, readBytes: os.ReadFile, run: func(context.Context, ...string) (string, error) { return "", nil }}
	return queue, h, r
}

func activationStoppedFixture(t *testing.T, h *hostActivation, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(h.root, box.AppsDir, "example.env"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestRootActivationOwnsDisconnectedClientAndStopsWin(t *testing.T) {
	for _, tc := range []struct {
		name, marker string
		during       string
		started      bool
		verbs        []string
	}{
		{"ordinary", "", "", true, []string{"up"}},
		{"stopped", "STOPPED=1\n", "", false, nil},
		{"crlf", "STOPPED=1\r\n", "", false, nil},
		{"first wins", "STOPPED=0\nSTOPPED=1\n", "", true, []string{"up"}},
		{"stop during up", "", "up", false, []string{"up", "stop"}},
		{"stop during proxy reload", "", "reload", false, []string{"up", "stop"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			queue, h, r := activationFixture(t)
			if tc.marker != "" {
				activationStoppedFixture(t, h, tc.marker)
			}
			var verbs []string
			h.run = func(_ context.Context, args ...string) (string, error) {
				if args[0] == "compose" {
					verb := args[7]
					verbs = append(verbs, verb)
					if verb == tc.during {
						activationStoppedFixture(t, h, "STOPPED=1\n")
					}
				}
				if args[0] == "exec" && args[3] == tc.during {
					activationStoppedFixture(t, h, "STOPPED=1\n")
				}
				return "", nil
			}
			client, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := waitActivation(client, queue, r.ID, h.readJSON); !errors.Is(err, context.Canceled) {
				t.Fatal("disconnected waiter did not cancel", err)
			}
			if err := activationPass(context.Background(), queue, h); err != nil {
				t.Fatal(err)
			}
			result, err := waitActivation(context.Background(), queue, r.ID, h.readJSON)
			if err != nil {
				t.Fatal(err)
			}
			if !result.OK || result.Started == nil || *result.Started != tc.started || !reflect.DeepEqual(verbs, tc.verbs) {
				t.Fatalf("result=%+v verbs=%v", result, verbs)
			}
			if result.Phase == "ready" {
				t.Fatal("absent readiness policy became verified")
			}
			if err := activationIdle(queue); err != nil {
				t.Fatal("completed queue still blocks staging", err)
			}
			body, err := os.ReadFile(filepath.Join(h.policy.AppDir, ".komizo-image-retention"))
			if err != nil || string(body) != "CURRENT=candidate\nPREVIOUS=previous\n" {
				t.Fatal("retention not durably committed", err)
			}
		})
	}
}

func TestRootActivationRefusesChangedInputsAndAmbiguousReplay(t *testing.T) {
	for _, field := range []string{"compose", "route", "policy", "revision", "journal", "interrupted"} {
		t.Run(field, func(t *testing.T) {
			queue, h, r := activationFixture(t)
			calls := 0
			h.run = func(context.Context, ...string) (string, error) { calls++; return "", nil }
			switch field {
			case "compose":
				os.WriteFile(filepath.Join(h.root, "srv", "example", "compose.yml"), []byte("{}"), 0600)
			case "route":
				os.WriteFile(r.RoutePath, []byte("changed"), 0600)
			case "policy":
				os.WriteFile(filepath.Join(h.policies, "example.json"), []byte("{}"), 0600)
			case "revision":
				os.WriteFile(filepath.Join(h.root, "srv", "example", ".env"), []byte("APP_VERSION=changed\n"), 0600)
			case "journal":
				var op workload.Operation
				h.readJSON(filepath.Join(h.releases, r.App, "operation.json"), &op)
				op.ID = strings.Repeat("f", 32)
				workload.WritePrivateJSON(filepath.Join(h.releases, r.App, "operation.json"), op)
			case "interrupted":
				if err := workload.RecordOperation(filepath.Join(h.releases, r.App, "operation.json"), r.App, r.Candidate, r.Previous, "activating", time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			if err := activationPass(context.Background(), queue, h); err != nil {
				t.Fatal(err)
			}
			result, err := waitActivation(context.Background(), queue, r.ID, h.readJSON)
			if err != nil {
				t.Fatal(err)
			}
			if result.OK || result.Started != nil || calls != 0 {
				t.Fatalf("changed request mutated host: %+v calls=%d", result, calls)
			}
			if field == "interrupted" {
				if result.Phase != "reconciliation_required" {
					t.Fatal(result.Phase)
				}
				if err := workload.RecordOperation(filepath.Join(h.releases, r.App, "operation.json"), r.App, r.Candidate, r.Previous, "admitted", time.Now()); err == nil {
					t.Fatal("ambiguous same candidate automatically replayed")
				}
			}
		})
	}
}

func TestRootActivationTimeoutAndFailedProxyRetainUncertainty(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(fmtBool(timeout), func(t *testing.T) {
			queue, h, r := activationFixture(t)
			calls := 0
			if timeout {
				r.Deadline = time.Now().Add(150 * time.Millisecond)
				var op workload.Operation
				h.readJSON(filepath.Join(h.releases, r.App, "operation.json"), &op)
				op.Deadline = r.Deadline
				workload.WritePrivateJSON(filepath.Join(h.releases, r.App, "operation.json"), op)
				workload.WritePrivateJSON(filepath.Join(queue, "pending.json"), r)
			}
			h.run = func(ctx context.Context, args ...string) (string, error) {
				calls++
				if timeout {
					<-ctx.Done()
					return "", ctx.Err()
				}
				if args[0] == "exec" {
					return "", errors.New("candidate invalid")
				}
				return "", nil
			}
			if err := activationPass(context.Background(), queue, h); err != nil {
				t.Fatal(err)
			}
			result, err := waitActivation(context.Background(), queue, r.ID, h.readJSON)
			if err != nil {
				t.Fatal(err)
			}
			if result.OK || result.Started != nil || result.Phase != "activation_failed" {
				t.Fatalf("manufactured certainty: %+v", result)
			}
			var op workload.Operation
			h.readJSON(filepath.Join(h.releases, r.App, "operation.json"), &op)
			if op.Phase != "activation_failed" {
				t.Fatal("failure acknowledgement missing", op.Phase)
			}
			if _, err := os.Stat(filepath.Join(h.root, "srv", "example", ".komizo-image-retention")); !os.IsNotExist(err) {
				t.Fatal("failed proxy accepted retention")
			}
			before := calls
			workload.WritePrivateJSON(filepath.Join(queue, "pending.json"), r)
			if err := activationPass(context.Background(), queue, h); err != nil {
				t.Fatal(err)
			}
			if calls != before {
				t.Fatal("uncertain external effect automatically repeated")
			}
		})
	}
}

func fmtBool(value bool) string {
	if value {
		return "deadline"
	}
	return "invalid proxy"
}

func TestRootRetentionPreservesRollbackOnSameCandidateAndRefusesLinks(t *testing.T) {
	_, h, r := activationFixture(t)
	h.policy, _ = workload.NewPolicy(r.App, filepath.Join(h.root, "srv", r.App), "ghcr.io/example/example-config", "edge")
	if err := h.Retain(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(h.policy.AppDir, ".komizo-image-retention")
	r.Previous = r.Candidate
	if err := h.Retain(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil || string(body) != "CURRENT=candidate\nPREVIOUS=previous\n" {
		t.Fatal("same candidate lost previous identity", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("retention must remain private", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(h.policy.AppDir, ".env"), path); err != nil {
		t.Fatal(err)
	}
	r.Previous = "previous"
	if err := h.Retain(context.Background(), r); err == nil {
		t.Fatal("unsafe retention destination accepted")
	}
}

func TestRootActivationProcessHelper(t *testing.T) {
	if os.Getenv("KOMIZO_ACTIVATION_PROCESS_FIXTURE") != "1" {
		return
	}
	root := os.Getenv("KOMIZO_ACTIVATION_FIXTURE_ROOT")
	h := &hostActivation{policies: filepath.Join(root, "policies"), releases: filepath.Join(root, "releases"), root: root, run: dockerReleaseRun, readBytes: os.ReadFile,
		readJSON: func(path string, out any) error {
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return json.Unmarshal(body, out)
		}}
	h.run = func(ctx context.Context, args ...string) (string, error) {
		out, err := dockerReleaseRun(ctx, args...)
		if err != nil {
			t.Logf("fixture adapter failed: %s: %v", strings.Join(args, " "), err)
		}
		return out, err
	}
	if err := activationPass(context.Background(), filepath.Join(root, "queue"), h); err != nil {
		t.Fatal(err)
	}
}

func TestRootActivationProcessCrashDoesNotReplayCompose(t *testing.T) {
	queue, h, r := activationFixture(t)
	bin := filepath.Join(h.root, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	boundary := filepath.Join(h.root, "compose-started")
	shim := `#!/bin/sh
case "$*" in
compose*)
 printf '%s\n' "$*" >> "$KOMIZO_ACTIVATION_FIXTURE_ROOT/compose-started"
 ticks=0
 while kill -0 "$PPID" 2>/dev/null && [ "$ticks" -lt 100 ]; do sleep 0.02; ticks=$((ticks+1)); done
 exit 1 ;;
*) exit 2 ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(shim), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRootActivationProcessHelper$", "-test.timeout=10s")
	cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin", "KOMIZO_ACTIVATION_PROCESS_FIXTURE=1", "KOMIZO_ACTIVATION_FIXTURE_ROOT="+h.root)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(boundary); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("actual Docker subprocess adapter never crossed the start boundary")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Kill only this test's known executor PID. The durable activating phase
	// precedes the external call, so a replacement worker must not run it again.
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	var op workload.Operation
	if err := h.readJSON(filepath.Join(h.releases, r.App, "operation.json"), &op); err != nil {
		t.Fatal(err)
	}
	if op.Phase != "activating" {
		t.Fatal("external effect started before durable admission", op.Phase)
	}
	before, err := os.ReadFile(boundary)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	h.run = func(context.Context, ...string) (string, error) { calls++; return "", nil }
	if err := activationPass(context.Background(), queue, h); err != nil {
		t.Fatal(err)
	}
	result, err := waitActivation(context.Background(), queue, r.ID, h.readJSON)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(boundary)
	if calls != 0 || string(before) != string(after) || result.OK || result.Phase != "reconciliation_required" {
		t.Fatal("restart replayed ambiguous external work", result, calls)
	}
}

func TestDockerAdapterBoundsActualSubprocessOutput(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\nexec head -c 2097153 /dev/zero\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := dockerReleaseRun(ctx, "fixture")
	if err == nil || output != "" {
		t.Fatal("Docker output exceeded its retention bound")
	}
	if ctx.Err() != nil {
		t.Fatal("output refusal waited for the operation deadline")
	}
}
