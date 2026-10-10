package box

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPreviewIngressRefusesForeignNetworkAndDoesNotAttach(t *testing.T) {
	calls := 0
	run := func(_ context.Context, _ string, args ...string) (string, error) {
		calls++
		return "another-preview", nil
	}
	if _, err := ensurePreviewIngress(context.Background(), run, "prizm-pr-7", "komizo-proxy"); err == nil || calls != 1 {
		t.Fatalf("foreign network accepted or changed: %v, %d", err, calls)
	}
	calls = 0
	if err := removePreviewIngress(context.Background(), run, "prizm-pr-7", "komizo-proxy"); err == nil || calls != 1 {
		t.Fatalf("foreign network removed: %v, %d", err, calls)
	}
}

func TestPreviewIngressCreatesInternalNetworkAndDetachesOnlyItsProxy(t *testing.T) {
	exists := false
	var calls []string
	run := func(_ context.Context, _ string, args ...string) (string, error) {
		call := strings.Join(args, " ")
		calls = append(calls, call)
		if args[0] == "network" && args[1] == "inspect" {
			if !exists {
				return "", errors.New("missing")
			}
			return "prizm-pr-7", nil
		}
		if args[0] == "network" && args[1] == "create" {
			exists = true
		}
		if args[0] == "inspect" {
			if len(calls) < 4 {
				return "edge\nother-preview-ingress", nil
			}
			return "edge\nprizm-pr-7-ingress\nother-preview-ingress", nil
		}
		return "", nil
	}
	network, err := ensurePreviewIngress(context.Background(), run, "prizm-pr-7", "komizo-proxy")
	if err != nil || network != "prizm-pr-7-ingress" {
		t.Fatalf("%s %v", network, err)
	}
	if err := removePreviewIngress(context.Background(), run, "prizm-pr-7", "komizo-proxy"); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(calls, "\n")
	for _, want := range []string{"network create --internal --label io.komizo.preview=prizm-pr-7 prizm-pr-7-ingress", "network connect prizm-pr-7-ingress komizo-proxy", "network disconnect --force prizm-pr-7-ingress komizo-proxy", "network rm prizm-pr-7-ingress"} {
		if !strings.Contains(all, want) {
			t.Fatalf("missing %s: %s", want, all)
		}
	}
	if strings.Contains(all, "network disconnect --force other-preview") {
		t.Fatal("neighbour detached")
	}
}
