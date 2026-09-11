package main

import (
	"os"
	"testing"

	"github.com/nicodes/komizo/box"
)

func TestRolloutDoesNotExpandSignedOperations(t *testing.T) {
	for _, op := range []string{"rollout", "app.rollout", "gateway", "gateway.swap"} {
		if box.KnownOp(op) || box.Applies(op) {
			t.Fatalf("operator-only action admitted to signed protocol: %s", op)
		}
	}
}

func TestLocalBoxRolloutRequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("nonroot refusal control requires a nonroot test user")
	}
	if err := runLocalRollout([]string{"--help"}); err == nil {
		t.Fatal("nonroot operator rollout accepted")
	}
}
