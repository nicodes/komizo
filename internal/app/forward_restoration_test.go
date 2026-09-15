package app

import (
	"strings"
	"testing"

	"github.com/nicodes/komizo/scripts"
)

func TestForwardRestorationKeepsTheEstablishedComposeDeployAuthority(t *testing.T) {
	source := scripts.AlpineScript
	for _, abandoned := range []string{"rollout-__APP_NAME__", "ROLLOUT_PROFILE", "/var/lib/komizo/rollouts/"} {
		if strings.Contains(source, abandoned) {
			t.Fatalf("abandoned journaled rollout authority remains: %q", abandoned)
		}
	}
	if !strings.Contains(source, "docker compose up -d --remove-orphans") || !strings.Contains(source, "/run/komizo/deploy-__APP_NAME__.lock") {
		t.Fatal("established app-scoped Compose deployment path is not reachable")
	}
}
