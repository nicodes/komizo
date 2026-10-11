package app

import (
	"strings"
	"testing"

	"github.com/nicodes/komizo/scripts"
)

func TestForwardRestorationUsesOneTypedDeployAuthority(t *testing.T) {
	source := scripts.AlpineScript
	for _, abandoned := range []string{"rollout-__APP_NAME__", "ROLLOUT_PROFILE", "/var/lib/komizo/rollouts/"} {
		if strings.Contains(source, abandoned) {
			t.Fatalf("abandoned journaled rollout authority remains: %q", abandoned)
		}
	}
	if !strings.Contains(source, "komizo-box workload deployment-submit --policy") || !strings.Contains(source, "komizo-box workload activation-wait --id") {
		t.Fatal("app-scoped typed deployment path is not reachable")
	}
	body := between(t, source, `cat > "$DEPLOY_BIN.tmp" <<'KOMIZO_DEPLOY_EOF'`, "KOMIZO_DEPLOY_EOF")
	if strings.Contains(body, "docker compose") || strings.Contains(body, "activation-submit") {
		t.Fatal("generated wrapper retains a second staging authority")
	}
}
