package rollout

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestExecutorDoesNotInheritRemoteDockerContext(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh unavailable")
	}
	for _, key := range []string{"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION"} {
		t.Setenv(key, "synthetic-must-not-be-used")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := command(ctx, "sh", "-c", `test -z "${DOCKER_HOST+x}${DOCKER_CONTEXT+x}${DOCKER_TLS_VERIFY+x}${DOCKER_CERT_PATH+x}${DOCKER_API_VERSION+x}"`)
	if err != nil {
		t.Fatal("executor inherited remote Docker configuration")
	}
}

func TestExecutorRequiresBoundedContext(t *testing.T) {
	if _, err := command(context.Background(), "must-not-be-executed"); err == nil {
		t.Fatal("unbounded process accepted")
	}
}
