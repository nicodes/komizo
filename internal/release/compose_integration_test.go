package release

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

// An explicitly enabled real Compose control. The Compose binary runs without
// networking or a Docker socket; only the outer local daemon creates the test
// container. No host application files, volumes or secrets are mounted.
func TestPinnedComposeNormalization(t *testing.T) {
	if os.Getenv("KOMIZO_TEST_COMPOSE") != "1" {
		t.Skip("set KOMIZO_TEST_COMPOSE=1 for isolated Docker/Compose normalization control")
	}
	const composeImage = "docker/compose-bin@sha256:023f617349e1791bc03b6d79ac7cc469b2e26c3aa8614c615389aa364a09c6aa"
	normalize := func(yaml string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "docker", "--host", "unix:///var/run/docker.sock", "run", "--rm", "-i",
			"--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
			"--entrypoint", "/docker-compose", composeImage, "--project-name", "komizo-fixture",
			"--project-directory", "/", "--file", "-", "config", "--format", "json", "--no-interpolate", "--no-env-resolution")
		cmd.Stdin = strings.NewReader(yaml)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			// This fixture has no sensitive values, but normal resolver tooling
			// must never reflect Compose stderr into public deployment logs.
			t.Fatalf("pinned Compose fixture failed: %v (%s)", err, stderr.String())
		}
		return stdout.Bytes()
	}
	yaml := `services:
  ui:
    image: example/ui@sha256:` + strings.Repeat("a", 64) + `
    networks: [private]
  api:
    image: example/api@sha256:` + strings.Repeat("b", 64) + `
    networks: [private]
    secrets: [db_password]
  db:
    image: example/db@sha256:` + strings.Repeat("c", 64) + `
    networks: [private]
    volumes: [data:/var/lib/db]
networks:
  private:
    internal: true
volumes:
  data: {}
secrets:
  db_password:
    external: true
x-komizo:
  version: 1
  secret_versions:
    db_password: fixture-version-1
  services:
    ui:
      mode: http
      port: 80
      ready_path: /readyz
      candidate_safe: true
    api:
      mode: http
      port: 8080
      ready_path: /readyz
      candidate_safe: true
    db:
      mode: persistent
`
	normalized := normalize(yaml)
	before, err := Resolve(normalized, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatalf("canonical synthetic Compose fixture refused: %v\n%s", err, normalized)
	}
	after, err := Resolve(normalize(strings.Replace(yaml, "example/ui@sha256:"+strings.Repeat("a", 64), "example/ui@sha256:"+strings.Repeat("d", 64), 1)), bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Compare(before.Inventory, after.Inventory)
	want := []Change{{Service: "api", Kind: Unchanged}, {Service: "db", Kind: Unchanged}, {Service: "ui", Kind: Changed, Reasons: []Component{Image}}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("canonical comparison: %#v, %v", got, err)
	}
}
