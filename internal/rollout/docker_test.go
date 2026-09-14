package rollout

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestAbsentCandidateCleanupDoesNotRequireApplicationLifecycle(t *testing.T) {
	directory := t.TempDir()
	docker := filepath.Join(directory, "docker")
	fake := `#!/bin/sh
if [ "${FAKE_PRESENT:-}" = 1 ]; then
	case "$*" in
		*"container ls"*) printf '%s\n' container-id ;;
		*"container inspect"*) /bin/cat "$FAKE_INSPECTION" ;;
		*) exit 2 ;;
	esac
fi
`
	if err := os.WriteFile(docker, []byte(fake), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)

	store, err := OpenStore(context.Background(), filepath.Join(directory, "state"), time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	instance := Instance{
		Name:       "kmz-0123456789abcdef0123456789abcdef01234567",
		App:        "fixture",
		Service:    "assets",
		Generation: "generation",
		Identity:   "identity",
		Mode:       "one-shot",
	}
	artifact := instance.Name + ".json"
	if err := store.WritePrivate(artifact, []byte("{}")); err != nil {
		t.Fatal(err)
	}

	proof := Retirement{}
	for _, action := range []string{"abort-quiesce", "seal", "drain", "stop", "remove"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		proof, err = (&Docker{App: instance.App, Store: store}).Lifecycle(ctx, instance, action, proof)
		cancel()
		if err != nil {
			t.Fatalf("%s absent one-shot candidate: %v", action, err)
		}
	}
	if !proof.Absent || proof.Stage != "remove" {
		t.Fatalf("absence cleanup proof = %+v", proof)
	}
	if _, err := os.Stat(store.Path(artifact)); !os.IsNotExist(err) {
		t.Fatalf("private candidate artifact remains: %v", err)
	}

	present := container{ID: "container-id"}
	present.Config.Labels = labels(instance)
	present.State.StartedAt = "2026-09-13T00:00:00Z"
	present.State.Running = true
	present.State.Status = "running"
	body, err := json.Marshal([]container{present})
	if err != nil {
		t.Fatal(err)
	}
	inspection := filepath.Join(directory, "inspection.json")
	if err := os.WriteFile(inspection, body, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_PRESENT", "1")
	t.Setenv("FAKE_INSPECTION", inspection)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	_, err = (&Docker{App: instance.App, Store: store}).Lifecycle(ctx, instance, "abort-quiesce", Retirement{})
	cancel()
	if err == nil {
		t.Fatal("present candidate without an application lifecycle was accepted")
	}
}

func TestRemovalNeverSubstitutesForcedKillForApplicationRetirement(t *testing.T) {
	instance := Instance{Name: "kmz-fixture"}
	for _, status := range []string{"created", "exited"} {
		current := &container{}
		current.State.Status = status
		args, err := removalArguments(instance, current)
		if err != nil || !slices.Equal(args, []string{"rm", "--volumes", instance.Name}) {
			t.Fatalf("clean cleanup=%v %v", args, err)
		}
	}
	for _, mutate := range []func(*container){
		func(c *container) { c.State.Running = true },
		func(c *container) { c.State.Restarting = true },
		func(c *container) { c.State.Dead = true },
		func(c *container) { c.State.OOMKilled = true },
		func(c *container) { c.State.ExitCode = 1 },
		func(c *container) { c.State.Status = "" },
		func(c *container) { c.State.Status = "paused" },
	} {
		current := &container{}
		current.State.Status = "exited"
		mutate(current)
		if args, err := removalArguments(instance, current); err == nil || len(args) != 0 {
			t.Fatal("unproved retirement authorized removal")
		}
	}
}

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

func TestCandidateStartCannotPullAfterCapacityGate(t *testing.T) {
	args := composeStartArguments("/private/candidate.json", "kmz-fixture")
	want := []string{"--file", "/private/candidate.json", "up", "--detach", "--no-deps", "--no-recreate", "--pull", "never", "kmz-fixture"}
	if !slices.Equal(args, want) {
		t.Fatalf("candidate start arguments = %v, want %v", args, want)
	}
}

func TestImagePullDiagnosticsAreBoundedFixedAndRedacted(t *testing.T) {
	secret := "private.example/owner/unpublished@sha256:" + strings.Repeat("a", 64)
	token := "ghp_secret-material"
	tests := []struct {
		name       string
		diagnostic string
		want       error
	}{
		{"access", `Error response from daemon: Head "https://` + secret + `?token=` + token + `": unauthorized: authentication required`, errImageRegistryAccess},
		{"network", `Get "https://` + secret + `": dial tcp: no such host`, errImageRegistryNetwork},
		{"digest", `manifest unknown: ` + secret + ` not found`, errImageDigestUnavailable},
		{"unknown", `daemon rejected ` + secret + ` with ` + token, errImagePullUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := classifyImagePullFailure(context.Background(), []byte(test.diagnostic))
			if !errors.Is(err, test.want) {
				t.Fatalf("diagnostic = %v, want %v", err, test.want)
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), token) {
				t.Fatalf("sensitive diagnostic escaped: %v", err)
			}
		})
	}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := classifyImagePullFailure(ctx, []byte("unauthorized")); !errors.Is(err, errImagePullDeadline) {
		t.Fatalf("operation deadline was not authoritative: %v", err)
	}

	var bounded diagnosticBuffer
	payload := bytes.Repeat([]byte("x"), 128<<10)
	if n, err := bounded.Write(payload); err != nil || n != len(payload) || bounded.Len() != 64<<10 {
		t.Fatalf("bounded diagnostic accepted=%d retained=%d err=%v", n, bounded.Len(), err)
	}
}

func TestStagePublishesSafePullCategoryWithoutRawDaemonOutput(t *testing.T) {
	directory := t.TempDir()
	docker := filepath.Join(directory, "docker")
	private := "private.example/owner/unpublished@sha256:" + strings.Repeat("b", 64)
	token := "ghp_must-not-escape"
	fake := `#!/bin/sh
case "$*" in
  *"container ls"*) exit 0 ;;
  *"image inspect"*) exit 1 ;;
  *" pull --quiet "*) printf '%s\n' 'Error response from daemon: Head "https://PRIVATE?token=SECRET": denied: denied' >&2; exit 1 ;;
  *) exit 2 ;;
esac
`
	fake = strings.ReplaceAll(strings.ReplaceAll(fake, "PRIVATE", private), "SECRET", token)
	if err := os.WriteFile(docker, []byte(fake), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	store, err := OpenStore(context.Background(), filepath.Join(directory, "state"), time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	instance := Instance{Name: "kmz-0123456789abcdef0123456789abcdef01234567", App: "fixture", Service: "gate", Generation: "generation", Identity: "identity", Mode: "request"}
	compose, _ := json.Marshal(map[string]any{"services": map[string]any{instance.Name: map[string]any{"image": private}}})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	err = (&Docker{App: instance.App, Store: store}).Stage(ctx, instance, compose)
	cancel()
	if !errors.Is(err, errImageRegistryAccess) {
		t.Fatalf("stage category = %v", err)
	}
	if strings.Contains(err.Error(), private) || strings.Contains(err.Error(), token) {
		t.Fatalf("private pull details escaped: %v", err)
	}
	if _, statErr := os.Stat(store.Path(instance.Name + ".json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed stage wrote candidate artifact: %v", statErr)
	}
}

func TestRegistryAuthenticationUsesOnlyPrivateConfigAndStdin(t *testing.T) {
	directory := t.TempDir()
	docker := filepath.Join(directory, "docker")
	argsPath := filepath.Join(directory, "args")
	stdinPath := filepath.Join(directory, "stdin")
	configPath := filepath.Join(directory, "config-path")
	fake := `#!/bin/sh
printf '%s\n' "$*" > "$FAKE_ARGS"
printf '%s' "$DOCKER_CONFIG" > "$FAKE_CONFIG_PATH"
/bin/cat > "$FAKE_STDIN"
`
	if err := os.WriteFile(docker, []byte(fake), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	t.Setenv("FAKE_ARGS", argsPath)
	t.Setenv("FAKE_STDIN", stdinPath)
	t.Setenv("FAKE_CONFIG_PATH", configPath)
	t.Setenv("DOCKER_CONFIG", filepath.Join(directory, "ambient-must-not-be-used"))
	privateConfig := filepath.Join(directory, "private-config")
	if err := os.Mkdir(privateConfig, 0o700); err != nil {
		t.Fatal(err)
	}
	token := []byte("workflow-token")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	err := (&Docker{DockerConfig: privateConfig}).authenticate(ctx, "registry.example", "workflow-actor", token)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	args, _ := os.ReadFile(argsPath)
	stdin, _ := os.ReadFile(stdinPath)
	config, _ := os.ReadFile(configPath)
	if strings.Contains(string(args), string(token)) || string(stdin) != "workflow-token\n" || string(config) != privateConfig {
		t.Fatalf("registry credential placement args=%q stdin=%q config=%q", args, stdin, config)
	}
	if string(args) != "--host unix:///var/run/docker.sock login registry.example --username workflow-actor --password-stdin\n" {
		t.Fatalf("registry login authority = %q", args)
	}
}

func TestPrivateApplicationNetworkPreservesNATControlWithoutPublicRouting(t *testing.T) {
	for _, internal := range []bool{false, true} {
		inspection := map[string]any{"Name": "sample-private", "Driver": "bridge", "Scope": "local", "Internal": internal,
			"Labels": map[string]string{"io.komizo.app": "sample"}, "Options": map[string]string{}}
		body, _ := json.Marshal([]any{inspection})
		if err := validateApplicationNetwork(body, "sample", "sample-private"); err != nil {
			t.Fatalf("owned bridge internal=%v was rejected: %v", internal, err)
		}
	}
	for _, mutate := range []func(map[string]any){
		func(v map[string]any) { delete(v, "Internal") },
		func(v map[string]any) { v["Name"] = "another-network" },
		func(v map[string]any) { v["Driver"] = "macvlan" },
		func(v map[string]any) { v["Scope"] = "swarm" },
		func(v map[string]any) { v["Labels"] = map[string]string{"io.komizo.app": "another-app"} },
		func(v map[string]any) {
			v["Options"] = map[string]string{"com.docker.network.bridge.gateway_mode_ipv4": "nat-unprotected"}
		},
		func(v map[string]any) {
			v["Options"] = map[string]string{"com.docker.network.bridge.gateway_mode_ipv6": "routed"}
		},
		func(v map[string]any) {
			v["Options"] = map[string]string{"com.docker.network.bridge.gateway_mode_ipv4": "isolated"}
		},
	} {
		inspection := map[string]any{"Name": "sample-private", "Driver": "bridge", "Scope": "local", "Internal": false,
			"Labels": map[string]string{"io.komizo.app": "sample"}}
		mutate(inspection)
		body, _ := json.Marshal([]any{inspection})
		if err := validateApplicationNetwork(body, "sample", "sample-private"); err == nil {
			t.Fatal("unscoped or directly routed application network was accepted")
		}
	}
}
