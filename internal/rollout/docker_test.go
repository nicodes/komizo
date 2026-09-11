package rollout

import (
	"context"
	"encoding/json"
	"os/exec"
	"slices"
	"testing"
	"time"
)

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
