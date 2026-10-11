package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// An explicitly selected local fixture exercises the real archive transport.
// Authenticated source binding has independent fixtures; no image is pushed.
func TestDeploymentDockerConfigurationCopy(t *testing.T) {
	image := os.Getenv("KOMIZO_DEPLOYMENT_FIXTURE_IMAGE")
	if image == "" {
		t.Skip("explicit immutable local configuration fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	run := func(args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, "docker", args...)
		var b bytes.Buffer
		cmd.Stdout = &b
		cmd.Stderr = &b
		err := cmd.Run()
		return b.String(), err
	}
	id, err := run("image", "inspect", "--format", "{{.Id}}", image)
	id = strings.TrimSpace(id)
	if err != nil || !strings.HasPrefix(id, "sha256:") {
		t.Fatal("local fixture image is unavailable")
	}
	cid, err := run("create", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--entrypoint", "/never-run", id)
	cid = strings.TrimSpace(cid)
	if err != nil || len(cid) != 64 {
		t.Fatal("fixture create failed")
	}
	defer run("rm", "--force", "--volumes", cid)
	compose, hosts, err := copyDeploymentConfiguration(ctx, cid)
	if err != nil {
		t.Fatal(err)
	}
	if len(compose) == 0 || len(compose) > 1<<20 || len(hosts) > 16<<10 {
		t.Fatal("configuration archive did not preserve its bounds")
	}
	proof, _ := json.Marshal(map[string]any{"result": "passed", "immutable_image": id, "compose_sha256": deploymentHash(compose), "hostnames_sha256": deploymentHash(hosts), "container_started": false, "host_ports": false})
	t.Log(string(proof))
}
