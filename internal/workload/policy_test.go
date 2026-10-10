package workload

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testPolicy(t *testing.T) Policy {
	t.Helper()
	p, err := NewPolicy("example", t.TempDir(), "ghcr.io/owner/example-config", "edge")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

const basic = `services:
  example-gate:
    image: ghcr.io/owner/example-gate:${APP_VERSION:?}
    networks: [shared]
  api:
    image: ghcr.io/owner/example-api:${APP_VERSION}
    env_file: [secrets.env]
    volumes: [files:/data]
volumes:
  files:
networks:
  shared:
    name: edge
    external: true
`

func TestValidWorkloadIsCanonicalAndBounded(t *testing.T) {
	out, err := Validate(strings.NewReader(basic), testPolicy(t), "commit123")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["name"] != "example" {
		t.Fatal("host project name was not selected")
	}
	services := doc["services"].(map[string]any)
	gate := services["example-gate"].(map[string]any)
	if gate["image"] != "ghcr.io/owner/example-gate:commit123" || gate["pids_limit"] != float64(128) || gate["logging"] == nil {
		t.Fatal("image identity or runtime bounds missing")
	}
	if gate["cap_drop"].([]any)[0] != "ALL" {
		t.Fatal("capabilities were not dropped")
	}
}

func TestHostPrivilegesAndForeignResourcesAreRefused(t *testing.T) {
	cases := map[string]string{
		"privileged":       "    privileged: true\n",
		"host-network":     "    network_mode: host\n",
		"host-pid":         "    pid: host\n",
		"host-ipc":         "    ipc: host\n",
		"devices":          "    devices: [/dev/kvm]\n",
		"docker-socket":    "    volumes: [/var/run/docker.sock:/var/run/docker.sock]\n",
		"root-bind":        "    volumes: [/:/host]\n",
		"external-config":  "    extends: /etc/private.yml\n",
		"build":            "    build: /srv/other\n",
		"hooks":            "    post_start: [{command: dangerous, privileged: true}]\n",
		"provider":         "    provider: {type: model}\n",
		"foreign-env":      "    env_file: [/srv/other/secrets.env]\n",
		"env-traversal":    "    env_file: [secrets/../../other.env]\n",
		"foreign-image":    "    image: ghcr.io/other/evil:commit123\n",
		"grant-caps":       "    cap_add: [SYS_ADMIN]\n",
		"disable-security": "    security_opt: [seccomp:unconfined]\n",
		"custom-name":      "    container_name: other-api\n",
		"extra-hosts":      "    extra_hosts: [host:host-gateway]\n",
		"unbounded-pids":   "    pids_limit: -1\n",
	}
	for name, field := range cases {
		t.Run(name, func(t *testing.T) {
			input := "services:\n  api:\n    image: ghcr.io/owner/example-api:commit123\n" + field
			// Avoid a duplicate image key so the image policy itself is exercised.
			if name == "foreign-image" {
				input = "services:\n  api:\n" + field
			}
			if _, err := Validate(strings.NewReader(input), testPolicy(t), "commit123"); err == nil {
				t.Fatal("unsafe workload accepted")
			}
		})
	}
	resources := []string{
		"volumes:\n  files: {external: true, name: other_data}\n",
		"volumes:\n  files: {driver_opts: {type: none, device: /, o: bind}}\n",
		"networks:\n  shared: {external: true, name: other_default}\n",
		"networks:\n  shared: {name: other_default}\n",
		"networks:\n  shared: {driver: host}\n",
		"include: /etc/private.yml\n",
		"secrets:\n  private: {file: /etc/private}\n",
		"name: other\n",
	}
	for _, resource := range resources {
		if _, err := Validate(strings.NewReader("services:\n  api:\n    image: ghcr.io/owner/example-api:commit123\n"+resource), testPolicy(t), "commit123"); err == nil {
			t.Fatalf("unsafe resource accepted: %s", resource)
		}
	}
}

func TestUntrustedYAMLHasNoTransitiveSemantics(t *testing.T) {
	for _, input := range []string{
		"services: &services {api: {image: ghcr.io/owner/example-api:commit123}}\n",
		"services: {api: {image: a, image: b}}\n",
		"services: {}\n---\nservices: {}\n",
		"services: {api: {<<: {privileged: true}}}\n",
		"services: !custom {}\n",
		strings.Repeat("a", MaxBytes+1),
	} {
		if _, err := Validate(strings.NewReader(input), testPolicy(t), "commit123"); err == nil {
			t.Fatal("ambiguous or oversized workload accepted")
		}
	}
}

func TestAppSecretsCannotFollowSymlinksOutOfApp(t *testing.T) {
	p := testPolicy(t)
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("PRIVATE"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(p.AppDir, "secrets.env")); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(strings.NewReader(basic), p, "commit123"); err == nil {
		t.Fatal("escaping env_file symlink accepted")
	}
}

func TestOnlyGatewayCanJoinIngress(t *testing.T) {
	input := strings.Replace(basic, "    env_file: [secrets.env]", "    env_file: [secrets.env]\n    networks: [shared]", 1)
	if _, err := Validate(strings.NewReader(input), testPolicy(t), "commit123"); err == nil {
		t.Fatal("backend joined shared ingress")
	}
}

func TestPostgresCapabilitiesAndPinnedDependencies(t *testing.T) {
	input := "services:\n  postgres:\n    image: postgres@sha256:" + strings.Repeat("a", 64) + "\n    cap_add: [CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID]\n    env_file: [secrets/postgres-owner.env]\n"
	if _, err := Validate(strings.NewReader(input), testPolicy(t), "commit123"); err != nil {
		t.Fatal(err)
	}
	for _, image := range []string{"postgres:latest", "redis:7-alpine", "postgres@sha256:bad", "ghcr.io/owner/example-api:previous"} {
		input := "services:\n  api:\n    image: " + image + "\n"
		if _, err := Validate(strings.NewReader(input), testPolicy(t), "commit123"); err == nil {
			t.Fatalf("unpinned or wrong revision image accepted: %s", image)
		}
	}
}

func TestDefaultNetworkCannotBypassGatewayRestriction(t *testing.T) {
	for _, attachment := range []string{"", "    networks: [default]\n"} {
		input := "services:\n  api:\n    image: ghcr.io/owner/example-api:commit123\n" + attachment + "networks:\n  default: {external: true, name: edge}\n"
		if _, err := Validate(strings.NewReader(input), testPolicy(t), "commit123"); err == nil {
			t.Fatal("default network bypassed ingress restriction")
		}
	}
}

func TestVolumeNamesRemainInAppNamespace(t *testing.T) {
	for _, name := range []string{"example_files", "other_files"} {
		input := strings.Replace(basic, "  files:\n", "  files: {name: "+name+"}\n", 1)
		_, err := Validate(strings.NewReader(input), testPolicy(t), "commit123")
		if (err == nil) != strings.HasPrefix(name, "example_") {
			t.Fatalf("volume ownership validation: %s: %v", name, err)
		}
	}
}

func TestAPIHasNoDatabaseOwnerSecretAuthority(t *testing.T) {
	for _, path := range []string{"secrets/postgres-owner.env", "postgres-owner.env", "secrets/current/migrate.env"} {
		input := "services:\n  api:\n    image: ghcr.io/owner/example-api:commit123\n    env_file: [" + path + "]\n"
		if _, err := Validate(strings.NewReader(input), testPolicy(t), "commit123"); err == nil {
			t.Fatal("API received another service's secret")
		}
	}
}
