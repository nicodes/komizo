package box

import (
	"go.yaml.in/yaml/v3"
	"strings"
	"testing"
)

func TestPreviewPrivateRuntimeHasNoCredentialsOrPublicNetwork(t *testing.T) {
	cfg := previewTestConfig(t)
	rec := PreviewRecord{V: 1, App: "example", PR: 12, Project: "example-pr-12", DBName: "example_pr_12", DBPassword: "synthetic-db-password", Images: []string{"ghcr.io/you/example-gate:head", "ghcr.io/you/example-api:head", "ghcr.io/you/example-renderer:head"}}
	raw := previewCompose(rec, cfg.Knob, "edge", true, PreviewDBContainer)
	var compose struct {
		Services map[string]struct {
			Environment map[string]string `yaml:"environment"`
			EnvFile     []string          `yaml:"env_file"`
			Networks    []string          `yaml:"networks"`
			Ports       []string          `yaml:"ports"`
			ReadOnly    bool              `yaml:"read_only"`
			CapDrop     []string          `yaml:"cap_drop"`
			Security    []string          `yaml:"security_opt"`
		}
		Networks map[string]struct {
			Internal bool   `yaml:"internal"`
			Name     string `yaml:"name"`
		}
	}
	if err := yaml.Unmarshal([]byte(raw), &compose); err != nil {
		t.Fatal(err)
	}
	runtime := compose.Services["example-renderer"]
	if len(runtime.Environment) != 0 || len(runtime.EnvFile) != 0 || len(runtime.Ports) != 0 || strings.Join(runtime.Networks, ",") != "runtime" {
		t.Fatalf("runtime gained authority: %+v", runtime)
	}
	if !runtime.ReadOnly || strings.Join(runtime.CapDrop, ",") != "ALL" || strings.Join(runtime.Security, ",") != "no-new-privileges:true" {
		t.Fatal("runtime lacks container restrictions")
	}
	api := compose.Services["example-api"]
	if len(api.EnvFile) != 1 || api.Environment["RUNTIME_DATABASE_URL"] == "" || strings.Join(api.Networks, ",") != "backend,runtime" {
		t.Fatalf("API lost its private connections: %+v", api)
	}
	if !compose.Networks["runtime"].Internal || compose.Networks["runtime"].Name != "example-pr-12-runtime" {
		t.Fatal("runtime network escaped the PR namespace")
	}
	if strings.Join(compose.Services["example-pr-12-gate"].Networks, ",") != "shared,backend" {
		t.Fatal("gateway joined runtime network")
	}
}
func TestPreviewRuntimeMemoryReservationMatchesRenderedLimit(t *testing.T) {
	cfg := previewTestConfig(t)
	cfg.Knob.MemLimit = "128m"
	cfg.Knob.body = "MEM_LIMIT.example.renderer=384m\n"
	images := []string{"ghcr.io/you/example-gate:head", "ghcr.io/you/example-api:head", "ghcr.io/you/example-renderer:head"}
	reserved, err := previewImagesMemoryReservation(cfg.Knob, "example", images)
	if err != nil || reserved != 640<<20 {
		t.Fatal(reserved, err)
	}
	raw := previewCompose(PreviewRecord{App: "example", Project: "example-pr-12", Images: images}, cfg.Knob, "edge", false, "")
	if !strings.Contains(raw, "mem_limit: 384m") {
		t.Fatal("runtime memory not enforced")
	}
	for _, test := range []struct{ image, want string }{{"ghcr.io/you/foo-renderer:head", "renderer"}, {"ghcr.io/you/foo-runtime@sha256:abcd", "runtime"}, {"ghcr.io/you/foo-worker:head", ""}, {"ghcr.io/you/foo-api:head", ""}} {
		if got := previewRuntimeRole(test.image); got != test.want {
			t.Fatalf("%s: %s", test.image, got)
		}
	}
}
