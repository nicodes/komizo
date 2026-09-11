package release

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func modelFixture() map[string]any {
	services := map[string]any{}
	policies := map[string]any{}
	for _, name := range []string{"ui", "api", "db"} {
		services[name] = map[string]any{
			"image":    "example/" + name + "@sha256:" + strings.Repeat("a", 64),
			"networks": map[string]any{"private": map[string]any{}},
		}
		policies[name] = map[string]any{"mode": "persistent"}
		if name != "db" {
			policies[name] = map[string]any{"mode": "request", "port": 8080, "ready_path": "/readyz", "candidate_safe": true}
		}
	}
	return map[string]any{
		"services": services,
		"networks": map[string]any{"private": map[string]any{"internal": true}},
		"x-komizo": map[string]any{"version": 1, "services": policies},
	}
}

func resolveFixture(t *testing.T, fixture map[string]any) *Model {
	t.Helper()
	data, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	model, err := Resolve(data, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return model
}

func fixtureService(f map[string]any, name string) map[string]any {
	return f["services"].(map[string]any)[name].(map[string]any)
}

func fixturePolicy(f map[string]any, name string) map[string]any {
	return f["x-komizo"].(map[string]any)["services"].(map[string]any)[name].(map[string]any)
}

func TestResolveSelectiveImagesAndPrivateConfig(t *testing.T) {
	f := modelFixture()
	before := resolveFixture(t, f)
	fixtureService(f, "ui")["image"] = "example/ui@sha256:" + strings.Repeat("b", 64)
	after := resolveFixture(t, f)
	got, err := Compare(before.Inventory, after.Inventory)
	want := []Change{{Service: "api", Kind: Unchanged}, {Service: "db", Kind: Unchanged}, {Service: "ui", Kind: Changed, Reasons: []Component{Image}}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, %v; want %#v", got, err, want)
	}
	fixtureService(f, "api")["environment"] = map[string]any{"PRIVATE_VALUE": "synthetic-sensitive-value"}
	private := resolveFixture(t, f)
	encoded, _ := json.Marshal(private)
	if bytes.Contains(encoded, []byte("synthetic-sensitive-value")) || bytes.Contains(encoded, []byte("PRIVATE_VALUE")) {
		t.Fatal("model exports raw environment")
	}
	if private.Inventory["api"].Runtime == after.Inventory["api"].Runtime {
		t.Fatal("environment change did not affect runtime")
	}
	data, _ := json.Marshal(f)
	otherKey, err := Resolve(data, bytes.Repeat([]byte{2}, 32))
	if err != nil || otherKey.Inventory["api"].Runtime == private.Inventory["api"].Runtime {
		t.Fatal("runtime token is not keyed")
	}
}

func TestResolveSecretVersionsAreScoped(t *testing.T) {
	f := modelFixture()
	f["secrets"] = map[string]any{"db_password": map[string]any{"external": true}}
	f["x-komizo"].(map[string]any)["secret_versions"] = map[string]any{"db_password": "version-1"}
	fixtureService(f, "api")["secrets"] = []any{map[string]any{"source": "db_password", "target": "db_password"}}
	before := resolveFixture(t, f)
	f["x-komizo"].(map[string]any)["secret_versions"] = map[string]any{"db_password": "version-2"}
	after := resolveFixture(t, f)
	got, err := Compare(before.Inventory, after.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	want := []Change{{Service: "api", Kind: Changed, Reasons: []Component{Secrets}}, {Service: "db", Kind: Unchanged}, {Service: "ui", Kind: Unchanged}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	f["secrets"].(map[string]any)["db_password"] = map[string]any{"file": "/private/new-password-file"}
	changedSource := resolveFixture(t, f)
	if changedSource.Inventory["api"].Secrets == after.Inventory["api"].Secrets {
		t.Fatal("secret source descriptor change ignored")
	}
}

func TestResolveResourceAndExplicitDependencyChanges(t *testing.T) {
	f := modelFixture()
	fixturePolicy(f, "api")["restart_on"] = []any{"db"}
	fixturePolicy(f, "ui")["restart_on"] = []any{"api"}
	before := resolveFixture(t, f)
	fixtureService(f, "db")["image"] = "example/db@sha256:" + strings.Repeat("b", 64)
	after := resolveFixture(t, f)
	if after.Inventory["api"].Dependencies == before.Inventory["api"].Dependencies || after.Inventory["ui"].Dependencies == before.Inventory["ui"].Dependencies {
		t.Fatal("explicit transitive invalidation missing")
	}
	f["networks"].(map[string]any)["private"] = map[string]any{"internal": false}
	newNetwork := resolveFixture(t, f)
	for _, name := range []string{"api", "db", "ui"} {
		if newNetwork.Inventory[name].Runtime == after.Inventory[name].Runtime {
			t.Fatalf("%s ignored referenced network change", name)
		}
	}
	// Unused resources must not invalidate services that never reference them.
	f["networks"].(map[string]any)["unused"] = map[string]any{"internal": true}
	if !sameAnalysis(newNetwork, resolveFixture(t, f)) {
		t.Fatal("unused network invalidated a service")
	}
}

func TestResolveCanonicalOrder(t *testing.T) {
	f := modelFixture()
	fixturePolicy(f, "ui")["restart_on"] = []any{"api", "db"}
	first := resolveFixture(t, f)
	fixturePolicy(f, "ui")["restart_on"] = []any{"db", "api"}
	if !sameAnalysis(first, resolveFixture(t, f)) {
		t.Fatal("dependency order changed semantic identity")
	}
	compact, _ := json.Marshal(f)
	pretty, _ := json.MarshalIndent(f, "", "  ")
	a, errA := Resolve(compact, bytes.Repeat([]byte{1}, 32))
	b, errB := Resolve(pretty, bytes.Repeat([]byte{1}, 32))
	if errA != nil || errB != nil || !sameAnalysis(a, b) {
		t.Fatal("JSON formatting changed identity")
	}
}

func sameAnalysis(a, b *Model) bool {
	return reflect.DeepEqual(a.Inventory, b.Inventory) && reflect.DeepEqual(a.Policies, b.Policies)
}

func TestResolveImageTagsDoNotOverrideContentIdentity(t *testing.T) {
	f := modelFixture()
	before := resolveFixture(t, f)
	fixtureService(f, "api")["image"] = "mirror.example/api:new-release@sha256:" + strings.Repeat("a", 64)
	after := resolveFixture(t, f)
	if !reflect.DeepEqual(before.Inventory, after.Inventory) {
		t.Fatal("identical image content was invalidated by a tag or mirror name")
	}
	fixtureService(f, "api")["platform"] = "linux/arm64"
	if after.Inventory["api"].Runtime == resolveFixture(t, f).Inventory["api"].Runtime {
		t.Fatal("platform change was ignored")
	}
}

func TestResolveRejectsAmbiguityAndUnsupportedInputs(t *testing.T) {
	cases := map[string]func(map[string]any){
		"mutable image":          func(f map[string]any) { fixtureService(f, "api")["image"] = "example/api:latest" },
		"unknown policy":         func(f map[string]any) { fixturePolicy(f, "api")["typo"] = true },
		"unsupported version":    func(f map[string]any) { f["x-komizo"].(map[string]any)["version"] = 2 },
		"missing metadata":       func(f map[string]any) { delete(f, "x-komizo") },
		"missing service policy": func(f map[string]any) { delete(f["x-komizo"].(map[string]any)["services"].(map[string]any), "db") },
		"build":                  func(f map[string]any) { fixtureService(f, "api")["build"] = "." },
		"env file":               func(f map[string]any) { fixtureService(f, "api")["env_file"] = []any{"private.env"} },
		"interpolation": func(f map[string]any) {
			fixtureService(f, "api")["environment"] = map[string]any{"VALUE": "${PRIVATE}"}
		},
		"inherited environment": func(f map[string]any) { fixtureService(f, "api")["environment"] = map[string]any{"VALUE": nil} },
		"profiles":              func(f map[string]any) { fixtureService(f, "api")["profiles"] = []any{"prod"} },
		"published port": func(f map[string]any) {
			fixtureService(f, "api")["ports"] = []any{map[string]any{"target": 80, "published": "80"}}
		},
		"host networking":    func(f map[string]any) { fixtureService(f, "api")["network_mode"] = "host" },
		"fixed name":         func(f map[string]any) { fixtureService(f, "api")["container_name"] = "api" },
		"privileged":         func(f map[string]any) { fixtureService(f, "api")["privileged"] = true },
		"unsafe candidate":   func(f map[string]any) { fixturePolicy(f, "api")["candidate_safe"] = false },
		"bad readiness":      func(f map[string]any) { fixturePolicy(f, "api")["ready_path"] = "//external/ready" },
		"readiness query":    func(f map[string]any) { fixturePolicy(f, "api")["ready_path"] = "/ready?secret=value" },
		"bad port":           func(f map[string]any) { fixturePolicy(f, "api")["port"] = 65536 },
		"unknown mode":       func(f map[string]any) { fixturePolicy(f, "api")["mode"] = "magic" },
		"persistent overlap": func(f map[string]any) { fixturePolicy(f, "db")["candidate_safe"] = true },
		"shared DNS alias": func(f map[string]any) {
			fixtureService(f, "api")["networks"] = map[string]any{"private": map[string]any{"aliases": []any{"api"}}}
		},
		"missing network": func(f map[string]any) { delete(f, "networks") },
		"writable volume": func(f map[string]any) {
			fixtureService(f, "api")["volumes"] = []any{map[string]any{"type": "volume", "source": "data", "target": "/data"}}
		},
		"bind file": func(f map[string]any) {
			fixtureService(f, "api")["volumes"] = []any{map[string]any{"type": "bind", "source": "/private/file", "target": "/data", "read_only": true}}
		},
		"missing secret version": func(f map[string]any) {
			fixtureService(f, "api")["secrets"] = []any{map[string]any{"source": "password"}}
		},
		"unused secret version": func(f map[string]any) {
			f["x-komizo"].(map[string]any)["secret_versions"] = map[string]any{"unused": "v1"}
		},
		"dependency cycle":     func(f map[string]any) { fixturePolicy(f, "api")["restart_on"] = []any{"api"} },
		"unknown dependency":   func(f map[string]any) { fixturePolicy(f, "api")["restart_on"] = []any{"missing"} },
		"duplicate dependency": func(f map[string]any) { fixturePolicy(f, "api")["restart_on"] = []any{"db", "db"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := modelFixture()
			mutate(f)
			data, _ := json.Marshal(f)
			if model, err := Resolve(data, bytes.Repeat([]byte{1}, 32)); err == nil || model != nil {
				t.Fatalf("unsafe/incomplete input accepted: %#v, %v", model, err)
			}
		})
	}
	for _, input := range []string{
		`{"services":{},"services":{},"x-komizo":{"version":1,"services":{}}}`,
		`{"services":{"api":{"image":"first","image":"second"}}}`,
		`{} {}`, `[]`, `null`, `{"secret":"do-not-echo"`,
	} {
		if model, err := Resolve([]byte(input), bytes.Repeat([]byte{1}, 32)); err == nil || model != nil {
			t.Fatalf("invalid JSON accepted: %v", err)
		} else if strings.Contains(err.Error(), "do-not-echo") {
			t.Fatal("decoder reflects input")
		}
	}
}

func TestResolveLimitsAndEmptyInventory(t *testing.T) {
	input := []byte(`{"services":{},"x-komizo":{"version":1,"services":{}}}`)
	if _, err := Resolve(input, nil); err == nil {
		t.Fatal("missing key accepted")
	}
	if _, err := Resolve(bytes.Repeat([]byte{' '}, MaxModelBytes+1), make([]byte, 32)); err == nil {
		t.Fatal("oversized model accepted")
	}
	if _, err := Resolve([]byte{'"', 0xff, '"'}, make([]byte, 32)); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
	model, err := Resolve(input, make([]byte, 32))
	if err != nil || model.Inventory == nil || len(model.Inventory) != 0 {
		t.Fatalf("explicit empty inventory: %#v, %v", model, err)
	}
}

func TestResolveSupportsImmutableLocalImageIDs(t *testing.T) {
	f := modelFixture()
	fixtureService(f, "api")["image"] = "sha256:" + strings.Repeat("a", 64)
	local := resolveFixture(t, f)
	fixtureService(f, "api")["image"] = "example/api@sha256:" + strings.Repeat("a", 64)
	manifest := resolveFixture(t, f)
	if local.Inventory["api"].Image == manifest.Inventory["api"].Image {
		t.Fatal("local config digest conflated with registry manifest digest")
	}
}
