package release

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestDeclaredLifecycleIdentityAndRefusal(t *testing.T) {
	f := modelFixture()
	before := resolveFixture(t, f)
	fixturePolicy(f, "api")["lifecycle"] = map[string]any{"version": 1, "command": []string{"/app", "lifecycle"}}
	after := resolveFixture(t, f)
	if before.Inventory["api"].Runtime == after.Inventory["api"].Runtime || before.Inventory["ui"] != after.Inventory["ui"] {
		t.Fatal("lifecycle is not a scoped immutable identity")
	}
	for _, invalid := range []any{
		map[string]any{"version": 2, "command": []string{"/app"}},
		map[string]any{"version": 1, "command": []string{"relative"}},
		map[string]any{"version": 1, "command": []string{}},
		map[string]any{"version": 1, "command": []string{"/app", "bad\narg"}},
		map[string]any{"version": 1, "command": []string{"/app"}, "unknown": true},
	} {
		fixturePolicy(f, "api")["lifecycle"] = invalid
		data, _ := json.Marshal(f)
		if _, err := Resolve(data, bytes.Repeat([]byte{1}, 32)); err == nil {
			t.Fatal("invalid lifecycle accepted")
		}
	}
	fixturePolicy(f, "api")["lifecycle"] = map[string]any{"version": 1, "command": []string{"/app"}}
	fixtureService(f, "api")["restart"] = "always"
	data, _ := json.Marshal(f)
	if _, err := Resolve(data, bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Fatal("automatic restart can invalidate stop proof")
	}
	fixtureService(f, "api")["restart"] = "no"
	resolveFixture(t, f)
}
