package release

import (
	"fmt"
	"maps"
	"reflect"
	"strings"
	"testing"
)

func identity() Identity {
	return Identity{
		Image: "resolved-image-1", Runtime: "resolved-runtime-1",
		Secrets: "known-empty-secret-set", Dependencies: "known-empty-dependency-set",
	}
}

func TestCompareSelectiveChanges(t *testing.T) {
	for _, service := range []string{"ui", "api", "db"} {
		t.Run(service, func(t *testing.T) {
			before := Inventory{"ui": identity(), "api": identity(), "db": identity()}
			after := maps.Clone(before)
			next := after[service]
			next.Image = "resolved-image-2"
			after[service] = next
			got, err := Compare(before, after)
			if err != nil {
				t.Fatal(err)
			}
			want := []Change{{Service: "api", Kind: Unchanged}, {Service: "db", Kind: Unchanged}, {Service: "ui", Kind: Unchanged}}
			for i := range want {
				if want[i].Service == service {
					want[i].Kind = Changed
					want[i].Reasons = []Component{Image}
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got %#v, want %#v", got, want)
			}
			if before[service] != identity() || after[service] != next {
				t.Fatal("comparison mutated an input")
			}
		})
	}
}

func TestCompareEachComponent(t *testing.T) {
	cases := []struct {
		component Component
		change    func(*Identity)
	}{
		{Image, func(v *Identity) { v.Image = "another-image" }},
		{Runtime, func(v *Identity) { v.Runtime = "another-runtime" }},
		{Secrets, func(v *Identity) { v.Secrets = "another-secret-version" }},
		{Dependencies, func(v *Identity) { v.Dependencies = "another-dependency-version" }},
	}
	for _, tc := range cases {
		t.Run(string(tc.component), func(t *testing.T) {
			next := identity()
			tc.change(&next)
			got, err := Compare(Inventory{"api": identity()}, Inventory{"api": next})
			want := []Change{{Service: "api", Kind: Changed, Reasons: []Component{tc.component}}}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("got %#v, %v; want %#v", got, err, want)
			}
		})
	}
}

func TestCompareMembershipAndNoOp(t *testing.T) {
	cases := []struct {
		name          string
		before, after Inventory
		want          []Change
	}{
		{"empty", Inventory{}, Inventory{}, []Change{}},
		{"initial", Inventory{}, Inventory{"api": identity()}, []Change{{Service: "api", Kind: Added}}},
		{"removal", Inventory{"api": identity()}, Inventory{}, []Change{{Service: "api", Kind: Removed}}},
		{"same", Inventory{"api": identity()}, Inventory{"api": identity()}, []Change{{Service: "api", Kind: Unchanged}}},
		{"rename", Inventory{"old": identity()}, Inventory{"new": identity()}, []Change{{Service: "new", Kind: Added}, {Service: "old", Kind: Removed}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Compare(tc.before, tc.after)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, %v; want %#v", got, err, tc.want)
			}
		})
	}
}

func TestCompareDeterministicAndValueFree(t *testing.T) {
	old := identity()
	next := Identity{"private-image-reference", "private-runtime-reference", "private-secret-version", "private-dependency-reference"}
	want := []Change{
		{Service: "a", Kind: Changed, Reasons: []Component{Image, Runtime, Secrets, Dependencies}},
		{Service: "z", Kind: Unchanged},
	}
	for i := range 100 {
		before, after := Inventory{}, Inventory{}
		if i%2 == 0 {
			before["z"], before["a"] = old, old
			after["a"], after["z"] = next, old
		} else {
			before["a"], before["z"] = old, old
			after["z"], after["a"] = old, next
		}
		got, err := Compare(before, after)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v, %v; want %#v", got, err, want)
		}
		output := fmt.Sprintf("%+v", got)
		for _, pair := range components(old, next) {
			if strings.Contains(output, pair.before) || strings.Contains(output, pair.after) {
				t.Fatal("analysis exposes identity values")
			}
		}
	}
}

func TestCompareRejectsUnresolvedInputWithoutPartialResult(t *testing.T) {
	for _, beforeSide := range []bool{true, false} {
		for _, missing := range []string{"inventory", "image", "runtime", "secrets", "dependencies"} {
			t.Run(fmt.Sprintf("before=%t/%s", beforeSide, missing), func(t *testing.T) {
				bad := identity()
				switch missing {
				case "image":
					bad.Image = ""
				case "runtime":
					bad.Runtime = " \t\n"
				case "secrets":
					bad.Secrets = ""
				case "dependencies":
					bad.Dependencies = ""
				}
				invalid := Inventory{"z": bad}
				if missing == "inventory" {
					invalid = nil
				}
				before, after := Inventory{"a": identity()}, invalid
				if beforeSide {
					before, after = after, before
				}
				got, err := Compare(before, after)
				if err == nil || got != nil {
					t.Fatalf("incomplete input yielded %#v, %v", got, err)
				}
				for _, pair := range components(identity(), Identity{}) {
					if strings.Contains(err.Error(), pair.before) {
						t.Fatal("validation error exposes an identity value")
					}
				}
			})
		}
	}
}

func TestCompareValidatesUnchangedAndRemovedIdentities(t *testing.T) {
	bad := Inventory{"api": {}}
	for _, after := range []Inventory{bad, {}} {
		if got, err := Compare(bad, after); err == nil || got != nil {
			t.Fatalf("unresolved old identity yielded %#v, %v", got, err)
		}
	}
}

func TestCompareServiceNames(t *testing.T) {
	for _, name := range []string{"api", "API_1", "worker-1", "service.v2", "_internal", "1"} {
		if _, err := Compare(Inventory{}, Inventory{name: identity()}); err != nil {
			t.Errorf("valid service %q: %v", name, err)
		}
	}
	for _, name := range []string{"", "--flag", ".hidden", "a/b", "a b", "api\nforged", "\x1b[31m", "服务"} {
		if got, err := Compare(Inventory{}, Inventory{name: identity()}); err == nil || got != nil {
			t.Errorf("invalid service name accepted: %#v, %v", got, err)
		} else if name != "" && strings.Contains(err.Error(), name) {
			t.Errorf("invalid name reflected into error: %q", err)
		}
	}
}

func TestCompareValidationOrder(t *testing.T) {
	for range 100 {
		_, err := Compare(Inventory{"z": {}, "a": {}}, Inventory{"b": {}})
		if err == nil || err.Error() != `before service "a": unresolved image identity` {
			t.Fatalf("nondeterministic validation: %v", err)
		}
	}
}
