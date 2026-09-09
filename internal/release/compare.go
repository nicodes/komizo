// Package release compares already-resolved service identities without reading
// files, contacting Docker, or choosing how a service should be replaced.
// It is an internal analysis seam, not a Compose loader or deployment contract.
package release

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// Identity contains opaque equality tokens supplied by a trusted resolver.
// Image identifies immutable image content, not a mutable tag. Runtime covers
// all effective settings, including command, environment, mounts and external
// config contents. Secrets identifies secret versions, NEVER raw secret values
// or public hashes of low-entropy secrets. Dependencies identifies explicitly
// resolved dependency/config invalidations; this package does not propagate them.
//
// All fields must be supplied, even when a component is absent: a resolver must
// use an explicit stable token for a known empty component. Empty strings mean
// unresolved, not unchanged. This validation cannot prove resolver completeness.
type Identity struct {
	Image        string
	Runtime      string
	Secrets      string
	Dependencies string
}

// Inventory is a complete service set. An empty, non-nil map represents a known
// empty release. A nil map is unresolved and cannot prove additions or removals.
type Inventory map[string]Identity

type Kind string

const (
	Unchanged Kind = "unchanged"
	Added     Kind = "added"
	Removed   Kind = "removed"
	Changed   Kind = "changed"
)

type Component string

const (
	Image        Component = "image"
	Runtime      Component = "runtime"
	Secrets      Component = "secret-versions"
	Dependencies Component = "dependencies"
)

// Change describes a difference, not an instruction to start, stop or replace.
// It deliberately contains no identity values. Added/Removed describe membership;
// only Changed has component reasons, in the fixed order declared above.
type Change struct {
	Service string
	Kind    Kind
	Reasons []Component
}

// Compare validates both complete inventories before returning any analysis.
// Results and validation order are deterministic. Inputs are never mutated, and
// no input values other than valid service names are included in results/errors.
func Compare(before, after Inventory) ([]Change, error) {
	if err := validate("before", before); err != nil {
		return nil, err
	}
	if err := validate("after", after); err != nil {
		return nil, err
	}

	names := make(map[string]struct{}, len(before)+len(after))
	for name := range before {
		names[name] = struct{}{}
	}
	for name := range after {
		names[name] = struct{}{}
	}
	changes := make([]Change, 0, len(names))
	for _, name := range slices.Sorted(maps.Keys(names)) {
		old, existed := before[name]
		next, exists := after[name]
		change := Change{Service: name, Kind: Unchanged}
		switch {
		case !existed:
			change.Kind = Added
		case !exists:
			change.Kind = Removed
		default:
			for _, pair := range components(old, next) {
				if pair.before != pair.after {
					change.Reasons = append(change.Reasons, pair.name)
				}
			}
			if len(change.Reasons) != 0 {
				change.Kind = Changed
			}
		}
		changes = append(changes, change)
	}
	return changes, nil
}

type componentPair struct {
	name          Component
	before, after string
}

func components(before, after Identity) [4]componentPair {
	return [4]componentPair{
		{Image, before.Image, after.Image},
		{Runtime, before.Runtime, after.Runtime},
		{Secrets, before.Secrets, after.Secrets},
		{Dependencies, before.Dependencies, after.Dependencies},
	}
}

func validate(side string, inventory Inventory) error {
	if inventory == nil {
		return fmt.Errorf("%s inventory is unresolved", side)
	}
	for _, name := range slices.Sorted(maps.Keys(inventory)) {
		if !validName(name) {
			// Do not reflect arbitrary strings into terminal/log output.
			return fmt.Errorf("%s inventory contains an invalid service name", side)
		}
		for _, pair := range components(inventory[name], Identity{}) {
			if strings.TrimSpace(pair.before) == "" {
				return fmt.Errorf("%s service %q: unresolved %s identity", side, name, pair.name)
			}
		}
	}
	return nil
}

// Compose service-key character shape, not shell quoting or a manifest parser.
func validName(name string) bool {
	if name == "" {
		return false
	}
	for i, c := range name {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' {
			continue
		}
		if i > 0 && (c == '.' || c == '-') {
			continue
		}
		return false
	}
	return true
}
