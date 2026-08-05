package main

import (
	"strings"
	"testing"
)

// The verbs are a closed set, and an unknown one is refused rather than passed
// to docker.
//
// This is the process a signed command ends in -- app-only.md §4's "op is a
// NAME, and args are structured". A verb that reached `docker compose` unchecked
// would make the signature the thing that authorised whatever was in it.
func TestOnlyTheKnownVerbsAreAccepted(t *testing.T) {
	// The MESSAGE is asserted, not merely that something failed. Every call
	// here also fails later at the app lookup, so "returned an error" would pass
	// with the check deleted -- which is the whole failure mode this style of
	// test exists to avoid.
	for _, bad := range []string{"rm", "exec", "up", "down", "--version", ""} {
		err := runApp([]string{bad, "--app", "web"})
		if err == nil || !strings.Contains(err.Error(), "not something an app can be told to do") {
			t.Errorf("komizo-box app %q = %v, want it refused as a verb", bad, err)
		}
	}
	if err := runApp(nil); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Errorf("komizo-box app with no verb = %v", err)
	}
}

// --app is required, and it is required before anything runs.
func TestAppIsRequired(t *testing.T) {
	for _, verb := range []string{"start", "stop", "restart", "logs"} {
		err := runApp([]string{verb})
		if err == nil || !strings.Contains(err.Error(), "--app") {
			t.Errorf("komizo-box app %s with no --app = %v", verb, err)
		}
	}
}

// A tail is bounded at both ends.
//
// Unbounded is what this route is not for -- app-only.md §5, "tail, do not
// index" -- and the caller is on the other side of an SSH connection or an
// HTTPS route in step 3.
func TestTheLogTailIsBounded(t *testing.T) {
	for _, n := range []string{"0", "-1", "100000"} {
		err := runApp([]string{"logs", "--app", "web", "--tail", n})
		if err == nil || !strings.Contains(err.Error(), "--tail must be between") {
			t.Errorf("--tail %s = %v, want it refused as a range", n, err)
		}
	}
	// And a tail inside the range gets past this check, so the test above is
	// not passing because every tail is refused.
	if err := runApp([]string{"logs", "--app", "web", "--tail", "40"}); err != nil &&
		strings.Contains(err.Error(), "--tail") {
		t.Errorf("a tail of 40 was refused: %v", err)
	}
}
