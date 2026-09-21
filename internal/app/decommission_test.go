package app

import (
	"errors"
	"strings"
	"testing"
)

// The komizo service is decommissioned (board decision) and the CLI is the
// whole product. The three backend-coupled paths are GATED, not ripped out:
// each refuses with one sentence and exits nonzero BEFORE the network is
// touched -- a dead domain must never be dialled. What stays service-free
// (enrol --token, enrol --remove, the whole of init's box setup) is asserted
// to still run.

// login's every path reached the service, so the gate is the whole body. A
// bad --api proves the order: validation would reject it, the gate fires
// first -- nothing is parsed against the service, nothing is dialled.
func TestLoginRefusesBeforeReachingTheNetwork(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--with-token"},
		{"--api", "not a url"},
	} {
		err := RunLogin(args)
		if !errors.Is(err, errServiceDecommissioned) {
			t.Errorf("komizo login %v = %v, want the decommission refusal", args, err)
		}
	}
}

// The tokenless enrolment exchange is gone with the service. The gate sits
// in front of target resolution -- no --host at all still gets the refusal,
// not "--host is required" -- so it cannot open a connection on the way out.
func TestTokenlessEnrolRefusesBeforeResolvingATarget(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--host", "root@not a host"},
	} {
		err := RunEnrol(args)
		if !errors.Is(err, errServiceDecommissioned) {
			t.Errorf("komizo enrol %v = %v, want the decommission refusal", args, err)
		}
	}
}

// enrol --token stays, but there is no default service to point a box at:
// --api is required, because a default that names a dead domain is a silent
// network call to nothing.
func TestEnrolWithTokenNeedsAnExplicitService(t *testing.T) {
	err := RunEnrol([]string{"--host", "root@box.example.com", "--token", "kmz_enr_x"})
	if err == nil || !strings.Contains(err.Error(), "--api is required") {
		t.Errorf("enrol --token without --api = %v, want the required-flag refusal", err)
	}
	if errors.Is(err, errServiceDecommissioned) {
		t.Errorf("enrol --token was refused as decommissioned -- that path STAYS")
	}
}

// And both service-free forms still run: past the gate, failing where a bad
// host should fail -- on target validation, which is proof the refusal did
// not fire and no account was asked for.
func TestTheServiceFreeEnrolFormsStillRun(t *testing.T) {
	for _, args := range [][]string{
		{"--host", "root@not a host", "--token", "kmz_enr_x", "--api", "https://service.example.com"},
		{"--host", "root@not a host", "--remove"},
	} {
		err := RunEnrol(args)
		if err == nil {
			t.Errorf("komizo enrol %v succeeded against a non-host", args)
		}
		if errors.Is(err, errServiceDecommissioned) || errors.Is(err, errNotSignedIn) {
			t.Errorf("komizo enrol %v = %v -- a service-free form was gated", args, err)
		}
		if !strings.Contains(err.Error(), "not a host") {
			t.Errorf("komizo enrol %v = %v, want the host-validation failure past the gate", args, err)
		}
	}
}

// init does not attempt registration and still sets the box up: the init
// script, the agent and the proxy are all still installed, and the only
// statement that ever talked to the service is gone. Source-level, because
// the fact lives in the order of statements -- the same reading
// init_order_test.go makes, and the same reason: no fixture could catch a
// registration that should not happen.
func TestInitSetsTheBoxUpAndDoesNotRegister(t *testing.T) {
	fn, ok := setupPaths(t)["RunInit"]
	if !ok {
		t.Fatal("RunInit no longer provisions a box, so nothing here is guarding setup")
	}
	for _, still := range []string{"AlpineInitScript", "installAgent", "AlpineProxyScript"} {
		if !calls(fn, still) {
			t.Errorf("RunInit no longer runs %s -- the decommission must not shrink box setup", still)
		}
	}
	if calls(fn, "registerAndEnrol") {
		t.Error("RunInit still files the box under an account -- the service is " +
			"decommissioned, so that call is a network request to nothing on every init")
	}
}

// Nothing in the CLI may name the dead domain as a default. The refusal
// message is one shared sentence, so this is a source assertion over the
// package: a reintroduced api.komizo.dev default fails here, wherever it
// lands. (Strings that DESCRIBE the decommission are fine and stay.)
func TestNoDefaultTargetsTheDeadDomain(t *testing.T) {
	if strings.Contains(sourceOf(t, "service.go"), `DefaultAPI = "https://`) {
		t.Error("DefaultAPI is back -- a default that points at a dead domain is a silent network call to nothing")
	}
	for _, f := range []string{"login.go", "enrol.go", "init.go"} {
		if strings.Contains(sourceOf(t, f), `"https://api.komizo.dev"`) {
			t.Errorf("%s still defaults to the decommissioned service", f)
		}
	}
}
