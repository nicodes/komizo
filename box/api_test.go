package box

import (
	"crypto/ed25519"

	"os"

	"testing"
	"time"
)

// The box answering for itself, and refusing to answer for anybody else.
//
// These are the tests for a wire format that is permanent from the moment it
// ships -- design/registry.md pins the shape before the code precisely because
// a published module version cannot be taken back.

// apiFixture is a box with a report, three samples, and ONE TRUSTED DEVICE.
//
// The device arrived with komizo-be#72. Before it, every test here read through
// `GET /v1/report`, which took the registry's token and nothing else -- and
// when that route was removed those reads would still have answered 401,
// because the catch-all refuses an unknown path with exactly the status an
// unauthorized one gets. Every token assertion in this file would have passed
// against a Handler with no token checking left in it at all.
//
// So they go through the signed route, which is the only way to read a box now.

// The property the whole design rests on: a token for one box is useless at
// another. Without it the registry is a skeleton key for every box it knows.

// A box that has never enrolled has no id, so no token can name it. Refusing
// everything is the right answer for a machine no registry has heard of.

// SIGNED WHILE THE BOX STILL HAD AN ID, so what makes this refusable is the
// box and not the request. Signing after would fail in SignCommand -- an
// envelope must name the server it is for -- and would test the helper.

// An unknown path must answer exactly as an unauthorized one does, or an
// unauthenticated caller can map the API by watching which paths 404.

// History carries the samples AS RECORDED -- cumulative counters, not rates.
// A rate needs two readings, and serving one would bake in an interval that a
// late poll makes wrong, unrecoverably.

// A box with no history yet is not a broken box.

// A box whose agent has not written a report yet says so, rather than serving
// an empty document that reads as a broken machine.

// The key as enrolment stores it: raw base64, one line, no armour.
func TestThePlantedKeyRoundTrips(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePublicKey(b64(pub) + "\n")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := SignReadToken(priv, "srv_x", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReadToken(parsed, tok, "srv_x", time.Now()); err != nil {
		t.Errorf("a key read back from its stored form did not verify: %v", err)
	}

	for name, bad := range map[string]string{
		"not base64":   "!!!!",
		"wrong length": b64([]byte("too short")),
	} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("%s was accepted as a registry key", name)
		}
	}
}

// The socket directory has to be reachable by the box's proxy, which runs with
// every capability dropped but CAP_NET_BIND_SERVICE.
//
// That is komizo's own hardening and it means the proxy's root is NOT exempt
// from permission checks -- it cannot traverse a directory it does not own.
// This shipped as 0750 agent:agent and the proxy answered 502 with
// "connect: permission denied" on every request.
func TestTheSocketDirectoryIsSetgidSoTheProxyCanReachIt(t *testing.T) {
	if APISocketDirMode&os.ModeSetgid == 0 {
		t.Error("the socket directory is not setgid, so the socket inherits the agent's " +
			"group and the proxy -- which has no CAP_DAC_OVERRIDE -- cannot connect to it")
	}
	if perm := APISocketDirMode.Perm(); perm&0o050 == 0 {
		t.Errorf("the socket directory is %04o: the group cannot traverse it", perm)
	}
	if perm := APISocketDirMode.Perm(); perm&0o007 != 0 {
		t.Errorf("the socket directory is %04o: it is reachable by anything on the box", perm)
	}
}
