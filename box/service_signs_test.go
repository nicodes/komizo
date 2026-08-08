package box

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The flow komizo-be#180 exists for, asserted end to end at this layer.
//
//  1. somebody runs `komizo login`
//  2. somebody runs `komizo init`, which enrols the box and plants a registry key
//  3. any device signed into that account commands it
//
// Step 3 is what this checks, and the box it checks it on is the one the flow
// actually produces: ZERO OPERATOR KEYS. Every other test in this package
// arranges a device key first, so all of them would have gone on passing with
// the registry key ignored entirely -- which is the failure mode this file is
// here to make impossible.
func TestABoxWithNoDeviceKeysTakesOrdersFromItsRegistry(t *testing.T) {
	regPub, regPriv := device(t)
	now := time.Now()

	conf := AgentConf{ServerID: "srv_mine",
		RegistryKey: base64.RawURLEncoding.EncodeToString(regPub)}
	if !conf.CanCommand() {
		t.Fatal("a freshly enrolled box will not take orders, so the flow is broken at step 2")
	}
	keys, err := conf.TrustedKeys()
	if err != nil {
		t.Fatal(err)
	}

	c := stopWeb(now.Add(time.Minute))
	c.Sub = "u1234567890abcd"
	got, signer, err := VerifyCommand(keys, signed(t, regPriv, c), "srv_mine", now)
	if err != nil {
		t.Fatalf("the service could not command a box it enrolled: %v", err)
	}
	if !signer.Equal(regPub) {
		t.Error("the registry key verified but was not reported as the signer")
	}
	if got.Sub != "u1234567890abcd" {
		t.Errorf("sub = %q, want the account the service signed for", got.Sub)
	}
}

// AND A STRANGER IS STILL REFUSED.
//
// The one property that had to survive the change, checked on the box shape the
// change created. #180 chose service-signing over deleting verification
// precisely so this assertion could still be written; a version of this feature
// that cannot fail here is the version that was rejected.
func TestAnEnrolledBoxStillRefusesAKeyItWasNeverGiven(t *testing.T) {
	regPub, _ := device(t)
	_, strangerPriv := device(t)
	now := time.Now()

	conf := AgentConf{ServerID: "srv_mine",
		RegistryKey: base64.RawURLEncoding.EncodeToString(regPub)}
	keys, err := conf.TrustedKeys()
	if err != nil {
		t.Fatal(err)
	}
	raw := signed(t, strangerPriv, stopWeb(now.Add(time.Minute)))
	if _, _, err := VerifyCommand(keys, raw, "srv_mine", now); err == nil {
		t.Fatal("an enrolled box acted on a command signed by nobody it trusts")
	}

	// And the audience check still holds for the registry too. A service that
	// signs for every box it knows about is exactly the thing `srv` bounds, so
	// widening the key set must not have widened the spend.
	regPub2, regPriv2 := device(t)
	conf2 := AgentConf{ServerID: "srv_theirs",
		RegistryKey: base64.RawURLEncoding.EncodeToString(regPub2)}
	keys2, err := conf2.TrustedKeys()
	if err != nil {
		t.Fatal(err)
	}
	// Signed by the key srv_theirs trusts, for srv_mine. Spent at srv_theirs.
	elsewhere := signed(t, regPriv2, stopWeb(now.Add(time.Minute)))
	if _, _, err := VerifyCommand(keys2, elsewhere, "srv_theirs", now); err == nil {
		t.Error("a command naming srv_mine was accepted by srv_theirs")
	}
}

// A subject can only be set by signing, and only within bounds.
//
// The first half is not a check this file can make on its own -- it IS the
// signature, and the assertion is that nothing reads `sub` before the signature
// has been verified. So it is checked the way the rest of the envelope is:
// tamper with the payload and watch the whole thing fall over.
func TestTheSubjectIsInsideTheSignature(t *testing.T) {
	pub, priv := device(t)
	now := time.Now()

	c := stopWeb(now.Add(time.Minute))
	c.Sub = "u1234567890abcd"
	env, err := SignCommand(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	// Re-encode the payload with a different subject, keeping the signature.
	payload, err := unb64(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	forged := strings.Replace(string(payload), "u1234567890abcd", "uSOMEBODYELSEX", 1)
	if forged == string(payload) {
		t.Fatal("the payload did not contain the subject, so this test proves nothing")
	}
	env.Payload = b64([]byte(forged))
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyCommand([]ed25519.PublicKey{pub}, raw, "srv_mine", now); err == nil {
		t.Error("a command whose subject was rewritten in flight was accepted")
	}
}

// What may be attributed.
//
// Bounded and narrow-alphabeted because this value LEAVES the envelope: it is
// written into an app's own record as STOPPED_BY, which root's own deploy script
// parses. setStateValues refuses a newline and is the guard that matters; this
// is the one that refuses it before anything acts on it.
func TestASubjectThatCouldNotBeWrittenDownIsRefused(t *testing.T) {
	pub, priv := device(t)
	now := time.Now()

	for _, tc := range []struct {
		name, sub string
		ok        bool
	}{
		{name: "absent", sub: "", ok: true},
		{name: "a record id", sub: "u1234567890abcd", ok: true},
		{name: "dashes and underscores", sub: "acct_a-b_c", ok: true},
		{name: "a newline forges a key in the app's record", sub: "u1\nAPP_DIR=/srv/theirs"},
		{name: "a carriage return does the same", sub: "u1\rAPP_DIR=/srv/theirs"},
		{name: "an equals sign", sub: "u1=2"},
		{name: "a space", sub: "somebody else"},
		{name: "longer than the box will store", sub: strings.Repeat("a", MaxSubjectBytes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := stopWeb(now.Add(time.Minute))
			c.Sub = tc.sub
			raw := signed(t, priv, c)
			_, _, err := VerifyCommand([]ed25519.PublicKey{pub}, raw, "srv_mine", now)
			if tc.ok && err != nil {
				t.Errorf("%q was refused: %v", tc.sub, err)
			}
			if !tc.ok && err == nil {
				t.Errorf("%q was accepted, and it is destined for a file root writes", tc.sub)
			}
		})
	}

	// Exactly at the limit is allowed. An off-by-one here is a subject the
	// service signs and the box silently refuses, which presents as a button
	// that does nothing.
	c := stopWeb(now.Add(time.Minute))
	c.Sub = strings.Repeat("a", MaxSubjectBytes)
	if _, _, err := VerifyCommand([]ed25519.PublicKey{pub}, signed(t, priv, c), "srv_mine", now); err != nil {
		t.Errorf("a subject of exactly %d bytes was refused: %v", MaxSubjectBytes, err)
	}
}

// Attribution says WHO, and says which kind of who.
//
// The registry key signs for every account komizo has, so a fingerprint of the
// verified key is the same eight characters on every box -- an answer shaped
// like an answer. This is what replaces it, and the fallback is what an
// operator's own device key still gets.
func TestAStopRecordsTheAccountWhenTheServiceSignedForOne(t *testing.T) {
	pub, _ := device(t)

	c := Command{Sub: "u1234567890abcd"}
	if got := StoppedByCommand(c, pub); got != "account u1234567890abcd" {
		t.Errorf("StoppedByCommand = %q, want the account named", got)
	}

	// No subject: an operator's device signed it, and the fingerprint names one
	// real device out of however many were planted.
	if got := StoppedByCommand(Command{}, pub); !strings.HasPrefix(got, "device ") {
		t.Errorf("StoppedByCommand = %q, want it to fall back to the device", got)
	}

	// A verified command always has a signer, so this is unreachable -- and it
	// is named anyway rather than left to write an empty STOPPED_BY, which is
	// omitempty in the report and would render as a stop nobody made.
	if got := StoppedByCommand(Command{}, nil); got != "device (unknown)" {
		t.Errorf("StoppedByCommand with no signer = %q, want it to say it does not know", got)
	}

	// And what it produces is writable. The two guards are in different files
	// and neither one alone is the check; this is the seam between them, and a
	// subject the envelope allows but the record refuses would be a stop that
	// half happens -- the app goes down and nothing says who.
	root := recordFixture(t)
	by := StoppedByCommand(Command{Sub: strings.Repeat("a", MaxSubjectBytes)}, pub)
	if err := MarkStopped(root, "blog", by, time.Now()); err != nil {
		t.Fatalf("an attribution the envelope allowed could not be written down: %v", err)
	}
	if got := recordOf(t, root); !strings.Contains(got, "STOPPED_BY="+by) {
		t.Errorf("the account did not reach the record:\n%s", got)
	}
}
