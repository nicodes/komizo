package box

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func testKey(t *testing.T) (ed25519.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, FormatDeviceKey(pub)
}

func TestADeviceKeyRoundTrips(t *testing.T) {
	pub, s := testKey(t)
	if !strings.HasPrefix(s, DeviceKeyPrefix) {
		t.Fatalf("FormatDeviceKey = %q, want the %s prefix", s, DeviceKeyPrefix)
	}
	got, err := ParseDeviceKey(s)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(pub) {
		t.Error("the key that came back is not the key that went in")
	}
	// Whitespace, because these arrive by being copied out of one window and
	// into another and a trailing newline comes with them.
	if _, err := ParseDeviceKey("  " + s + "\n"); err != nil {
		t.Errorf("a key with whitespace around it was refused: %v", err)
	}
}

// The prefix is a REFUSAL, not decoration.
//
// A registry key, an agent token and a device key are all opaque blobs to
// somebody moving them between two windows. A box that quietly accepted any of
// them as an authority would be a box trusting something nobody meant it to.
func TestOnlyADeviceKeyIsADeviceKey(t *testing.T) {
	pub, good := testKey(t)
	raw := base64.RawURLEncoding.EncodeToString(pub)

	for name, in := range map[string]string{
		"a registry key, which is the same bytes with no prefix": raw,
		"an agent token":         "kmz_agt_" + raw,
		"an enrolment token":     "kmz_enr_" + raw,
		"a read token":           ReadTokenPrefix + raw,
		"nothing at all":         "",
		"the prefix on its own":  DeviceKeyPrefix,
		"not base64":             DeviceKeyPrefix + "!!!!",
		"the right shape, short": DeviceKeyPrefix + base64.RawURLEncoding.EncodeToString(pub[:16]),
	} {
		if _, err := ParseDeviceKey(in); err == nil {
			t.Errorf("%s was accepted as a device key", name)
		}
	}
	if _, err := ParseDeviceKey(good); err != nil {
		t.Errorf("a real device key was refused: %v", err)
	}
}

// All or nothing.
//
// Skipping the bad one would leave a box trusting fewer devices than the
// operator believes it does, and the way that gets discovered is somebody's app
// refusing to work on one box out of six, months later, with nothing to read.
func TestOneUnreadableKeyFailsTheWholeSet(t *testing.T) {
	_, a := testKey(t)
	_, b := testKey(t)

	c := AgentConf{ServerID: "srv_x", OperatorKeys: []string{a, b}}
	keys, err := c.TrustedKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}

	c.OperatorKeys = []string{a, "kmz_dev_nonsense", b}
	if _, err := c.TrustedKeys(); err == nil {
		t.Fatal("a set with an unreadable key was accepted")
	} else if !strings.Contains(err.Error(), "2 of 3") {
		t.Errorf("error = %q, want it to name which key of how many", err)
	}
}

// Reading and commanding are separate questions with, since komizo-be#180, the
// same answer on an ordinary box.
//
// This test USED to assert the opposite of its first case -- that a box with a
// registry key and no operator key takes orders from nobody. That was the
// property #180 reversed on purpose, and it is inverted here rather than
// deleted so the reversal is visible to whoever reads this file next.
//
// The cases that did NOT change are the ones that matter most: an enrolled box
// still cannot be commanded without a server id, and a box with neither kind of
// key is still inert.
func TestServingAndCommandingAreIndependent(t *testing.T) {
	_, k := testKey(t)
	reg := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))

	serves := AgentConf{ServerID: "srv_x", RegistryKey: reg}
	if !serves.CanServe() {
		t.Error("a box with a registry key and an id cannot serve")
	}
	if !serves.CanCommand() {
		t.Error("an enrolled box would not take orders from its owner, which is the whole of komizo-be#180")
	}

	commands := AgentConf{ServerID: "srv_x", OperatorKeys: []string{k}}
	if commands.CanCommand() != true {
		t.Error("a box with an operator key and an id will not take orders")
	}
	if commands.CanServe() {
		t.Error("an operator key made a box serve reads, which is a different authority")
	}

	// And neither without an id: no token and no command can name a box that
	// no registry has heard of.
	none := AgentConf{OperatorKeys: []string{k}, RegistryKey: reg}
	if none.CanCommand() || none.CanServe() {
		t.Error("a box with no server id claimed it could do something")
	}

	// The box that is genuinely inert: enrolled against nothing, given nothing.
	// This is what #180 must NOT have widened, and the case that would have gone
	// unnoticed if CanCommand had simply been made to return true.
	bare := AgentConf{ServerID: "srv_x"}
	if bare.CanCommand() {
		t.Error("a box with no registry key and no device key would take orders from somebody")
	}
}

// The registry key is an authority to command, and an unrelated key is not.
//
// THE PROPERTY THAT HAD TO SURVIVE komizo-be#180. The alternative design deleted
// verification outright, and with it every assertion of this shape; the whole
// argument for signing at the service instead was that this stays true and stays
// checkable. So it is checked at the level that decides it -- the key set -- and
// again in service_signs_test.go at the level that spends it.
func TestTheRegistryKeyIsTrustedAndAStrangerIsNot(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	stranger, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := AgentConf{ServerID: "srv_x", RegistryKey: base64.RawURLEncoding.EncodeToString(pub)}
	keys, err := c.TrustedKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || !keys[0].Equal(pub) {
		t.Fatalf("trusted keys = %v, want just the registry key", keys)
	}
	for _, k := range keys {
		if k.Equal(stranger) {
			t.Error("a key nobody planted is in the trusted set")
		}
	}

	// Carried ALONGSIDE the operator keys rather than instead of them. A box
	// that had devices planted keeps trusting them; that is what makes this
	// additive rather than a replacement.
	_, dev := testKey(t)
	c.OperatorKeys = []string{dev}
	keys, err = c.TrustedKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want the device and the registry key", len(keys))
	}

	// And all-or-nothing covers the registry key too. A box whose credential
	// carries an unreadable one refuses everything rather than quietly falling
	// back to device-only, which would be a box in a mode nobody chose.
	c.RegistryKey = "not base64 at all!!"
	if _, err := c.TrustedKeys(); err == nil {
		t.Error("an unreadable registry key was skipped instead of failing the set")
	}
}

func TestTheConfCarriesOperatorKeysAcrossAWrite(t *testing.T) {
	_, k := testKey(t)
	dir := t.TempDir()
	path := dir + "/agent.json"
	in := AgentConf{API: "https://api.example.com", ServerID: "srv_x", Token: "kmz_agt_x",
		OperatorKeys: []string{k}}
	if err := WriteAgentConf(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := ReadAgentConf(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.OperatorKeys) != 1 || out.OperatorKeys[0] != k {
		t.Errorf("operator keys = %v, want %v", out.OperatorKeys, in.OperatorKeys)
	}
}

// The fingerprint is what a person compares between a screen and a terminal.
//
// The same form on both ends, and it is the key itself rather than a hash of it
// -- a hash would be a second thing to compute in two places and get wrong
// once. app/src/lib/device.ts renders this exact shape.
func TestAFingerprintIsTheKeyShortened(t *testing.T) {
	pub, key := testKey(t)
	_ = pub

	got := Fingerprint(key)
	body := strings.TrimPrefix(key, DeviceKeyPrefix)
	if got != body[:8]+"…"+body[len(body)-8:] {
		t.Errorf("Fingerprint = %q", got)
	}
	// The prefix is not part of it: every key has the same one, so including it
	// would be eight characters that are identical on every comparison.
	if strings.Contains(got, DeviceKeyPrefix) {
		t.Error("the fingerprint repeats the prefix every key shares")
	}
	// Both ends of the key are in it, so a truncated paste changes it. A prefix
	// alone would not: a key cut short keeps its first eight characters.
	if !strings.HasPrefix(got, body[:8]) || !strings.HasSuffix(got, body[len(body)-8:]) {
		t.Error("the fingerprint does not cover both ends, so a truncated key would match")
	}
	// Two different keys do not share one.
	_, other := testKey(t)
	if Fingerprint(other) == got {
		t.Error("two keys share a fingerprint")
	}
	// And a short string is returned whole rather than sliced out of range.
	if Fingerprint("kmz_dev_abc") != "abc" {
		t.Errorf("a short key = %q", Fingerprint("kmz_dev_abc"))
	}
}

// A KEY PRODUCED BY THE BROWSER, PINNED HERE.
//
// The app makes these with WebCrypto and hand-rolls base64url on top of btoa;
// this package parses them with encoding/base64. Nothing in CI held the two
// together -- app/ has no test runner at all, and every fixture in this file is
// generated by Go, so Go agreeing with Go proved nothing about the pair that
// actually has to agree.
//
// Generated once by:
//
//	const pair = await crypto.subtle.generateKey({name:'Ed25519'}, false, ['sign','verify'])
//	const raw  = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))
//	btoa(String.fromCharCode(...raw)).replaceAll('+','-').replaceAll('/','_').replaceAll('=','')
//
// If this ever fails, one of the two encoders moved and boxes will start
// refusing the app's key with nothing to say why.
const browserKey = "kmz_dev_RR8l1xNODQvUGRsHahLBjrqypsAhJ-9ZhCuERCJGleU"

func TestAKeyTheBrowserProducedIsAcceptedHere(t *testing.T) {
	pub, err := ParseDeviceKey(browserKey)
	if err != nil {
		t.Fatalf("a key produced by the app was refused: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("%d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	// And this end renders it back identically, so a key that made a round trip
	// through Go is still the string the app showed.
	if got := FormatDeviceKey(pub); got != browserKey {
		t.Errorf("FormatDeviceKey round trip = %q, want %q", got, browserKey)
	}
	// The fingerprint the two ends compare is the same one. app/src/lib/device.ts
	// renders exactly this, and a person matching them by eye is the only step in
	// this design that depends on somebody looking.
	// The literal the TypeScript produces for this same key, checked by running
	// device.ts's fingerprint() against it. A value derived here with the same
	// arithmetic would agree with itself whatever either side did.
	if got := Fingerprint(browserKey); got != "RR8l1xNO…ERCJGleU" {
		t.Errorf("Fingerprint = %q, want what app/src/lib/device.ts renders", got)
	}
}
