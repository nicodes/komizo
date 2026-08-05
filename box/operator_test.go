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

// Reading and commanding are different questions.
//
// Reading is authorised by the registry's signature; commanding is authorised
// only by a key an operator planted. Conflating them would make planting a
// device key the price of looking at a chart.
func TestServingAndCommandingAreIndependent(t *testing.T) {
	_, k := testKey(t)
	reg := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))

	serves := AgentConf{ServerID: "srv_x", RegistryKey: reg}
	if !serves.CanServe() {
		t.Error("a box with a registry key and an id cannot serve")
	}
	if serves.CanCommand() {
		t.Error("a box with no operator key would take orders")
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
