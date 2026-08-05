package box

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func device(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func signed(t *testing.T, priv ed25519.PrivateKey, c Command) []byte {
	t.Helper()
	env, err := SignCommand(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func stopWeb(exp time.Time) Command {
	return Command{Srv: "srv_mine", Exp: exp.Unix(), Op: OpAppStop, Args: map[string]string{"app": "web"}}
}

func TestACommandRoundTrips(t *testing.T) {
	pub, priv := device(t)
	now := time.Now()
	raw := signed(t, priv, stopWeb(now.Add(time.Minute)))

	got, signer, err := VerifyCommand([]ed25519.PublicKey{pub}, raw, "srv_mine", now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Op != OpAppStop {
		t.Errorf("op = %q", got.Op)
	}
	if app, err := got.AppOf(); err != nil || app != "web" {
		t.Errorf("AppOf = %q, %v", app, err)
	}
	if !signer.Equal(pub) {
		t.Error("the signer reported is not the key that signed")
	}
	if got.ID == "" {
		t.Error("SignCommand left the id empty, so a replay could not be told from a new command")
	}
	if got.V != CommandVersion {
		t.Errorf("v = %d, want %d", got.V, CommandVersion)
	}
}

// THE SKELETON-KEY DEFENCE.
//
// A command signed for one box must be useless at another. registry.md §6 had
// to learn this for read tokens; a command is worse, because it is a signed
// INSTRUCTION an attacker could spend on every box the operator owns.
func TestACommandForOneBoxIsRefusedAtAnother(t *testing.T) {
	pub, priv := device(t)
	now := time.Now()
	raw := signed(t, priv, stopWeb(now.Add(time.Minute)))

	if _, _, err := VerifyCommand([]ed25519.PublicKey{pub}, raw, "srv_someone_else", now); err == nil {
		t.Fatal("a command minted for one box was accepted at another")
	}
	// And a box with no id of its own accepts nothing: no command can name a
	// machine no registry has heard of.
	if _, _, err := VerifyCommand([]ed25519.PublicKey{pub}, raw, "", now); err == nil {
		t.Error("a box with no server id acted on a command")
	}
}

// Only a key the operator planted counts.
func TestOnlyAPlantedKeyCanCommand(t *testing.T) {
	pub, priv := device(t)
	other, otherPriv := device(t)
	now := time.Now()

	// Signed by a key this box does not hold.
	raw := signed(t, otherPriv, stopWeb(now.Add(time.Minute)))
	if _, _, err := VerifyCommand([]ed25519.PublicKey{pub}, raw, "srv_mine", now); err == nil {
		t.Error("a command signed by a key this box does not trust was accepted")
	}

	// An empty set refuses everything, which is every box today.
	raw = signed(t, priv, stopWeb(now.Add(time.Minute)))
	if _, _, err := VerifyCommand(nil, raw, "srv_mine", now); err == nil {
		t.Error("a box that trusts no device acted on a command")
	}

	// More than one device, and either may sign.
	if _, signer, err := VerifyCommand([]ed25519.PublicKey{other, pub}, raw, "srv_mine", now); err != nil {
		t.Errorf("a second trusted device could not command: %v", err)
	} else if !signer.Equal(pub) {
		t.Error("the wrong key was reported as the signer")
	}
}

func TestExpiryIsBoundedAtBothEnds(t *testing.T) {
	pub, priv := device(t)
	now := time.Now()

	expired := signed(t, priv, stopWeb(now.Add(-time.Second)))
	if _, _, err := VerifyCommand([]ed25519.PublicKey{pub}, expired, "srv_mine", now); err == nil {
		t.Error("an expired command was accepted")
	}

	// Dated far out. Without this bound the SIGNER decides how long a captured
	// signature stays spendable, which is what the short life exists to stop --
	// and the threat is a service that routed the request and held it back.
	forever := signed(t, priv, stopWeb(now.Add(72*time.Hour)))
	if _, _, err := VerifyCommand([]ed25519.PublicKey{pub}, forever, "srv_mine", now); err == nil {
		t.Error("a command valid for three days was accepted")
	}
}

// The signature covers the BYTES THAT ARRIVED.
//
// Re-marshalling the payload to check it would mean verifying something the
// signer never saw. JSON has no single serialisation, so the gap between what
// was signed and what was re-encoded is where a canonicalisation bug lives.
func TestTheSignatureCoversTheBytesThatArrived(t *testing.T) {
	pub, priv := device(t)
	now := time.Now()
	raw := signed(t, priv, stopWeb(now.Add(time.Minute)))

	var env Signed
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	payload, err := unb64(env.Payload)
	if err != nil {
		t.Fatal(err)
	}

	// Same document, different bytes: decode and re-encode with indentation.
	var c Command
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatal(err)
	}
	reencoded, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	tampered, err := json.Marshal(Signed{Payload: b64(reencoded), Sig: env.Sig})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyCommand([]ed25519.PublicKey{pub}, tampered, "srv_mine", now); err == nil {
		t.Error("a re-encoded payload verified against the original signature")
	}

	// And a single flipped bit in the payload.
	flipped := make([]byte, len(payload))
	copy(flipped, payload)
	flipped[len(flipped)/2] ^= 0x01
	bad, _ := json.Marshal(Signed{Payload: b64(flipped), Sig: env.Sig})
	if _, _, err := VerifyCommand([]ed25519.PublicKey{pub}, bad, "srv_mine", now); err == nil {
		t.Error("a modified payload verified")
	}
}

// THE SIGNATURE IS CHECKED FIRST.
//
// architecture.md §9 accepted that an unprivileged process can wake root by
// dropping a file here, on the condition that unsigned traffic costs one
// public-key operation and nothing else. If the payload were interpreted before
// the signature, an attacker would get parsing, dispatch decisions and distinct
// error messages for free.
//
// Proven by the ERROR: a command that is both unsigned and unknown answers with
// the opaque refusal, not with the version or op message it would earn if its
// contents had been read.
func TestNothingIsInterpretedBeforeTheSignature(t *testing.T) {
	pub, _ := device(t)
	_, wrongPriv := device(t)
	now := time.Now()

	c := stopWeb(now.Add(time.Minute))
	c.V = 99
	c.Op = "definitely.not.an.op"
	raw := signed(t, wrongPriv, c)

	_, _, err := VerifyCommand([]ed25519.PublicKey{pub}, raw, "srv_mine", now)
	if !errors.Is(err, ErrCommandRefused) {
		t.Errorf("err = %v, want the opaque refusal -- the payload was read before the signature was checked", err)
	}
}

// A version mismatch is a state, not an attack, so it says so.
func TestAVersionThisBoxDoesNotSpeakSaysSo(t *testing.T) {
	pub, priv := device(t)
	now := time.Now()
	c := stopWeb(now.Add(time.Minute))
	c.V = CommandVersion + 1
	// SignCommand overwrites V, so the envelope is built by hand to carry one
	// this box does not speak.
	payload, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(Signed{Payload: b64(payload), Sig: b64(ed25519.Sign(priv, payload))})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = VerifyCommand([]ed25519.PublicKey{pub}, raw, "srv_mine", now)
	if err == nil || !strings.Contains(err.Error(), "speaks v") {
		t.Errorf("err = %v, want a message naming both versions", err)
	}
}

func TestAnUnknownOpIsRefusedBeforeAnythingDispatches(t *testing.T) {
	pub, priv := device(t)
	now := time.Now()
	c := stopWeb(now.Add(time.Minute))
	c.Op = "app.rm"
	raw := signed(t, priv, c)

	_, _, err := VerifyCommand([]ed25519.PublicKey{pub}, raw, "srv_mine", now)
	if err == nil || !strings.Contains(err.Error(), "app.rm") {
		t.Errorf("err = %v, want it to name the op it does not know", err)
	}
}

func TestAnOversizedCommandIsRefusedWithoutBeingParsed(t *testing.T) {
	pub, priv := device(t)
	now := time.Now()
	c := stopWeb(now.Add(time.Minute))
	c.Args["padding"] = strings.Repeat("x", MaxCommandBytes)
	if _, err := SignCommand(priv, c); err == nil {
		t.Error("an oversized command was signed")
	}
	// And on the way in, where the caller is not ours.
	//
	// The envelope here is otherwise PERFECT -- a small, validly signed, current
	// payload -- and is oversized only because of a field nothing reads. Without
	// that it would be refused by the signature or the payload bound and this
	// would pass with the check deleted, which is what the first version of this
	// test did. A box must not read a hundred megabytes off the wire because the
	// meaningful part of it is short.
	good := signed(t, priv, stopWeb(now.Add(time.Minute)))
	var env map[string]any
	if err := json.Unmarshal(good, &env); err != nil {
		t.Fatal(err)
	}
	env["padding"] = strings.Repeat("x", MaxCommandBytes*2)
	fat, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fat) <= MaxCommandBytes {
		t.Fatalf("the fixture is only %d bytes", len(fat))
	}
	if _, _, err := VerifyCommand([]ed25519.PublicKey{pub}, fat, "srv_mine", now); !errors.Is(err, ErrCommandRefused) {
		t.Errorf("err = %v, want the opaque refusal -- an oversized body was read", err)
	}
}

// One argument cannot be enormous either, even inside a small command.
//
// The total bound would let a single value take nearly the whole envelope, and
// every value here is destined to become an argument to something on this
// machine.
func TestOneArgumentCannotBeEnormous(t *testing.T) {
	pub, priv := device(t)
	now := time.Now()

	c := stopWeb(now.Add(time.Minute))
	c.V = CommandVersion
	c.ID = "abcdefghijklmnopqrstuv"
	c.Args["app"] = strings.Repeat("a", 300)
	payload, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) > MaxCommandBytes {
		t.Fatalf("the fixture is %d bytes, which the total bound would catch first", len(payload))
	}
	raw, err := json.Marshal(Signed{Payload: b64(payload), Sig: b64(ed25519.Sign(priv, payload))})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyCommand([]ed25519.PublicKey{pub}, raw, "srv_mine", now); err == nil {
		t.Error("a 300-byte argument was accepted")
	}
}

// The value that crosses from a signed document into an argument on this
// machine is checked as an app name, not trusted because it was signed.
func TestAnAppNameIsCheckedEvenWhenItIsSigned(t *testing.T) {
	for _, bad := range []string{"", "../etc", "a/b", "web.env", "-rf", "web; rm -rf /", "web app"} {
		c := Command{Op: OpAppStop, Args: map[string]string{"app": bad}}
		if _, err := c.AppOf(); err == nil {
			t.Errorf("%q was accepted as an app name", bad)
		}
	}
	c := Command{Op: OpAppStop, Args: map[string]string{"app": "my-app_2"}}
	if got, err := c.AppOf(); err != nil || got != "my-app_2" {
		t.Errorf("AppOf = %q, %v -- an ordinary name was refused", got, err)
	}
}

// A command must name a server and an op before it can be signed at all, so a
// call site cannot produce one that every box would refuse.
func TestSigningRefusesACommandNobodyCouldAccept(t *testing.T) {
	_, priv := device(t)
	if _, err := SignCommand(priv, Command{Op: OpAppStop}); err == nil {
		t.Error("a command with no server was signed")
	}
	if _, err := SignCommand(priv, Command{Srv: "srv_mine"}); err == nil {
		t.Error("a command with no op was signed")
	}
	if _, err := SignCommand(ed25519.PrivateKey("short"), stopWeb(time.Now())); err == nil {
		t.Error("something that is not a private key signed a command")
	}
}

// A REFUSAL RETURNS NOTHING, not the thing it refused.
//
// Callers check the error, so this is the second of two independent reasons an
// unverified command cannot be acted on -- and it is the one that keeps holding
// if a caller ever forgets. Handing back the parsed payload of a document whose
// signature did not verify would make the error the only thing standing there.
func TestARefusedCommandComesBackEmpty(t *testing.T) {
	pub, _ := device(t)
	_, stranger := device(t)
	now := time.Now()

	raw := signed(t, stranger, stopWeb(now.Add(time.Minute)))
	c, signer, err := VerifyCommand([]ed25519.PublicKey{pub}, raw, "srv_mine", now)
	if err == nil {
		t.Fatal("a command signed by an untrusted key verified")
	}
	if signer != nil {
		t.Error("a refusal named a signer")
	}
	if c.Op != "" || c.ID != "" || c.Srv != "" || len(c.Args) != 0 {
		t.Errorf("a refusal returned the payload it refused: %+v", c)
	}
}
