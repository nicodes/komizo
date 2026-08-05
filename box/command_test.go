package box

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

// stopWeb is a command that is correct in every way a test is not varying.
//
// V is SET. A hand-built payload leaves it zero, and the version check runs
// before almost everything else -- so a fixture without it makes every test that
// builds its own envelope pass for the same wrong reason, whatever it thought it
// was checking.
func stopWeb(exp time.Time) Command {
	return Command{V: CommandVersion, ID: "abc123", Srv: "srv_mine", Exp: exp.Unix(),
		Op: OpAppStop, Args: map[string]string{"app": "web"}}
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

	expired := signed(t, priv, stopWeb(now.Add(-2*commandLeeway)))
	if _, _, err := VerifyCommand([]ed25519.PublicKey{pub}, expired, "srv_mine", now); err == nil {
		t.Error("an expired command was accepted")
	}

	// A LITTLE past expiry is allowed, at both ends, because the two clocks are
	// not the same clock. This was on the ceiling only: a box running fast
	// refused everything as expired with no allowance, and the symptom was an
	// app whose buttons did nothing and a log that said nothing about clocks.
	justPast := signed(t, priv, stopWeb(now.Add(-commandLeeway/2)))
	if _, _, err := VerifyCommand([]ed25519.PublicKey{pub}, justPast, "srv_mine", now); err != nil {
		t.Errorf("a command a few seconds past expiry was refused: %v", err)
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

// AN ID THIS BOX CANNOT FILE IS AN ID IT CANNOT REMEMBER.
//
// resultPath was the only thing that looked at an id, so one it refused --
// anything with a separator, anything empty -- bypassed replay protection
// entirely: Applied found no record and WriteResult could write none, so the
// same signed bytes applied again on every arrival, for the whole of their life.
func TestAnIDMustBeOneTheBoxCanFile(t *testing.T) {
	pub, priv := device(t)
	now := time.Now()

	for _, bad := range []string{"", "a.b", "..", "../../etc/cron.d/x", "a/b", "a b", strings.Repeat("x", 65), "\n"} {
		c := stopWeb(now.Add(time.Minute))
		c.ID = bad
		payload, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(Signed{Payload: b64(payload), Sig: b64(ed25519.Sign(priv, payload))})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := VerifyCommand([]ed25519.PublicKey{pub}, raw, "srv_mine", now); err == nil {
			t.Errorf("id %q was accepted", bad)
		}
	}

	// And signing refuses one too, so a caller cannot mint what no box will take.
	c := stopWeb(now.Add(time.Minute))
	c.ID = "../../etc/x"
	if _, err := SignCommand(priv, c); err == nil {
		t.Error("a command with an unfilable id was signed")
	}

	// The generator's own output is always acceptable.
	id, err := NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidCommandID(id); err != nil {
		t.Errorf("NewCommandID produced %q, which ValidCommandID refuses: %v", id, err)
	}
}

// ONE DOCUMENT, ONE READING.
//
// Go resolves a repeated key last-wins and says nothing, so a single signature
// could name two audiences and let two conforming parsers disagree about which.
// The audience check is what stops one signature being spent on every box the
// operator owns; it must not depend on every reader of a permanent format
// agreeing about which duplicate wins.
func TestARepeatedKeyIsRefused(t *testing.T) {
	pub, priv := device(t)
	now := time.Now()
	exp := now.Add(time.Minute).Unix()

	payload := []byte(fmt.Sprintf(
		`{"v":1,"id":"abc123","srv":"srv_theirs","srv":"srv_mine","exp":%d,"op":"app.stop","args":{"app":"web"}}`, exp))
	raw, err := json.Marshal(Signed{Payload: b64(payload), Sig: b64(ed25519.Sign(priv, payload))})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyCommand([]ed25519.PublicKey{pub}, raw, "srv_mine", now); err == nil {
		t.Error("a document naming two audiences was accepted at one of them")
	}

	// Nested objects too, since args is one.
	payload = []byte(fmt.Sprintf(
		`{"v":1,"id":"abc123","srv":"srv_mine","exp":%d,"op":"app.stop","args":{"app":"web","app":"other"}}`, exp))
	raw, _ = json.Marshal(Signed{Payload: b64(payload), Sig: b64(ed25519.Sign(priv, payload))})
	if _, _, err := VerifyCommand([]ed25519.PublicKey{pub}, raw, "srv_mine", now); err == nil {
		t.Error("a nested object with a repeated key was accepted")
	}

	// And an ordinary document still verifies, so this is not refusing everything.
	if _, _, err := VerifyCommand([]ed25519.PublicKey{pub}, signed(t, priv, stopWeb(now.Add(time.Minute))), "srv_mine", now); err != nil {
		t.Errorf("an ordinary command was refused: %v", err)
	}
}

// One encoding per document.
func TestANonCanonicalSignatureIsRefused(t *testing.T) {
	pub, priv := device(t)
	now := time.Now()
	raw := signed(t, priv, stopWeb(now.Add(time.Minute)))

	var env Signed
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	// A 64-byte signature is 86 base64 characters, and the final one carries two
	// real bits and four of slack -- so sixteen different characters decode to
	// the same signature under a lenient decoder. Built here rather than
	// searched for, because a search that finds nothing passes silently.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := env.Sig[len(env.Sig)-1]
	idx := strings.IndexByte(alphabet, last)
	if idx < 0 {
		t.Fatalf("signature ends in %q, which is not base64url", last)
	}
	alt := alphabet[(idx&0x30)|((idx+1)&0x0F)]
	if alt == last {
		t.Fatal("could not build a different spelling")
	}
	noncanonical := env.Sig[:len(env.Sig)-1] + string(alt)

	// It really is the same signature to a lenient decoder -- otherwise this
	// would be testing that a corrupted signature is refused, which is a
	// different and much easier thing.
	a, err := base64.RawURLEncoding.DecodeString(noncanonical)
	if err != nil {
		t.Fatalf("the alternative spelling does not decode: %v", err)
	}
	b, err := base64.RawURLEncoding.DecodeString(env.Sig)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("the alternative spelling is a different signature, not another spelling")
	}

	bad, err := json.Marshal(Signed{Payload: env.Payload, Sig: noncanonical})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyCommand([]ed25519.PublicKey{pub}, bad, "srv_mine", now); err == nil {
		t.Error("a non-canonical spelling of the signature was accepted, so one command has several encodings")
	}
}

// The arg KEY is bounded as well as the value.
func TestAnArgumentKeyCannotBeEnormous(t *testing.T) {
	pub, priv := device(t)
	now := time.Now()
	c := stopWeb(now.Add(time.Minute))
	c.Args[strings.Repeat("k", 100)] = "x"
	payload, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(Signed{Payload: b64(payload), Sig: b64(ed25519.Sign(priv, payload))})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyCommand([]ed25519.PublicKey{pub}, raw, "srv_mine", now); err == nil {
		t.Error("a 100-byte argument key was accepted")
	}
}
