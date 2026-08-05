package box

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// What it takes to tell a box to do something.
//
// komizo-be design/app-only.md §4. The box's API is the TRANSPORT and this
// signature is the AUTHORITY: a caller that merely authenticated -- with a
// bearer token the registry minted, as reads do -- has authority belonging to
// whoever mints tokens, which would make komizo able to command every box it
// knows about. So the app signs, and the box verifies against keys an operator
// planted with root. See operator.go for how they get there.
//
// This shape is PERMANENT from the moment it ships, the same as the read
// routes and for the same reason: the box and whatever talks to it are separate
// releases. Command types are additive -- a new one is a new name, never a
// changed envelope.
//
// Hand-rolled rather than JWT, for the reason token.go gives: both ends are
// ours, there is exactly one algorithm and always will be, and a JWT library
// brings an algorithm-negotiation surface for a format that needs none.

// CommandVersion is the envelope's schema. Its own number, not APIVersion and
// not Version: a new route does not change what a command is, and a new report
// field does not either.
const CommandVersion = 1

// CommandPrefix marks the signed form, so a string in a log or a bug report can
// be identified without being decoded.
const CommandPrefix = "kmz_cmd_"

// MaxCommandBytes bounds one command.
//
// Small on purpose. A command is an op and a handful of short arguments; this
// is reachable from a route on the internet, and an unbounded read is an
// unbounded allocation before anything has been verified.
const MaxCommandBytes = 8 << 10

// MaxCommandTTL is the longest a command may be valid for.
//
// The threat is not a stranger -- it is a service that ROUTED the request and
// chose not to deliver it, holding a valid signature to spend later. A short
// life is what makes that captured signature nearly worthless, so the box
// refuses one dated further out rather than trusting the signer's judgement.
const MaxCommandTTL = 5 * time.Minute

// Command is one instruction, and the whole of what is signed.
type Command struct {
	// V is the envelope version, so a box can say "I do not speak this" rather
	// than misreading a field that moved.
	V int `json:"v"`

	// ID names this command and the result written for it. Random, not a
	// counter: a counter is guessable, and the id is what makes a REPLAY
	// refusable -- a second arrival of an id already applied is the same
	// command, not a new one.
	ID string `json:"id"`

	// Srv is the audience, and it is not optional.
	//
	// registry.md §6 had to learn this for reads: "a token signed for box A must
	// be useless at box B, or the registry becomes a skeleton key for every box
	// it knows about". A command without it is worse than a read token without
	// it, because it is a signed INSTRUCTION spendable on every box the operator
	// owns.
	Srv string `json:"srv"`

	// Exp is unix seconds. See MaxCommandTTL.
	Exp int64 `json:"exp"`

	// Op is a NAME, never a command line.
	//
	// The box maps this to its own call and builds the arguments itself. A
	// signed command containing a shell string would be remote code execution by
	// design, with the signature as the thing that authorised it.
	Op string `json:"op"`

	// Args are flat strings, deliberately.
	//
	// No nesting, no lists, no numbers. Every value here is destined to become
	// an argument to something on this machine, and a nested structure is a
	// second parser with its own opinions about what a value is. An op that one
	// day genuinely needs structure is a version bump, which is a cost worth
	// paying to keep this one shallow.
	Args map[string]string `json:"args,omitempty"`
}

// Signed is the envelope as it crosses the wire.
//
// The payload travels as OPAQUE BYTES and the signature covers those exact
// bytes. Not a struct the box re-marshals before checking: JSON has no single
// serialisation, so re-encoding to verify means verifying something the signer
// never saw, and the gap between the two is where a canonicalisation bug lives.
type Signed struct {
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
}

// SignCommand produces the envelope for one command.
//
// Fills in V, and an ID if the caller left one out, so those two cannot be
// forgotten at a call site.
func SignCommand(priv ed25519.PrivateKey, c Command) (Signed, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Signed{}, fmt.Errorf("that is not an ed25519 private key")
	}
	if c.Srv == "" {
		return Signed{}, fmt.Errorf("a command must name the server it is for")
	}
	if c.Op == "" {
		return Signed{}, fmt.Errorf("a command must say what to do")
	}
	c.V = CommandVersion
	if c.ID == "" {
		id, err := NewCommandID()
		if err != nil {
			return Signed{}, err
		}
		c.ID = id
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return Signed{}, err
	}
	if len(payload) > MaxCommandBytes {
		return Signed{}, fmt.Errorf("that command is larger than %d bytes", MaxCommandBytes)
	}
	return Signed{Payload: b64(payload), Sig: b64(ed25519.Sign(priv, payload))}, nil
}

// NewCommandID is 128 random bits, hex-free and URL-safe.
func NewCommandID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return b64(b[:]), nil
}

// VerifyCommand decides whether this box will act on what it was sent.
//
// The order is deliberate and is the mitigation architecture.md §9 asked for
// when it leaned towards waking root on a file arriving: THE SIGNATURE IS
// CHECKED FIRST, so anything unsigned costs one public-key operation and a
// delete rather than any parsing of what it claims to be.
//
// keys is the operator set from AgentConf.TrustedKeys. An empty set refuses
// everything, which is the right answer for a box nobody has given a device to
// -- and is the state of every box that exists today.
//
// Which key matched is returned, because a result should be able to say who
// asked and because revoking one device later means knowing that.
func VerifyCommand(keys []ed25519.PublicKey, raw []byte, serverID string, now time.Time) (Command, ed25519.PublicKey, error) {
	if len(raw) > MaxCommandBytes {
		return Command{}, nil, ErrCommandRefused
	}
	var env Signed
	if err := json.Unmarshal(raw, &env); err != nil {
		return Command{}, nil, ErrCommandRefused
	}
	payload, err := unb64(env.Payload)
	if err != nil || len(payload) == 0 || len(payload) > MaxCommandBytes {
		return Command{}, nil, ErrCommandRefused
	}
	sig, err := unb64(env.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Command{}, nil, ErrCommandRefused
	}

	// First, and before the payload is looked at as anything but bytes.
	var signer ed25519.PublicKey
	for _, k := range keys {
		if len(k) == ed25519.PublicKeySize && ed25519.Verify(k, payload, sig) {
			signer = k
			break
		}
	}
	if signer == nil {
		return Command{}, nil, ErrCommandRefused
	}

	var c Command
	if err := json.Unmarshal(payload, &c); err != nil {
		return Command{}, nil, ErrCommandRefused
	}
	switch {
	case c.V != CommandVersion:
		// Said differently from a refusal, because it is not one: a box and an
		// app are separate releases and one being ahead is a normal state that
		// somebody can act on.
		return Command{}, nil, fmt.Errorf("this command is v%d and this box speaks v%d", c.V, CommandVersion)
	case c.ID == "":
		return Command{}, nil, ErrCommandRefused
	case serverID == "" || c.Srv != serverID:
		// The audience check. A box with no id of its own refuses everything,
		// which is correct for a machine no registry has heard of.
		return Command{}, nil, ErrCommandRefused
	case c.Exp <= now.Unix():
		return Command{}, nil, ErrCommandRefused
	case time.Unix(c.Exp, 0).After(now.Add(MaxCommandTTL + commandLeeway)):
		// Dated too far out. Without this the signer chooses how long a captured
		// signature stays spendable, which is exactly the thing a short life is
		// for.
		return Command{}, nil, ErrCommandRefused
	case !knownOp(c.Op):
		return Command{}, nil, fmt.Errorf("this box does not know how to %q", c.Op)
	}
	for k, v := range c.Args {
		if len(k) > 64 || len(v) > 256 {
			return Command{}, nil, ErrCommandRefused
		}
	}
	return c, signer, nil
}

// commandLeeway lets a box whose clock runs a little slow accept a command the
// app has just signed, the same allowance read tokens make.
const commandLeeway = 30 * time.Second

// ErrCommandRefused is every reason a command was not accepted.
//
// One error, deliberately. "Not signed by a key I hold", "meant for another
// box", "expired" and "malformed" are one answer as far as a caller is
// concerned, and telling them apart out loud is free reconnaissance about which
// keys a box trusts. rootd logs the detail locally, where the operator is.
var ErrCommandRefused = fmt.Errorf("this box will not act on that")

// The ops a box knows, which is the same closed set komizo-box implements.
//
// Named here so that VerifyCommand can refuse an unknown one BEFORE anything
// dispatches on it, and so that adding a verb is one edit rather than two that
// can disagree.
const (
	OpAppStart   = "app.start"
	OpAppStop    = "app.stop"
	OpAppRestart = "app.restart"
)

var commandOps = []string{OpAppStart, OpAppStop, OpAppRestart}

func knownOp(op string) bool { return slices.Contains(commandOps, op) }

// AppOf is the app an op names, checked as an app name rather than trusted.
//
// Checked HERE and not only where it is used, because this is the value that
// crosses from a signed document into an argument on this machine, and the
// rule that makes it safe should live beside the thing that decides a command
// is legitimate.
func (c Command) AppOf() (string, error) {
	name := c.Args["app"]
	if name == "" {
		return "", fmt.Errorf("%s needs an app", c.Op)
	}
	if strings.ContainsAny(name, "/.") || strings.HasPrefix(name, "-") {
		// A separator would make it a path and a leading dash would make it a
		// flag. Refused rather than sanitised: neither is a typo to be helpful
		// about, and this arrives over the internet.
		return "", fmt.Errorf("%q is not an app name", name)
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return "", fmt.Errorf("%q is not an app name", name)
		}
	}
	return name, nil
}
