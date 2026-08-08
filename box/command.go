package box

import (
	"bytes"
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

	// Sub is WHO this was signed for, and it is only meaningful because it is
	// inside the signature.
	//
	// komizo-be#180 made the registry key an authority to command, which solved
	// the product flow and cost the box the one identity it used to be able to
	// assert: with device keys, the key that verified WAS the person. Now every
	// command from the app verifies against the same registry key, so "which
	// device stopped this app" has exactly one answer for every account komizo
	// serves, which is no answer at all.
	//
	// So the service names the account it signed for. The box cannot check that
	// claim -- it has no idea who komizo's users are, and asking would be the
	// network dependency registry.md §6 exists to remove -- but it does not need
	// to. SETTING THIS REQUIRES SIGNING. A caller who could put an arbitrary
	// subject here could put an arbitrary op here, and the signature is what
	// stops both. It is exactly as trustworthy as the key that signed it, which
	// is the correct amount for a field whose whole job is attribution.
	//
	// OPTIONAL, and stays optional. A command signed by an operator's device key
	// carries no subject and does not need one: the key itself is the identity,
	// and that path is unchanged. An empty value means "the signer did not say",
	// which stopped.go renders as the device rather than as nobody.
	Sub string `json:"sub,omitempty"`

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
	if c.ID != "" {
		if err := ValidCommandID(c.ID); err != nil {
			return Signed{}, err
		}
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

// ValidCommandID is what an id may be.
//
// The alphabet NewCommandID produces and nothing else, because this string is
// joined into a path to name a result -- and the id is chosen by whoever
// signed, which is not the same as being safe. A device that was planted is
// still a device somebody can lose.
//
// Checked in the ENVELOPE rather than only where a file is opened. That was the
// bug: the one place that looked at an id was resultPath, so an id it refused
// made the box unable to record the command and unable to notice a replay of
// it, which is worse than refusing the command outright.
func ValidCommandID(id string) error {
	if id == "" || len(id) > 64 {
		return fmt.Errorf("a command id is 1 to 64 characters; this one is %d", len(id))
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return fmt.Errorf("%q is not a command id", id)
		}
	}
	return nil
}

// MaxSubjectBytes bounds the account name in an envelope.
//
// Generous next to what fills it -- komizo signs a PocketBase record id, which
// is fifteen characters -- and deliberately not sized to that. The box does not
// get to decide what a service calls its accounts, and a limit tuned to today's
// id would be a limit that breaks the day the service changes one.
const MaxSubjectBytes = 64

// validSubject is what may be attributed.
//
// The same alphabet as a command id, and the same reason: this string is copied
// out of a signed envelope into a file root writes. Empty is valid and is the
// ordinary case for a command signed by a device.
func validSubject(s string) bool {
	if len(s) > MaxSubjectBytes {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
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

	// ONE DOCUMENT, ONE READING. Go resolves a repeated key last-wins and says
	// nothing, so {"srv":"srv_theirs","srv":"srv_mine"} is a single signature
	// that two conforming parsers can disagree about the audience of. The
	// audience check is what stops one signature being spent on every box the
	// operator owns, and it must not rest on every present and future reader of
	// a permanent format agreeing about which duplicate wins.
	if hasDuplicateKeys(payload) {
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
		//
		// The COMMAND comes back with it. Everything from here down has already
		// passed the signature, so the caller is a device this box trusts and is
		// entitled to be told -- and telling them means filing a result under
		// the id, which needs the id. A refusal still returns nothing.
		return c, signer, fmt.Errorf("this command is v%d and this box speaks v%d", c.V, CommandVersion)
	case ValidCommandID(c.ID) != nil:
		// Refused by the ENVELOPE, not merely by whatever files it later.
		// resultPath used to be the only thing that looked at an id, and an id
		// it could not file -- "a.b", "..", anything with a separator --
		// bypassed replay protection completely: Applied could not find a
		// record, and WriteResult could not write one, so the same signed bytes
		// applied again every time they arrived.
		return Command{}, nil, ErrCommandRefused
	case serverID == "" || c.Srv != serverID:
		// The audience check. A box with no id of its own refuses everything,
		// which is correct for a machine no registry has heard of.
		return Command{}, nil, ErrCommandRefused
	case time.Unix(c.Exp, 0).Add(commandLeeway).Before(now):
		return Command{}, nil, ErrCommandRefused
	case time.Unix(c.Exp, 0).After(now.Add(MaxCommandTTL + commandLeeway)):
		// Dated too far out. Without this the signer chooses how long a captured
		// signature stays spendable, which is exactly the thing a short life is
		// for.
		return Command{}, nil, ErrCommandRefused
	case !validSubject(c.Sub):
		// Bounded and narrow-alphabeted for the reason ValidCommandID is: this
		// value LEAVES the envelope. It is written into an app's own record as
		// STOPPED_BY, and that record is read by three parsers in two languages,
		// one of them generated into a script that runs as root on every deploy.
		//
		// setStateValues refuses a newline in a value and is the guard that
		// matters; this is the second one, and it is here rather than only there
		// because a field the box will not act on should be refused before it is
		// acted on. A subject that cannot be written is a stop that half happens:
		// the app goes down and the record does not say so.
		return Command{}, nil, ErrCommandRefused
	case !knownOp(c.Op):
		return c, signer, fmt.Errorf("this box does not know how to %q", c.Op)
	}
	for k, v := range c.Args {
		if len(k) > 64 || len(v) > 256 {
			return Command{}, nil, ErrCommandRefused
		}
	}
	return c, signer, nil
}

// hasDuplicateKeys reports whether any object in the document names a key twice.
//
// A token walk, because encoding/json offers no other way to see it: Unmarshal
// has already collapsed them by the time a caller could look.
func hasDuplicateKeys(b []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(b))
	type frame struct {
		obj       bool
		keys      map[string]bool
		expectKey bool
	}
	var st []*frame
	for {
		t, err := dec.Token()
		if err != nil {
			// Malformed or finished. Unmarshal reports the first; the second is
			// a document with no duplicate in it.
			return false
		}
		top := func() *frame {
			if len(st) == 0 {
				return nil
			}
			return st[len(st)-1]
		}
		if f := top(); f != nil && f.obj && f.expectKey {
			if k, ok := t.(string); ok {
				if f.keys[k] {
					return true
				}
				f.keys[k] = true
				f.expectKey = false
				continue
			}
		}
		switch v := t.(type) {
		case json.Delim:
			switch v {
			case '{':
				st = append(st, &frame{obj: true, keys: map[string]bool{}, expectKey: true})
			case '[':
				st = append(st, &frame{})
			case '}', ']':
				if len(st) > 0 {
					st = st[:len(st)-1]
				}
				if f := top(); f != nil && f.obj {
					f.expectKey = true
				}
			}
		default:
			if f := top(); f != nil && f.obj {
				f.expectKey = true
			}
		}
	}
}

// commandLeeway is the allowance for a clock that is not quite ours.
//
// Applied to BOTH ends, which is a correction: it was on the ceiling only, so a
// box running fast refused everything as expired with no allowance at all, and
// the symptom was an app whose buttons did nothing. token.go extends validity
// past expiry for the same reason.
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

	// OpAppAdd sets an app up.
	//
	// NOT "or updates one", which is what this said and could not do. `pubkey`
	// is mandatory and alpine.sh WRITES authorized_keys, so pointing this at an
	// app that already exists rotates its deploy key and breaks that repository's
	// CI -- where `komizo add` reads the existing values back off the box first.
	// Updating over this transport is a separate op with its own arguments, not
	// this one used twice.
	//
	// The op that mints nothing. `komizo add` on the command line generates a
	// deploy keypair and prints the private half; a command carries only the
	// PUBLIC half, because a result file lives where the account that talks to
	// the internet can read it and report.go says never, in anything it can
	// read, "registry tokens, private keys". The app generates the pair and
	// shows the private half once -- app-only.md §5a.
	OpAppAdd = "app.add"

	// OpAppRotate replaces one app's deploy key and changes nothing else.
	//
	// nicodes/komizo-be#112. The moment a deploy key is discovered leaked is the
	// moment most likely to happen away from a laptop, and it was the one
	// capability with time pressure that the app could not reach.
	//
	// SEPARATE FROM app.add RATHER THAN app.add WITH FEWER ARGUMENTS. app.add
	// carries every setting an app has -- config image, deploy account, app
	// directory, hostnames -- and a caller that had to supply those to rotate a
	// key would be a caller that could CHANGE them while rotating one. The
	// screen doing it knows the app's name and nothing else, and it should not
	// have to know more to revoke a credential.
	//
	// So the box reads the rest off its own record. Every setting comes from
	// /var/lib/komizo/apps/<app>.env, which root wrote, and the only thing the
	// envelope decides is which app and which key.
	//
	// AND THE APP MUST ALREADY EXIST. app.add creates one; this refuses a name
	// it has no record of rather than provisioning it, because "rotate the key
	// of an app that is not here" is a typo and creating an app in response to
	// one is the worst available reading of it.
	OpAppRotate = "app.rotate"

	// OpLogsRead is a READ, and the only op here that nothing applies.
	//
	// It exists because app-only.md §5 asks for logs to be authorised by the
	// DEVICE rather than by the registry: a read token names a server and an
	// expiry and no user, so the ownership check is the service's to make, and
	// whoever holds its signing key could otherwise mint one for any box. That
	// is already true of the report and the history -- registry.md §6 decided it
	// -- and §5 refuses to put the most sensitive bytes on the machine behind
	// the same single environment variable.
	//
	// The serving account verifies this itself, which grants it nothing: the
	// keys are public, and verifying with a public key is not signing with one.
	//
	// It is NOT an op /v1/commands accepts -- see ApplyOps. A comment here once
	// claimed rootd would refuse it, and rootd did: it took the file, verified
	// it, wrote a claim and wrote a failure. Refusing it costs a public-key
	// operation and two writes; refusing it at the route costs nothing.
	OpLogsRead = "logs.read"

	// OpReportRead and OpHistoryRead are the same shape, for the same reason.
	//
	// komizo-be#58: the report and the history were behind the registry token
	// alone, so whoever held the service's signing key could read every enrolled
	// box -- which is the sentence komizo.dev is built on, being true of two
	// routes out of four. §5 had already refused that trade for logs; this is the
	// same refusal applied consistently rather than a new argument.
	//
	// Neither is applied. See ApplyOps.
	OpReportRead  = "report.read"
	OpHistoryRead = "history.read"

	// OpMetricsRead is what the proxy's access log says about an app: requests
	// and failures per minute, per service.
	//
	// komizo#80. It was computed only by `komizo-box poll` and `monitor`, which
	// the CLI runs over SSH, so the TUI could draw a sparkline and the app could
	// not -- the one column of the interface with no path to a device. A READ,
	// like the three above, and not applied.
	//
	// SEPARATE FROM history.read RATHER THAN FOLDED INTO IT. Samples are written
	// on rootd's timer; metrics are computed from a log over an arbitrary
	// window. Serving them together would force one cadence on two things that
	// do not share one, and would grow every stored sample to carry counts it
	// was not measured with.
	OpMetricsRead = "metrics.read"
)

// commandOps is every op an ENVELOPE may name.
var commandOps = []string{OpAppStart, OpAppStop, OpAppRestart, OpAppAdd, OpAppRotate,
	OpLogsRead, OpReportRead, OpHistoryRead, OpMetricsRead}

// ApplyOps is the subset /v1/commands accepts, which is every op that CHANGES
// something. app.add is one of them: it provisions, which is work for root.
//
// Two sets because they answer different questions, and one set answering both
// is how a read envelope became something root would pick up, parse and write
// two files about. apply.go asserts its own dispatch against this, so adding an
// op to one and not the other is a refusal rather than a silent success.
var ApplyOps = []string{OpAppStart, OpAppStop, OpAppRestart, OpAppAdd, OpAppRotate}

// Applies reports whether this op is one the command route takes.
func Applies(op string) bool { return slices.Contains(ApplyOps, op) }

// KnownOp reports whether this box would recognise the name at all.
//
// EXPORTED FOR THE SIGNER, which since komizo-be#180 is the service rather than
// a device. Something has to decide what it is willing to put a signature on,
// and the answer is "an op a box could act on" -- so the service asks this
// rather than keeping a list of its own. Two lists of what may be signed are two
// chances to disagree about it, and the one that is wrong is whichever the
// reviewer did not read; operator.go makes the same argument about device-key
// parsers, in the same words.
//
// A FUNCTION RATHER THAN THE SLICE. `commandOps` stays unexported because an
// exported slice is a mutable global: any package that can see it can append to
// it, and what it would be appending to is the set of instructions a box acts
// on. ApplyOps above is exported and predates this, which makes it the exception
// to fix rather than the precedent to follow.
//
// This is NOT an authorisation check and must not be read as one. It says a name
// is spellable, nothing more. Who may spend it is settled by ownership at the
// service and by the signature at the box.
func KnownOp(op string) bool { return knownOp(op) }

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

// AddSpec is app.add's arguments, checked.
//
// A separate step from verifying the envelope, and a separate one again from
// running anything: the signature says a device this box trusts sent it, and
// says nothing about whether "web; rm -rf /" is an app name.
type AddSpec struct {
	App       string
	Config    string
	PubKey    string
	User      string
	AppDir    string
	KnownAs   []string
	HardenSSH bool
}

// AddOf reads app.add's arguments, refusing anything that is not what it claims.
// RotateOf is which app and which key, and nothing else.
//
// The public half only. A private key is not carried, generated or returned
// here for the reason OpAppAdd gives: a result file lives where the account
// that talks to the internet can read it.
//
// The key rules are AddOf's, deliberately shared rather than restated -- a
// second copy is a second chance for one of them to relax, and the one that
// matters is that komizo authorises ed25519 and nothing else, whoever signed
// for it.
func (c Command) RotateOf() (app, pubkey string, err error) {
	app, err = c.AppOf()
	if err != nil {
		return "", "", err
	}
	if strings.HasPrefix(app, "_") {
		return "", "", fmt.Errorf("%q is reserved", app)
	}
	pubkey = c.Args["pubkey"]
	if err := validPubKey(pubkey); err != nil {
		return "", "", err
	}
	// NOTHING ELSE IS ACCEPTED. An envelope carrying `config` or `app_dir`
	// alongside a rotation is one whose signer meant something this op does not
	// do, and silently ignoring it is how a caller comes to believe a setting
	// changed. Refused rather than dropped.
	for k := range c.Args {
		switch k {
		case "app", "pubkey":
		default:
			return "", "", fmt.Errorf("app.rotate does not take %q -- it changes the deploy key and nothing else", k)
		}
	}
	return app, pubkey, nil
}

// validPubKey is what komizo will write into an authorized_keys file.
func validPubKey(k string) error {
	if k == "" {
		return fmt.Errorf("needs the public half of a deploy key")
	}
	if strings.ContainsAny(k, "\n\r") {
		return fmt.Errorf("a deploy key is one line")
	}
	if !strings.HasPrefix(k, "ssh-ed25519 ") {
		return fmt.Errorf("a deploy key is ssh-ed25519")
	}
	return nil
}

func (c Command) AddOf() (AddSpec, error) {
	app, err := c.AppOf()
	if err != nil {
		return AddSpec{}, err
	}
	spec := AddSpec{
		App:       app,
		Config:    c.Args["config"],
		PubKey:    c.Args["pubkey"],
		User:      c.Args["user"],
		AppDir:    c.Args["app_dir"],
		HardenSSH: c.Args["harden_ssh"] == "1",
	}

	// The PUBLIC half of a deploy key, and one line of it. A second line would
	// be a second key nobody asked to authorise.
	//
	// komizo issues ed25519 and nothing else. Refusing the rest means the box
	// never authorises a key type this project has not thought about, whoever
	// signed for it -- and app.rotate holds to the same rule from the same
	// function, because two copies is two chances for one of them to relax.
	if err := validPubKey(spec.PubKey); err != nil {
		return AddSpec{}, fmt.Errorf("app.add %w", err)
	}

	// RESERVED. validateApp and alpine.sh both refuse a leading underscore --
	// it is komizo's own namespace under /srv, where the shared proxy lives --
	// and AppOf does not, because until this op existed AppOf only ever named an
	// app that already exists. Routing it into PROVISIONING is what made the gap
	// reachable, so the refusal belongs to the op that provisions.
	if strings.HasPrefix(spec.App, "_") {
		return AddSpec{}, fmt.Errorf("%q is reserved", spec.App)
	}

	// A registry reference with NO tag: alpine.sh appends its own, and a tag
	// here would produce something docker cannot pull.
	//
	// REQUIRED, because the script requires it. Optional here it was accepted,
	// claimed, and then died inside a shell as a failure mid-provision rather
	// than as a refusal -- and a caller cannot tell those apart.
	if spec.Config == "" {
		return AddSpec{}, fmt.Errorf("app.add needs the image its compose file comes from")
	}
	if !onlyImageChars(spec.Config) {
		return AddSpec{}, fmt.Errorf("%q is not a registry path", spec.Config)
	}
	if strings.Contains(LastSegment(spec.Config), ":") {
		return AddSpec{}, fmt.Errorf("a config image carries no tag")
	}
	// AND IT ENDS IN A SEGMENT. "ghcr.io/a/web:1/" has no tag by the rule above
	// -- the last segment is empty -- and the box appends its own, producing
	// "ghcr.io/a/web:1/:v1", which docker cannot parse. Accepted, the whole
	// provision SUCCEEDS and every later deploy fails at `docker pull`, a long
	// way from the field that caused it. That is worse than the mid-provision
	// failure this function refuses two rules above, and for the same reason.
	if strings.HasSuffix(spec.Config, "/") {
		return AddSpec{}, fmt.Errorf("a config image does not end in %q", "/")
	}

	if spec.AppDir != "" {
		// Absolute. Relative it becomes a path relative to whatever the applier
		// happens to be in, and leading with a dash it becomes a flag.
		if !strings.HasPrefix(spec.AppDir, "/") {
			return AddSpec{}, fmt.Errorf("app_dir must be absolute")
		}
		if !onlyPathChars(spec.AppDir) {
			return AddSpec{}, fmt.Errorf("%q is not a path", spec.AppDir)
		}
		// NO "..", which is the guard this path had lost while the CLI's
		// validateAppDir kept it -- so the newer, internet-reachable trigger was
		// the weaker of the two, which is the wrong way round.
		//
		// The reason is validateAppDir's, unchanged: the path is recorded and
		// later handed to `rm -rf` on removal, and the removal guard refuses a
		// fixed set of LITERAL paths, which /srv/../etc walks straight past. It
		// is also chown'd and chmod'd as root on the way in, so a traversal
		// component points those at somewhere they were never meant to reach --
		// `chmod 750 /etc` takes the box off the network and needs a console to
		// undo.
		if hasDotDot(spec.AppDir) {
			return AddSpec{}, fmt.Errorf("app_dir must not contain a %q component", "..")
		}
	}

	for _, n := range strings.Split(c.Args["known_as"], ",") {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		// validHostname, NOT ValidateAPIHost. The latter decides whether THIS
		// BOX's own endpoint can be issued a public certificate, and refused
		// `box`, `10.0.0.5` and `my_host.example.com` here -- every one of which
		// `komizo add --known-as` accepts, because this field is the names CI
		// dials the APP by and has nothing to do with certificates. Two
		// unrelated jobs sharing one validator also means relaxing it for
		// endpoints would silently widen what a signed command may write.
		if err := validHostname(n); err != nil {
			return AddSpec{}, fmt.Errorf("known_as: %w", err)
		}
		spec.KnownAs = append(spec.KnownAs, n)
	}

	// The deploy account. Defaulted rather than required, because the CLI
	// defaults it too and a command that must state it is one more thing an app
	// can get wrong.
	if spec.User == "" {
		spec.User = "komizo-" + spec.App
	}
	// CHECKED EITHER WAY. The default was exempt, and it is derived from an app
	// name -- which may be longer than an account may be, and which allows
	// uppercase where an account does not.
	if !validAccount(spec.User) {
		return AddSpec{}, fmt.Errorf("%q is not an account name", spec.User)
	}
	if spec.User == "root" {
		// Refused here as well as by alpine.sh, and said as its own sentence:
		// "root" passes every character rule and is the one account this must
		// never be. The deploy account exists to be unprivileged.
		return AddSpec{}, fmt.Errorf("the deploy account must not be root")
	}
	return spec, nil
}

// hasDotDot reports whether a path has a ".." COMPONENT.
//
// Component rather than substring: "/srv/..foo" is a directory whose name
// begins with two dots and is not traversal.
func hasDotDot(s string) bool {
	return s == ".." || strings.HasPrefix(s, "../") ||
		strings.HasSuffix(s, "/..") || strings.Contains(s, "/../")
}

// validHostname is a name CI connects by, which is not the same question as
// whether a certificate authority would issue for it. internal/app's
// validateHost, in the terms this package can check.
func validHostname(s string) error {
	// A leading hyphen would let the name be read as an option by ssh or
	// ssh-keyscan, which is the argv-injection class rather than a naming one.
	if s == "" || len(s) > 253 || strings.HasPrefix(s, "-") {
		return fmt.Errorf("%q is not a hostname", s)
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '.' || r == '_' || r == '-') {
			return fmt.Errorf("%q is not a hostname", s)
		}
	}
	return nil
}

func onlyPathChars(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_' || r == '/':
		default:
			return false
		}
	}
	return s != ""
}

// LastSegment is the part of a registry reference a TAG would be in.
//
// THE RULE: a colon AFTER the last slash is a tag; a colon before it is a
// registry port. `reg.example.com:5000/a/web` has no tag; `a/web:1` does. That
// sentence lived in internal/app and in alpine.sh and not in the function that
// now decides it for both, which is how a rule goes missing while three copies
// of the code that implements it survive.
//
// Agrees with `${VAR##*/}`, which is what scripts/alpine.sh uses and therefore
// what actually decides what gets pulled -- see segment_test.go, which pins this
// against a real shell rather than against a second Go opinion.
//
// One function because there were two, and they disagreed. The CLI took
// everything after the last "/" and the box used path.Base, which differ on a
// trailing slash: for "ghcr.io/a/web:1/" the first yields "" -- no colon, no
// tag, accepted -- and the second yields "web:1", refused. So there was a value
// `komizo add` took and a signed app.add would not, which is the app able to do
// less than the CLI.
//
// Not exploitable, since both refuse the shapes that matter. Fixed by removing
// the second opinion rather than by picking a winner: two ways of finding the
// last segment is how this happened, and it is how it would happen again.
func LastSegment(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

func onlyImageChars(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_' || r == '/' || r == ':':
		default:
			return false
		}
	}
	return s != ""
}

// validAccount is the deploy account, in the same characters internal/app's
// validateUser and alpine.sh's CI_USER case both allow.
//
// UPPERCASE IS ALLOWED, which it was not: this was lowercase-only, so
// `--user Web` was a name the CLI took and a signed command could not carry --
// a field the app could do less with than the CLI, which is the one direction
// the parity rule does not permit. See TestASignedCommandTakesWhatTheCLITakes.
//
// The length bound is a deliberate exception to that agreement, and the only
// one: an account name longer than 32 characters is one `adduser` refuses on
// the far end, so the CLI's silence about it is a failure that happens over
// SSH minutes later rather than a capability the app is missing.
func validAccount(s string) bool {
	if s == "" || len(s) > 32 || s[0] == '-' {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' ||
			r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
