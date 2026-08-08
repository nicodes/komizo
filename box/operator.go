package box

import (
	"crypto/ed25519"
	"fmt"
	"slices"
	"strings"
)

// The keys this box will take orders from.
//
// komizo-be design/app-only.md §4: the box's API is the TRANSPORT and a
// signature is the AUTHORITY. A caller that merely authenticated -- with a
// bearer token the registry signed, as reads use -- is a caller whose authority
// belongs to whoever mints tokens, and that would make komizo able to command
// every box it knows about. appify.md §1 exists to prevent exactly that.
//
// So the app signs, and the box verifies against keys planted HERE, by an
// operator, with root. The service never chooses what is in this list: it is
// carried by the person setting the box up, which is the one moment somebody
// with root is present. design/enrolment.md §1 reserved this and said why it
// could not wait --
//
//	enrolment is the only moment the operator is present with root, and adding
//	it later means touching every enrolled box.
//
// A box with no operator keys is not broken and is not unusual. It reports, it
// serves reads, and it accepts no commands -- which is every box that exists
// today, and is the state this leaves them in until somebody plants one.

// DeviceKeyPrefix marks a device's public key.
//
// Public, so this is not the leak-detection argument the token prefixes make.
// It is so that a string somebody has pasted into an issue, a script or the
// wrong flag can be identified as what it is without being decoded first.
const DeviceKeyPrefix = "kmz_dev_"

// FormatDeviceKey renders a public key as it is carried and stored.
func FormatDeviceKey(pub ed25519.PublicKey) string {
	return DeviceKeyPrefix + b64(pub)
}

// ParseDeviceKey reads one, and is strict about the prefix.
//
// Strict because the failure it prevents is planting the WRONG STRING as an
// authority. A registry key, an agent token and a device key are all opaque
// base64-ish blobs to a person moving them between two windows, and a box that
// quietly accepted any of them would be a box trusting something nobody meant
// to trust.
func ParseDeviceKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	rest, ok := strings.CutPrefix(s, DeviceKeyPrefix)
	if !ok {
		return nil, fmt.Errorf("a device key starts with %s -- this one does not, so it is some other kind of credential", DeviceKeyPrefix)
	}
	b, err := unb64(rest)
	if err != nil {
		return nil, fmt.Errorf("that device key is not valid base64: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("that device key is %d bytes, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// TrustedKeys is what this box will verify a command against.
//
// TWO SOURCES, and the second one is a reversal recorded rather than edited
// away. The operator keys above are carried here by a person with root. The
// REGISTRY KEY is issued by the service at enrolment, and it is now also an
// authority to command -- komizo-be#180.
//
// The whole of the argument for that is the product flow. Somebody runs
// `komizo login`, runs `komizo init`, and expects the app to work on every
// device they are signed into. Device keys made that a per-device root session:
// each browser generated its own keypair and each one had to be planted on the
// box by hand before any button did anything. That is not a step that can be
// asked for, and it was the step that killed the flow.
//
// What is given up is stated plainly, because it is real: KOMIZO CAN COMMAND
// EVERY ENROLLED BOX. app.add creates a deploy account, so that means root.
// design/app-only.md §6 was written to prevent exactly this and is reversed by
// komizo-be#180 -- see the reversal note there, which carries the argument.
//
// What is NOT given up is the shape of the check. This is a key in a trusted
// set, verified by the same VerifyCommand, against the same audience and the
// same expiry -- authority by a stated fact rather than by the absence of one.
// The alternative considered was deleting verification and letting the bearer
// token be the whole authority, which would have deleted every test asserting
// an untrusted caller is refused: the written inventory of what this box
// guarantees.
//
// A box with no registry key still commands nothing, and that is the same
// sentence as before with a different subject: it is a box no service has
// enrolled.
//
// ALL OR NOTHING. One unreadable key fails the set rather than being skipped,
// because the alternative is a box that silently trusts fewer devices than the
// operator believes it does -- and the way that is discovered is somebody's app
// refusing to work on one box out of six, months later, with nothing to read.
// A conf carrying a value somebody meant to work is the same argument the
// service makes about an unreadable signing key. That now covers the registry
// key too: a box whose registry key is corrupt refuses commands rather than
// falling back to whatever operator keys happen to be there, because the
// fallback would be a box quietly commanding-by-device on the day the service
// stopped working, with nobody able to tell which mode they were in.
func (c AgentConf) TrustedKeys() ([]ed25519.PublicKey, error) {
	out := make([]ed25519.PublicKey, 0, len(c.OperatorKeys)+1)
	for i, raw := range c.OperatorKeys {
		k, err := ParseDeviceKey(raw)
		if err != nil {
			return nil, fmt.Errorf("operator key %d of %d: %w", i+1, len(c.OperatorKeys), err)
		}
		out = append(out, k)
	}
	if c.RegistryKey != "" {
		k, err := ParsePublicKey(c.RegistryKey)
		if err != nil {
			return nil, fmt.Errorf("the registry key in this box's credential: %w", err)
		}
		out = append(out, k)
	}
	return out, nil
}

// CanCommand reports whether anything may tell this box to do something.
//
// Deliberately separate from CanServe, and no longer a different answer in
// practice. A box can serve reads with no operator key at all, and since
// komizo-be#180 it can be commanded with none either -- the registry key that
// verifies its read tokens also verifies a command signed for its owner.
//
// The two stay separate functions because they are separate questions and the
// answers can still differ: a box enrolled against a service that offers no
// signing key has no registry key, serves nothing, and commands nothing; a box
// with operator keys and no registry key commands but does not serve.
//
// It DOES require a server id, which couples command authority to registry
// state: `komizo-box unenrol` deletes the whole credential, so leaving the
// service also de-authorises every device AND the service itself. That follows
// from a command naming the box it is for (app-only.md §4's srv), and it is
// worth knowing rather than discovering -- a box taken off komizo is managed
// over SSH, as it was before it ever joined.
func (c AgentConf) CanCommand() bool {
	return c.ServerID != "" && (len(c.OperatorKeys) > 0 || c.RegistryKey != "")
}

// Fingerprint is a device key in the form somebody compares by eye.
//
// The first and last eight characters of the key ITSELF, not a hash of it. A
// hash would be a second thing to compute in two places and get wrong once, and
// what a person actually does is look at a screen and look at a terminal and
// see whether they match. The app renders exactly this form, and the two ends
// agreeing is the whole of the check.
//
// It is not a security boundary on its own. The key is carried in the command
// the operator pastes, so this catches a truncated paste and a key that went
// somewhere unexpected -- not a browser that was served a dishonest bundle,
// which would show a matching fingerprint for a key that was never yours.
func Fingerprint(key string) string {
	body := strings.TrimPrefix(key, DeviceKeyPrefix)
	if len(body) <= 16 {
		return body
	}
	return body[:8] + "…" + body[len(body)-8:]
}

// DeviceKeyList collects a repeatable --device-key on any command line.
//
// ONE definition, used by the CLI on the laptop and by komizo-box on the
// server. There were two, briefly, with the same TrimSpace-parse-dedupe body in
// both -- and scripts/embed.go already records why that is wrong in this
// codebase's own words: "The app package had its own copy; it now calls this
// one, so there is a single definition of the rule."
//
// It matters more here than for a rule about shell quoting. Two parsers for
// what counts as an authority are two chances to disagree about it, and the one
// that is wrong is whichever the reviewer did not read.
type DeviceKeyList []string

func (d *DeviceKeyList) String() string { return strings.Join(*d, ",") }

// Set validates as it goes, so an error names the value that is wrong.
//
// These are copied between two windows, which is where a truncated base64
// string comes from -- and a truncated authority that failed later, on the box,
// would fail after the connection and in the middle of somebody's setup.
func (d *DeviceKeyList) Set(v string) error {
	v = strings.TrimSpace(v)
	if _, err := ParseDeviceKey(v); err != nil {
		return err
	}
	if slices.Contains(*d, v) {
		// The same key twice is somebody pasting twice, and the result they
		// wanted is the result they get.
		return nil
	}
	*d = append(*d, v)
	return nil
}

// DeviceKeyUsage is the one wording for the flag, so the two commands that take
// it cannot describe it differently.
const DeviceKeyUsage = "a device that may command this box, from the app (repeatable)"
