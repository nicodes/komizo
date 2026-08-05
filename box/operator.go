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
// ALL OR NOTHING. One unreadable key fails the set rather than being skipped,
// because the alternative is a box that silently trusts fewer devices than the
// operator believes it does -- and the way that is discovered is somebody's app
// refusing to work on one box out of six, months later, with nothing to read.
// A conf carrying a value somebody meant to work is the same argument the
// service makes about an unreadable signing key.
// Nothing calls this yet. The enforcement point is rootd verifying a command --
// app-only.md §9 step 3 -- and until then the only way an unparseable key
// reaches here is somebody editing agent.json by hand, because both flag
// parsers refuse one on the way in.
func (c AgentConf) TrustedKeys() ([]ed25519.PublicKey, error) {
	out := make([]ed25519.PublicKey, 0, len(c.OperatorKeys))
	for i, raw := range c.OperatorKeys {
		k, err := ParseDeviceKey(raw)
		if err != nil {
			return nil, fmt.Errorf("operator key %d of %d: %w", i+1, len(c.OperatorKeys), err)
		}
		out = append(out, k)
	}
	return out, nil
}

// CanCommand reports whether anything may tell this box to do something.
//
// Deliberately separate from CanServe. A box can serve reads with no operator
// key at all -- reading is authorised by the registry's signature and commanding
// is not -- and conflating them would mean planting a device key was the price
// of looking at a chart.
//
// It DOES require a server id, which couples command authority to registry
// state: `komizo-box unenrol` deletes the whole credential, so leaving the
// service also de-authorises every device. That follows from a command naming
// the box it is for (app-only.md §4's srv), and it is worth knowing rather than
// discovering -- a box taken off komizo is managed over SSH, as it was before
// it ever joined.
func (c AgentConf) CanCommand() bool { return len(c.OperatorKeys) > 0 && c.ServerID != "" }

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
