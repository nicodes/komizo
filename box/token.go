package box

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The credential that lets somebody read a box.
//
// design/registry.md in komizo-be decides that a box serves its own data and
// the service keeps only what must outlive it. That makes "is this caller
// allowed to read this machine" a question the BOX has to answer, on its own,
// with no network call -- the service may be down, and a box that could not be
// read while its registry was unreachable would have moved the dependency it
// was supposed to remove.
//
// So the registry SIGNS and the box VERIFIES, against a public key planted at
// enrolment. enrolment.md §1 reserved exactly that key, and warned that adding
// it later means touching every enrolled box.
//
// Hand-rolled rather than JWT, and the reason is narrow: both ends are ours,
// the payload is two fields, and a JWT library brings an algorithm-negotiation
// surface -- `alg: none`, RS256-vs-HS256 confusion -- for a format that here
// has exactly one algorithm and always will. Ed25519 is in the standard
// library. The cost of the choice is that it is not interoperable with anything
// else, which is not a thing this token needs to be.

// ReadTokenPrefix marks a token as this kind, so a leaked string is
// identifiable at a glance -- in a log, a bug report, or a secret scanner.
const ReadTokenPrefix = "kmz_rd_"

// readClaims is the whole of what a read token says.
//
// Two fields, and both are refusals rather than permissions. There is no scope
// and no capability list: a token that verifies may read this one box, which is
// the only thing the API it opens can do.
type readClaims struct {
	// Server is the box this token is for. Checked against the box's OWN id,
	// so a token minted for one machine is useless at another -- without it the
	// registry becomes a skeleton key for every box it knows about. This is the
	// same defence komizo-be's Clerk verifier applies with its azp check.
	Server string `json:"srv"`
	// Expires is unix seconds. Short, because the registry can mint another
	// whenever somebody opens the app, and a long-lived one is a credential
	// sitting in a browser for a machine it can read.
	Expires int64 `json:"exp"`
}

// ErrUnauthorized covers every reason a token was not accepted.
//
// Which reason is deliberately not reported. "Expired", "forged" and "meant for
// another box" are one answer as far as a caller is concerned, and telling them
// apart out loud is free reconnaissance.
var ErrUnauthorized = errors.New("missing or invalid read token")

// readTokenLeeway keeps a token valid slightly past its expiry, so a box whose
// clock runs a few seconds fast does not refuse one the registry has just
// signed.
const readTokenLeeway = 30 * time.Second

// SignReadToken mints a token for one server. The registry calls this; a box
// never does.
//
// Exported from this package because the wire format has to have exactly one
// definition. The service reimplementing it from a specification is two
// implementations that can disagree about a security boundary, which is the
// failure this package exists to prevent for the report already.
func SignReadToken(priv ed25519.PrivateKey, serverID string, expires time.Time) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("that is not an ed25519 private key")
	}
	if serverID == "" {
		return "", errors.New("a read token must name a server")
	}
	payload, err := json.Marshal(readClaims{Server: serverID, Expires: expires.UTC().Unix()})
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, payload)
	return ReadTokenPrefix + b64(payload) + "." + b64(sig), nil
}

// VerifyReadToken decides whether a caller may read THIS box.
//
// serverID is the box's own id, from the credential enrolment left behind. A
// box that has not enrolled has no id, cannot be named by any token, and
// therefore refuses everything -- which is the correct answer for a machine no
// registry has ever heard of.
func VerifyReadToken(pub ed25519.PublicKey, token, serverID string, now time.Time) error {
	if len(pub) != ed25519.PublicKeySize || serverID == "" {
		return ErrUnauthorized
	}
	rest, ok := strings.CutPrefix(token, ReadTokenPrefix)
	if !ok {
		return ErrUnauthorized
	}
	encPayload, encSig, ok := strings.Cut(rest, ".")
	if !ok {
		return ErrUnauthorized
	}
	payload, err := unb64(encPayload)
	if err != nil {
		return ErrUnauthorized
	}
	sig, err := unb64(encSig)
	if err != nil {
		return ErrUnauthorized
	}

	// The signature FIRST, before anything in the payload is believed. Reading
	// claims out of an unverified document and acting on them is how a parser
	// becomes the security boundary instead of the crypto.
	if !ed25519.Verify(pub, payload, sig) {
		return ErrUnauthorized
	}

	var c readClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return ErrUnauthorized
	}
	if c.Server != serverID {
		return ErrUnauthorized
	}
	if now.After(time.Unix(c.Expires, 0).Add(readTokenLeeway)) {
		return ErrUnauthorized
	}
	return nil
}

// ParsePublicKey reads the key enrolment planted, as it is stored on the box.
//
// Raw base64 of the 32 bytes, one line, no armour. There is no format to
// negotiate and no algorithm field to lie about: it is an ed25519 key or the
// file is wrong.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := unb64(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("the registry key is not valid base64: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("the registry key is %d bytes, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// STRICT. Without it RawURLEncoding accepts non-canonical trailing bits, so one
// signature has several spellings -- and a format described as permanent should
// have one encoding per document, before anything downstream ever dedupes or
// caches on the bytes.
func unb64(s string) ([]byte, error) { return base64.RawURLEncoding.Strict().DecodeString(s) }
