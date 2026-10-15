package app

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
)

// Resume only Komizo's unencrypted single-ed25519 format, bound to this exact
// app/host comment. Never overwrite or silently substitute a different key.
func readExistingKey(path, comment string) (keypair, error) {
	bad := errors.New("existing key is not an intact Komizo key for this application and host")
	body, err := readJourneyFile(path, 64<<10, true)
	if err != nil {
		return keypair{}, err
	}
	block, rest := pem.Decode(body)
	if block == nil || block.Type != "OPENSSH PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 || !bytes.HasPrefix(block.Bytes, []byte("openssh-key-v1\x00")) {
		return keypair{}, bad
	}
	r := keyReader{body: block.Bytes[len("openssh-key-v1\x00"):]}
	if string(r.field()) != "none" || string(r.field()) != "none" || len(r.field()) != 0 || r.number() != 1 {
		return keypair{}, bad
	}
	public, private := r.field(), r.field()
	if r.failed || len(r.body) != 0 {
		return keypair{}, bad
	}
	p := keyReader{body: private}
	check := p.number()
	if p.number() != check || string(p.field()) != "ssh-ed25519" {
		return keypair{}, bad
	}
	pub, priv, recorded := p.field(), p.field(), p.field()
	if p.failed || len(pub) != ed25519.PublicKeySize || len(priv) != ed25519.PrivateKeySize || string(recorded) != comment {
		return keypair{}, bad
	}
	derived := ed25519.NewKeyFromSeed(priv[:ed25519.SeedSize])
	if !bytes.Equal(derived, priv) || !bytes.Equal(derived[ed25519.SeedSize:], pub) || !bytes.Equal(public, ed25519PubBlob(ed25519.PublicKey(pub))) || len(private)%8 != 0 || len(p.body) > 8 {
		return keypair{}, bad
	}
	for i, value := range p.body {
		if value != byte(i+1) {
			return keypair{}, bad
		}
	}
	return keypair{private: string(body), public: "ssh-ed25519 " + base64.StdEncoding.EncodeToString(public) + " " + comment}, nil
}

type keyReader struct {
	body   []byte
	failed bool
}

func (r *keyReader) number() uint32 {
	if len(r.body) < 4 {
		r.failed = true
		return 0
	}
	n := binary.BigEndian.Uint32(r.body[:4])
	r.body = r.body[4:]
	return n
}
func (r *keyReader) field() []byte {
	n := r.number()
	if r.failed || uint64(n) > uint64(len(r.body)) {
		r.failed = true
		return nil
	}
	value := r.body[:n]
	r.body = r.body[n:]
	return value
}
