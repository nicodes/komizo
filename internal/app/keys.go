package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"strings"
)

// Deploy keypairs are generated in memory and never written to disk.
//
// They used to be written to ~/.ssh/deploy_<app>_<host>, and every rotation
// renamed the old one to .replaced.<timestamp> beside it -- so a box rotated a
// few times left a small pile of private keys on the machine, each one still
// valid for whatever it was valid for at the time, and none of them ever read
// again. komizo does not use these keys: it connects as you, with your own key.
// The private half exists for one purpose, which is to be pasted into a GitHub
// secret, and the only thing it needs to survive is the moment between being
// generated and being copied.
//
// So it is generated here rather than by shelling out to ssh-keygen, which
// needs a filename to write to. That is the whole reason for the encoder below:
// the format is public and stable, and a temporary file is still a file -- it
// lands in a directory somebody else may be able to read, it survives a crash
// between writing and deleting, and on a machine with a spinning disk it
// survives the delete.
//
// The cost is that if you close the screen without copying it, it is gone.
// That is the right way round: a deploy key you did not save is one rotation
// away, and a deploy key on a laptop is there until the laptop is not.

type keypair struct {
	// private is the OpenSSH-format private key, the value of SSH_DEPLOY_KEY.
	private string
	// public is the one line that goes in the server's authorized_keys.
	public string
}

func newKeypair(comment string) (keypair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return keypair{}, fmt.Errorf("could not generate a keypair: %w", err)
	}
	return keypair{
		private: marshalOpenSSHPrivate(pub, priv, comment),
		public:  "ssh-ed25519 " + base64.StdEncoding.EncodeToString(ed25519PubBlob(pub)) + " " + comment,
	}, nil
}

// marshalOpenSSHPrivate writes the "openssh-key-v1" container, unencrypted.
//
// The format is: the magic string, the cipher and KDF names (all "none" for a
// passphrase-less key), the number of keys, the public blob, and then a private
// section that repeats the public half. The two check integers at the front of
// that section are what a passphrase-protected key uses to tell a correct
// passphrase from a wrong one -- with no cipher they simply have to match.
func marshalOpenSSHPrivate(pub ed25519.PublicKey, priv ed25519.PrivateKey, comment string) string {
	var check [4]byte
	// Errors here would mean the system random source failed, and that has
	// already been reported by GenerateKey above.
	_, _ = rand.Read(check[:])

	var sec []byte
	sec = append(sec, check[:]...)
	sec = append(sec, check[:]...)
	sec = appendString(sec, []byte("ssh-ed25519"))
	sec = appendString(sec, pub)
	sec = appendString(sec, priv)
	sec = appendString(sec, []byte(comment))
	// Padded to the cipher's block size with 1, 2, 3... Eight even for "none",
	// which is what ssh-keygen writes and what every reader expects.
	for i := byte(1); len(sec)%8 != 0; i++ {
		sec = append(sec, i)
	}

	var out []byte
	out = append(out, "openssh-key-v1\x00"...)
	out = appendString(out, []byte("none")) // cipher
	out = appendString(out, []byte("none")) // kdf
	out = appendString(out, nil)            // kdf options
	out = binary.BigEndian.AppendUint32(out, 1)
	out = appendString(out, ed25519PubBlob(pub))
	out = appendString(out, sec)

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: out,
	}))
}

// ed25519PubBlob is the wire form of the public key: its type, then its bytes.
func ed25519PubBlob(pub ed25519.PublicKey) []byte {
	var b []byte
	b = appendString(b, []byte("ssh-ed25519"))
	return appendString(b, pub)
}

// appendString writes an SSH wire string: a big-endian length, then the bytes.
func appendString(dst, s []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(s)))
	return append(dst, s...)
}

// keyComment names the key on the server, and is what a rotation matches on to
// replace the old one rather than authorising both.
func keyComment(user, host string) string {
	return fmt.Sprintf("komizo:%s@%s", user, strings.TrimSpace(host))
}
