package project

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"
)

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestToolchainDownloadAcceptsAuthenticatedExecutableLargerThan64MiB(t *testing.T) {
	const size = (64 << 20) + 1
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(zeroReader{}, size)); err != nil {
		t.Fatal(err)
	}
	body, err := verifiedToolchain(io.LimitReader(zeroReader{}, size), hex.EncodeToString(hash.Sum(nil)))
	if err != nil || len(body) != size {
		t.Fatalf("valid workstation executable was refused: %d bytes, %v", len(body), err)
	}
	if _, err := verifiedToolchain(bytes.NewReader([]byte("changed binary")), hex.EncodeToString(hash.Sum(nil))); err == nil {
		t.Fatal("a changed executable passed verification")
	}
}
