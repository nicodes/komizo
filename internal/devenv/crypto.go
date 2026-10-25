package devenv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
)

const protocol = "ghenv-v1"
const maxPayload = 2 << 20

// Only this envelope is persisted on the runner or uploaded to GitHub.
type envelope struct {
	Version    string `json:"version"`
	Key        []byte `json:"key"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func seal(publicKey string, values map[string]string, requestID string) ([]byte, error) {
	der, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, errors.New("invalid public key encoding")
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errors.New("invalid public key")
	}
	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok || rsaKey.N.BitLen() < 3072 || rsaKey.N.BitLen() > 4096 || rsaKey.E != 65537 {
		return nil, errors.New("expected a 3072-4096 bit RSA public key")
	}
	plaintext, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	if len(plaintext) > maxPayload {
		return nil, errors.New("environment is too large")
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaKey, key, []byte(protocol))
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{protocol, wrapped, nonce, gcm.Seal(nil, nonce, plaintext, []byte(requestID))})
}

func unseal(privateKey *rsa.PrivateKey, data []byte, requestID string) (map[string]string, error) {
	var e envelope
	if len(data) > maxPayload*2 {
		return nil, errors.New("encrypted payload is too large")
	}
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, errors.New("invalid encrypted payload")
	}
	if e.Version != protocol {
		return nil, errors.New("unsupported encryption protocol")
	}
	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, e.Key, []byte(protocol))
	if err != nil {
		return nil, errors.New("cannot decrypt payload key")
	}
	defer clear(key)
	if len(key) != 32 {
		return nil, errors.New("invalid payload key length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(e.Nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid payload nonce")
	}
	plaintext, err := gcm.Open(nil, e.Nonce, e.Ciphertext, []byte(requestID))
	if err != nil {
		return nil, errors.New("payload authentication failed")
	}
	defer clear(plaintext)
	var values map[string]string
	if err = json.Unmarshal(plaintext, &values); err != nil {
		return nil, errors.New("invalid environment payload")
	}
	return values, nil
}
