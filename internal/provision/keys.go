package provision

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

// KeyPair is a RustDesk-compatible ed25519 identity.
//
// RustDesk keeps the private key as an OpenSSH/PKCS#8 PEM file (id_ed25519) and
// the public key as base64 of the raw 32 bytes (id_ed25519.pub).
type KeyPair struct {
	PrivatePEM  string
	PublicKey   string
	Fingerprint string
}

// GenerateKeyPair creates a fresh ed25519 identity.
func GenerateKeyPair() (KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("generate ed25519 key: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return KeyPair{}, fmt.Errorf("marshal private key: %w", err)
	}
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	sum := sha256.Sum256(pub)
	return KeyPair{
		PrivatePEM:  privPEM,
		PublicKey:   base64.StdEncoding.EncodeToString(pub),
		Fingerprint: hex.EncodeToString(sum[:16]),
	}, nil
}
