package provision

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// keyGenerationAttempts mirrors RustDesk's own retry: it regenerates keys until
// the encoded secret avoids characters that would break its config parsing.
const keyGenerationAttempts = 20

// KeyPair is a RustDesk-compatible ed25519 identity.
//
// RustDesk stores id_ed25519 as base64 of the 64-byte secret key (seed||pub) and
// id_ed25519.pub as base64 of the raw 32-byte public key. Go's ed25519.PrivateKey
// already uses that 64-byte layout, so it is encoded directly.
type KeyPair struct {
	PrivateKey  string
	PublicKey   string
	Fingerprint string
}

// GenerateKeyPair creates a fresh ed25519 identity in RustDesk's encoding.
func GenerateKeyPair() (KeyPair, error) {
	for attempt := 0; attempt < keyGenerationAttempts; attempt++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return KeyPair{}, fmt.Errorf("generate ed25519 key: %w", err)
		}

		secret := base64.StdEncoding.EncodeToString(priv)
		if strings.ContainsAny(secret, "/:") {
			continue
		}

		sum := sha256.Sum256(pub)
		return KeyPair{
			PrivateKey:  secret,
			PublicKey:   base64.StdEncoding.EncodeToString(pub),
			Fingerprint: hex.EncodeToString(sum[:16]),
		}, nil
	}
	return KeyPair{}, fmt.Errorf("generate ed25519 key: no acceptable encoding after %d attempts", keyGenerationAttempts)
}
