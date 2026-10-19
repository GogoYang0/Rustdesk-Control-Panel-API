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

// keyGenerationAttempts mirrors RustDesk's gen_sk, which regenerates keys until
// the encoded public key avoids the characters that break its config parsing.
const keyGenerationAttempts = 300

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

		// RustDesk constrains the public key, not the secret: the public key is
		// embedded in the client configuration string, where '/' and ':' break
		// parsing. The secret key is written to id_ed25519 verbatim, so it needs
		// no such restriction.
		public := base64.StdEncoding.EncodeToString(pub)
		if strings.ContainsAny(public, "/:") {
			continue
		}

		sum := sha256.Sum256(pub)
		return KeyPair{
			PrivateKey:  base64.StdEncoding.EncodeToString(priv),
			PublicKey:   public,
			Fingerprint: hex.EncodeToString(sum[:16]),
		}, nil
	}
	return KeyPair{}, fmt.Errorf("generate ed25519 key: no acceptable encoding after %d attempts", keyGenerationAttempts)
}
