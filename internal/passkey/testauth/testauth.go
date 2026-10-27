// Package testauth fabricates WebAuthn ceremonies for tests. It is a helper,
// not production code: it holds a P-256 key and emits the JSON a browser would
// send, so tests exercise the library's real parsing and signature checks
// instead of stubbing them out.
package testauth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// Authenticator is one virtual platform authenticator.
type Authenticator struct {
	rpID   string
	origin string
	key    *ecdsa.PrivateKey
	credID []byte
	aaguid [16]byte
}

// New creates an authenticator bound to one relying party.
func New(t *testing.T, rpID, origin string) *Authenticator {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		t.Fatalf("generate credential id: %v", err)
	}
	a := &Authenticator{rpID: rpID, origin: origin, key: key, credID: credID}
	copy(a.aaguid[:], []byte("testauth-v1-0000"))
	return a
}

// CredentialID returns the raw credential id this authenticator will present.
func (a *Authenticator) CredentialID() []byte { return a.credID }

// SetCredentialID overrides the generated id, for duplicate-credential tests.
func (a *Authenticator) SetCredentialID(id []byte) { a.credID = id }

// ExportPublicKey copies the credential public key out for independent
// signature verification in tests.
func (a *Authenticator) ExportPublicKey(dst *ecdsa.PublicKey) error {
	*dst = a.key.PublicKey
	return nil
}

// Attestation returns the JSON body a browser posts to a registration finish
// endpoint. userHandleB64 is the base64url user handle the panel issued.
func (a *Authenticator) Attestation(t *testing.T, challengeB64, userHandleB64 string) []byte {
	t.Helper()

	authData := a.authData(0x45, 0) // UP | UV | AT
	cose := a.coseKey(t)
	authData = append(authData, a.aaguid[:]...)
	authData = append(authData, byte(len(a.credID)>>8), byte(len(a.credID)))
	authData = append(authData, a.credID...)
	authData = append(authData, cose...)

	attObj, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	if err != nil {
		t.Fatalf("marshal attestation object: %v", err)
	}

	clientData := a.clientData(t, "webauthn.create", challengeB64)
	body := map[string]any{
		"id":    b64(a.credID),
		"rawId": b64(a.credID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientData),
			"attestationObject": b64(attObj),
		},
		"clientExtensionResults": map[string]any{},
	}
	if userHandleB64 != "" {
		body["userHandle"] = userHandleB64
	}
	return mustJSON(t, body)
}

// Assertion returns the JSON body a browser posts to a login or step-up finish
// endpoint. signCount is the counter the authenticator reports.
func (a *Authenticator) Assertion(t *testing.T, challengeB64 string, signCount uint32, userHandleB64 string) []byte {
	t.Helper()

	authData := a.authData(0x05, signCount) // UP | UV
	clientData := a.clientData(t, "webauthn.get", challengeB64)
	clientHash := sha256.Sum256(clientData)
	signed := append(append([]byte{}, authData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}

	response := map[string]any{
		"clientDataJSON":    b64(clientData),
		"authenticatorData": b64(authData),
		"signature":         b64(signature),
	}
	body := map[string]any{
		"id":                     b64(a.credID),
		"rawId":                  b64(a.credID),
		"type":                   "public-key",
		"response":               response,
		"clientExtensionResults": map[string]any{},
	}
	if userHandleB64 != "" {
		response["userHandle"] = userHandleB64
	}
	return mustJSON(t, body)
}

func (a *Authenticator) authData(flags byte, signCount uint32) []byte {
	rpHash := sha256.Sum256([]byte(a.rpID))
	buf := bytes.Buffer{}
	buf.Write(rpHash[:])
	buf.WriteByte(flags)
	_ = binary.Write(&buf, binary.BigEndian, signCount)
	return buf.Bytes()
}

func (a *Authenticator) coseKey(t *testing.T) []byte {
	t.Helper()

	x := make([]byte, 32)
	y := make([]byte, 32)
	a.key.PublicKey.X.FillBytes(x)
	a.key.PublicKey.Y.FillBytes(y)

	// COSE_Key: kty=EC2(2), alg=ES256(-7), crv=P-256(1), x, y.
	encoded, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	if err != nil {
		t.Fatalf("marshal COSE key: %v", err)
	}
	return encoded
}

func (a *Authenticator) clientData(t *testing.T, ceremonyType, challengeB64 string) []byte {
	t.Helper()

	return mustJSON(t, map[string]any{
		"type":        ceremonyType,
		"challenge":   challengeB64,
		"origin":      a.origin,
		"crossOrigin": false,
	})
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()

	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return encoded
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
