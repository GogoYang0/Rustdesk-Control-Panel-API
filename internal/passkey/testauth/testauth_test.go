package testauth

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
)

const (
	testRPID   = "panel.example.com"
	testOrigin = "https://panel.example.com"
)

// TestAttestation_RoundTripsThroughProtocolParser is the guard that keeps this
// helper honest: the JSON we fabricate must satisfy the library's own parser,
// otherwise every downstream test would be proving our bug against our bug.
func TestAttestation_RoundTripsThroughProtocolParser(t *testing.T) {
	a := New(t, testRPID, testOrigin)
	challenge := b64([]byte("challenge-32-bytes-long-padding!!"))
	body := a.Attestation(t, challenge, b64([]byte("user-handle")))

	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		t.Fatalf("library rejected our attestation: %v", err)
	}
	if parsed.ID != b64(a.CredentialID()) {
		t.Fatalf("credential id = %s, want %s", parsed.ID, b64(a.CredentialID()))
	}
	if parsed.Response.CollectedClientData.Type != "webauthn.create" {
		t.Fatalf("client data type = %q", parsed.Response.CollectedClientData.Type)
	}
	if parsed.Response.CollectedClientData.Challenge != challenge {
		t.Fatalf("challenge = %q, want %q", parsed.Response.CollectedClientData.Challenge, challenge)
	}
	if parsed.Response.CollectedClientData.Origin != testOrigin {
		t.Fatalf("origin = %q", parsed.Response.CollectedClientData.Origin)
	}
	if len(parsed.Response.AttestationObject.AuthData.AttData.CredentialPublicKey) == 0 {
		t.Fatal("attestation carried no credential public key")
	}
}

// TestAssertion_VerifiesWithStoredPublicKey verifies the signature with the
// standard library rather than the library under test: same-key signature
// checking is what a real relying party does.
func TestAssertion_VerifiesWithStoredPublicKey(t *testing.T) {
	a := New(t, testRPID, testOrigin)
	challenge := b64([]byte("assertion-challenge-32-bytes-long!!"))
	body := a.Assertion(t, challenge, 7, b64([]byte("user-handle")))

	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		t.Fatalf("library rejected our assertion: %v", err)
	}
	clientHash := sha256.Sum256(parsed.Raw.AssertionResponse.ClientDataJSON)
	signed := append(append([]byte{}, parsed.Raw.AssertionResponse.AuthenticatorData...), clientHash[:]...)
	digest := sha256.Sum256(signed)

	var pub ecdsa.PublicKey
	if err := a.ExportPublicKey(&pub); err != nil {
		t.Fatalf("export public key: %v", err)
	}
	if !ecdsa.VerifyASN1(&pub, digest[:], parsed.Raw.AssertionResponse.Signature) {
		t.Fatal("signature did not verify against the registered public key")
	}
	if parsed.Response.CollectedClientData.Type != "webauthn.get" {
		t.Fatalf("client data type = %q", parsed.Response.CollectedClientData.Type)
	}
}

// TestAttestation_RespectsInjectedOrigin pins that a wrong-origin ceremony can
// actually be produced: tests for origin rejection would be vacuous otherwise.
func TestAttestation_RespectsInjectedOrigin(t *testing.T) {
	a := New(t, testRPID, "https://evil.example.org")
	body := a.Attestation(t, b64([]byte("challenge-32-bytes-long-padding!!")), b64([]byte("user-handle")))

	var raw struct {
		Response struct {
			ClientDataJSON string `json:"clientDataJSON"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw.Response.ClientDataJSON)
	if err != nil {
		t.Fatalf("decode clientDataJSON: %v", err)
	}
	var cd struct {
		Origin string `json:"origin"`
	}
	if err := json.Unmarshal(decoded, &cd); err != nil {
		t.Fatalf("unmarshal client data: %v", err)
	}
	if cd.Origin != "https://evil.example.org" {
		t.Fatalf("origin = %q", cd.Origin)
	}
}
