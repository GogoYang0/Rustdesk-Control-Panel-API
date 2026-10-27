// Package oidctest runs a fake OpenID Connect provider for tests. It signs real
// RS256 ID tokens, publishes a real JWKS and a discovery document, so the
// production verifier is exercised end to end instead of being replaced by a
// stub. Knobs on Server inject the claim shapes and failures real providers
// produce.
package oidctest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

const keyID = "test-key"

// Server is a running fake provider. Set the claim fields before requesting a
// token; they are read at signing time so a test can change them per call.
type Server struct {
	Issuer   string
	ClientID string

	Nonce string
	// NoncesByCode maps an authorization code to the nonce its ID token must
	// carry: concurrency tests run several flows whose nonces must not bleed
	// into each other.
	NoncesByCode  map[string]string
	Sub           string
	Email         string
	EmailVerified any           // true, "true", []any{"true"} or nil to omit
	Audience      []string      // defaults to []string{ClientID}
	IssuerClaim   string        // defaults to Issuer
	IDTokenTTL    time.Duration // defaults to 5m

	TokenStatus int // non-zero makes the token endpoint fail with this status

	// PublishForeignKey serves an unrelated key in the JWKS while still signing
	// with the real key. Verification must fail; it is the negative control
	// that keeps every other test from passing on an unchecked signature.
	PublishForeignKey bool

	LastTokenForm url.Values

	srv        *httptest.Server
	key        *rsa.PrivateKey
	foreignKey *rsa.PrivateKey
	closed     bool
}

// New starts the fake provider and registers its shutdown with the test.
func New(t *testing.T, clientID string) *Server {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("oidctest: generate signing key: %v", err)
	}
	foreign, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("oidctest: generate foreign key: %v", err)
	}

	s := &Server{
		ClientID:   clientID,
		IDTokenTTL: 5 * time.Minute,
		srv:        httptest.NewServer(nil),
		key:        key,
		foreignKey: foreign,
	}
	s.srv.Config.Handler = http.HandlerFunc(s.handle)
	s.Issuer = s.srv.URL
	t.Cleanup(s.Close)
	return s
}

// Close stops the server. It is safe to call twice (New registers it with the
// test as well).
func (s *Server) Close() {
	if s.closed {
		return
	}
	s.closed = true
	s.srv.Close()
}

func (s *Server) TokenURL() string     { return s.Issuer + "/token" }
func (s *Server) AuthorizeURL() string { return s.Issuer + "/authorize" }
func (s *Server) JWKSURL() string      { return s.Issuer + "/keys" }

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		s.serveDiscovery(w)
	case "/keys":
		s.serveKeys(w)
	case "/token":
		s.serveToken(w, r)
	case "/authorize":
		// The tests drive the browser leg by parsing the authorization URL the
		// panel produced, so this endpoint never needs to issue a redirect.
		http.Error(w, "the tests never call /authorize", http.StatusNotImplemented)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) serveDiscovery(w http.ResponseWriter) {
	writeJSON(w, map[string]any{
		"issuer":                                s.Issuer,
		"authorization_endpoint":                s.AuthorizeURL(),
		"token_endpoint":                        s.TokenURL(),
		"jwks_uri":                              s.JWKSURL(),
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
	})
}

func (s *Server) serveKeys(w http.ResponseWriter) {
	key := s.key
	if s.PublishForeignKey {
		key = s.foreignKey
	}
	writeJSON(w, map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"kid": keyID,
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		}},
	})
}

func (s *Server) serveToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	s.LastTokenForm = r.PostForm
	if s.TokenStatus != 0 {
		http.Error(w, "injected token failure", s.TokenStatus)
		return
	}
	if got := r.PostForm.Get("grant_type"); got != "authorization_code" {
		http.Error(w, "unsupported grant", http.StatusBadRequest)
		return
	}

	idToken, err := s.signIDToken(r.PostForm.Get("code"))
	if err != nil {
		http.Error(w, "sign: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"access_token": "oidctest-access-token",
		"token_type":   "Bearer",
		"expires_in":   300,
		"id_token":     idToken,
	})
}

func (s *Server) signIDToken(code string) (string, error) {
	now := time.Now()
	issuer := s.IssuerClaim
	if issuer == "" {
		issuer = s.Issuer
	}
	audience := s.Audience
	if len(audience) == 0 {
		audience = []string{s.ClientID}
	}
	ttl := s.IDTokenTTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}

	claims := map[string]any{
		"iss": issuer,
		"sub": s.Sub,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	}
	if nonce, ok := s.NoncesByCode[code]; ok {
		claims["nonce"] = nonce
	} else if s.Nonce != "" {
		claims["nonce"] = s.Nonce
	}
	if s.Email != "" {
		claims["email"] = s.Email
	}
	if s.EmailVerified != nil {
		claims["email_verified"] = s.EmailVerified
	}

	headerJSON, err := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": keyID})
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)

	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}
