package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth/oidctest"
)

func testConfig(issuer string) Config {
	return Config{
		ProviderName: "Test IdP",
		Issuer:       issuer,
		ClientID:     "panel-client",
		ClientSecret: "s3cret-value",
		Scopes:       []string{"openid", "profile", "email"},
		ClockSkew:    time.Minute,
		StateTTL:     10 * time.Minute,
		CallbackURL:  "https://panel.example.com/api/v1/auth/oidc/callback",
		Now:          time.Now,
	}
}

func TestAuthCodeURL_CarriesPKCEAndNonce(t *testing.T) {
	fake := oidctest.New(t, "panel-client")
	svc := NewService(nil, testConfig(fake.Issuer), nil)

	if err := svc.EnsureProvider(context.Background()); err != nil {
		t.Fatalf("EnsureProvider: %v", err)
	}
	raw, err := svc.AuthCodeURL("state-1", "nonce-1", "verifier-1")
	if err != nil {
		t.Fatalf("AuthCodeURL: %v", err)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	q := parsed.Query()
	for key, want := range map[string]string{
		"response_type":         "code",
		"client_id":             "panel-client",
		"redirect_uri":          "https://panel.example.com/api/v1/auth/oidc/callback",
		"state":                 "state-1",
		"nonce":                 "nonce-1",
		"code_challenge_method": "S256",
	} {
		if got := q.Get(key); got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
	// PKCE only helps if the challenge is the S256 of the verifier the flow
	// will send at exchange time.
	sum := sha256.Sum256([]byte("verifier-1"))
	if got, want := q.Get("code_challenge"), base64.RawURLEncoding.EncodeToString(sum[:]); got != want {
		t.Fatalf("code_challenge = %q, want S256(verifier) = %q", got, want)
	}
}

func TestEnsureProvider_Unavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer srv.Close()

	svc := NewService(nil, testConfig(srv.URL), nil)
	err := svc.EnsureProvider(context.Background())
	if !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("EnsureProvider() = %v, want ErrProviderUnavailable", err)
	}
}

// TestEnsureProvider_Recovers pins the fail-then-recover behaviour: a failed
// discovery must not be cached, otherwise one IdP blip would keep SSO down
// until the process restarts.
func TestEnsureProvider_Recovers(t *testing.T) {
	var down atomic.Bool
	down.Store(true)
	var issuer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/keys",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	defer srv.Close()
	issuer = srv.URL

	svc := NewService(nil, testConfig(issuer), nil)
	if err := svc.EnsureProvider(context.Background()); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("first EnsureProvider() = %v, want ErrProviderUnavailable", err)
	}

	down.Store(false)
	if err := svc.EnsureProvider(context.Background()); err != nil {
		t.Fatalf("second EnsureProvider() = %v, want nil (failure must not be cached)", err)
	}
}

func TestExchangeCode_ForwardsPKCEAndRedirect(t *testing.T) {
	fake := oidctest.New(t, "panel-client")
	fake.Sub = "subject-9"
	fake.ClientID = "panel-client"

	svc := NewService(nil, testConfig(fake.Issuer), nil)
	idToken, err := svc.ExchangeCode(context.Background(), "code-9", "verifier-9")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if idToken.Subject != "subject-9" {
		t.Fatalf("subject = %q", idToken.Subject)
	}
	if got := fake.LastTokenForm.Get("code_verifier"); got != "verifier-9" {
		t.Fatalf("code_verifier = %q", got)
	}
	if got := fake.LastTokenForm.Get("redirect_uri"); got != "https://panel.example.com/api/v1/auth/oidc/callback" {
		t.Fatalf("redirect_uri = %q", got)
	}
}

func TestExchangeCode_TokenEndpointFailure(t *testing.T) {
	fake := oidctest.New(t, "panel-client")
	fake.TokenStatus = http.StatusBadRequest

	svc := NewService(nil, testConfig(fake.Issuer), nil)
	_, err := svc.ExchangeCode(context.Background(), "code-1", "verifier-1")
	if !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("ExchangeCode() = %v, want ErrLoginFailed", err)
	}
}

func TestExchangeCode_RejectsForeignSignature(t *testing.T) {
	fake := oidctest.New(t, "panel-client")
	fake.PublishForeignKey = true

	svc := NewService(nil, testConfig(fake.Issuer), nil)
	if _, err := svc.ExchangeCode(context.Background(), "code-1", "verifier-1"); !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("ExchangeCode() = %v, want ErrLoginFailed for an unverifiable token", err)
	}
}
