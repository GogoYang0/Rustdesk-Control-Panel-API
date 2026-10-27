package oidctest_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth/oidctest"
)

func TestServer_RoundTrip(t *testing.T) {
	srv := oidctest.New(t, "panel-client")
	defer srv.Close()
	srv.Sub = "subject-1"
	srv.Email = "oidc-user@example.com"
	srv.EmailVerified = true
	srv.Nonce = "nonce-abc"

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, srv.Issuer)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: "panel-client"})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"code-1"},
		"code_verifier": {"the-verifier"},
		"redirect_uri":  {"https://panel.example.com/api/v1/auth/oidc/callback"},
	}
	resp, err := http.PostForm(srv.TokenURL(), form)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d", resp.StatusCode)
	}
	var payload struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode token response: %v", err)
	}

	idToken, err := verifier.Verify(ctx, payload.IDToken)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if idToken.Subject != "subject-1" {
		t.Fatalf("subject = %q", idToken.Subject)
	}
	// go-oidc explicitly does not check the nonce; the fake must surface it so
	// the production code's own comparison has something to compare.
	if idToken.Nonce != "nonce-abc" {
		t.Fatalf("nonce = %q", idToken.Nonce)
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified any    `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		t.Fatalf("claims: %v", err)
	}
	if claims.Email != "oidc-user@example.com" {
		t.Fatalf("email = %q", claims.Email)
	}
	if claims.EmailVerified != true {
		t.Fatalf("email_verified = %#v", claims.EmailVerified)
	}
	if got := srv.LastTokenForm.Get("code_verifier"); got != "the-verifier" {
		t.Fatalf("recorded code_verifier = %q", got)
	}
}

// TestServer_StringEmailVerified pins the claim shape some providers emit: the
// boolean as a JSON string. The fake has to be able to produce it so the
// production normalisation (T7) has a real case to pass.
func TestServer_StringEmailVerified(t *testing.T) {
	srv := oidctest.New(t, "panel-client")
	defer srv.Close()
	srv.Sub = "subject-2"
	srv.EmailVerified = "true"

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, srv.Issuer)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: "panel-client"})

	resp, err := http.PostForm(srv.TokenURL(), url.Values{"grant_type": {"authorization_code"}, "code": {"c"}})
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var payload struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	idToken, err := verifier.Verify(ctx, payload.IDToken)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	var claims struct {
		EmailVerified any `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		t.Fatalf("claims: %v", err)
	}
	if claims.EmailVerified != "true" {
		t.Fatalf("email_verified = %#v, want the string \"true\"", claims.EmailVerified)
	}
}

// TestServer_ForeignKeyFailsVerification is the negative control for the whole
// suite: if the fake's JWKS advertised the signing key unconditionally, every
// "signature is checked" assertion elsewhere would be vacuous.
func TestServer_ForeignKeyFailsVerification(t *testing.T) {
	srv := oidctest.New(t, "panel-client")
	defer srv.Close()
	srv.Sub = "subject-3"
	srv.PublishForeignKey = true

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(ctx, srv.Issuer)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: "panel-client"})

	resp, err := http.PostForm(srv.TokenURL(), url.Values{"grant_type": {"authorization_code"}, "code": {"c"}})
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var payload struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, err := verifier.Verify(ctx, payload.IDToken); err == nil {
		t.Fatal("verify succeeded with a foreign key; the fake would not catch signature bugs")
	} else if !strings.Contains(strings.ToLower(err.Error()), "signature") && !strings.Contains(strings.ToLower(err.Error()), "verify") {
		t.Logf("verify error (accepted, any failure is enough): %v", err)
	}
}

// TestServer_TokenError knobs the failure path the production code must map to
// oidc_failed rather than a 500.
func TestServer_TokenError(t *testing.T) {
	srv := oidctest.New(t, "panel-client")
	defer srv.Close()
	srv.TokenStatus = http.StatusBadRequest

	resp, err := http.PostForm(srv.TokenURL(), url.Values{"grant_type": {"authorization_code"}, "code": {"c"}})
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}
