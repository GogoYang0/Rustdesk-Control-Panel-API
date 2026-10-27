package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"path"
	"strings"

	"golang.org/x/oauth2"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// randomToken returns a 256-bit URL-safe secret for state, nonce and ticket.
func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Start begins an authorization-code flow: it validates the post-login path,
// discovers the provider, records the one-shot state row and returns the URL the
// browser must visit.
func (s *Service) Start(ctx context.Context, redirectPath string) (authURL, state string, err error) {
	target, err := SanitizeRedirectPath(redirectPath)
	if err != nil {
		return "", "", err
	}
	if err := s.EnsureProvider(ctx); err != nil {
		return "", "", err
	}

	state, err = randomToken()
	if err != nil {
		return "", "", err
	}
	nonce, err := randomToken()
	if err != nil {
		return "", "", err
	}
	// oauth2.GenerateVerifier already returns the S256-compatible length and
	// alphabet; the challenge sent to the IdP is S256(verifier).
	verifier := oauth2.GenerateVerifier()

	authURL, err = s.AuthCodeURL(state, nonce, verifier)
	if err != nil {
		return "", "", err
	}

	flow := &model.ExternalLoginFlow{
		State:        state,
		Provider:     model.IdentityProviderOIDC,
		Nonce:        nonce,
		PKCEVerifier: verifier,
		RedirectPath: target,
		ExpiresAt:    s.cfg.Now().Add(s.cfg.StateTTL),
	}
	if err := s.createFlow(ctx, flow); err != nil {
		return "", "", err
	}
	return authURL, state, nil
}

// SanitizeRedirectPath turns the caller's post-login path into something that
// can only point inside the panel. It is the single place that decides what a
// safe redirect looks like, so the callback and the SPA agree by construction.
func SanitizeRedirectPath(raw string) (string, error) {
	target := strings.TrimSpace(raw)
	if target == "" {
		return "/", nil
	}
	if len(target) > 256 {
		return "", ErrInvalidRedirect
	}
	if !strings.HasPrefix(target, "/") {
		return "", ErrInvalidRedirect
	}
	// "//host" is protocol-relative, "/\host" is treated as "//host" by several
	// browsers, and a backslash anywhere is never part of a panel route.
	if strings.HasPrefix(target, "//") || strings.Contains(target, "\\") {
		return "", ErrInvalidRedirect
	}
	// A colon would let "/x:y" reach a scheme-interpreting parser downstream.
	if strings.Contains(target, ":") {
		return "", ErrInvalidRedirect
	}
	// Percent-encoded separators are decoded by the browser before navigation,
	// so "/%2F%2Fevil" becomes "///evil".
	lower := strings.ToLower(target)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return "", ErrInvalidRedirect
	}
	// Dot segments can only confuse the client-side router; no panel route
	// needs them.
	if strings.Contains(target, "..") {
		return "", ErrInvalidRedirect
	}
	if strings.ContainsAny(target, "\r\n\t") {
		return "", ErrInvalidRedirect
	}
	// path.Clean also collapses duplicate slashes in the path component.
	if cleaned := path.Clean(target); cleaned == "." || !strings.HasPrefix(cleaned, "/") {
		return "", ErrInvalidRedirect
	}
	return target, nil
}
