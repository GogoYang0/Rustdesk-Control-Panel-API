// Package oidc implements deployment-wide OpenID Connect single sign-on: one
// provider from config, authorization code with PKCE and nonce, a one-shot
// ticket exchanged by the SPA, and identities bound to existing panel accounts
// (no just-in-time provisioning).
package oidc

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// discoveryTimeout bounds the single discovery round trip so a black-holed IdP
// cannot pin request goroutines.
const discoveryTimeout = 10 * time.Second

// Config is the resolved, already-validated OIDC configuration.
type Config struct {
	ProviderName string
	Issuer       string
	ClientID     string
	ClientSecret string
	Scopes       []string
	ClockSkew    time.Duration
	StateTTL     time.Duration
	CallbackURL  string
	Now          func() time.Time
}

// Service owns the provider connection, the login flows and the identity
// bindings. A nil *Service means the feature is disabled; the HTTP layer then
// answers 503 on every OIDC endpoint.
type Service struct {
	db  *gorm.DB
	cfg Config
	log *zap.Logger

	mu sync.Mutex
	p  *provider
}

// provider is one successfully discovered IdP.
type provider struct {
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// NewService builds the service. It performs no network I/O: discovery happens
// on the first request, so an unreachable IdP delays nothing at startup and
// recovers without a restart (design O9).
func NewService(db *gorm.DB, cfg Config, log *zap.Logger) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.ClockSkew < 0 {
		cfg.ClockSkew = 0
	}
	return &Service{db: db, cfg: cfg, log: log}
}

// ProviderName is the label the login page shows.
func (s *Service) ProviderName() string { return s.cfg.ProviderName }

// EnsureProvider discovers the IdP once and caches the result. Failures are
// not cached: a single IdP outage must not disable SSO for the process
// lifetime.
func (s *Service) EnsureProvider(ctx context.Context) error {
	_, err := s.providerFor(ctx)
	return err
}

func (s *Service) providerFor(ctx context.Context) (*provider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.p != nil {
		return s.p, nil
	}

	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	discovered, err := oidc.NewProvider(ctx, s.cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: discovery: %v", ErrProviderUnavailable, err)
	}

	// go-oidc checks exp against Now; shifting Now back by the configured skew
	// is how a tolerance for a slow IdP clock is expressed.
	now := s.cfg.Now
	if s.cfg.ClockSkew > 0 {
		skew := s.cfg.ClockSkew
		now = func() time.Time { return s.cfg.Now().Add(-skew) }
	}
	s.p = &provider{
		oauth: oauth2.Config{
			ClientID:     s.cfg.ClientID,
			ClientSecret: s.cfg.ClientSecret,
			Endpoint:     discovered.Endpoint(),
			RedirectURL:  s.cfg.CallbackURL,
			Scopes:       s.cfg.Scopes,
		},
		verifier: discovered.Verifier(&oidc.Config{ClientID: s.cfg.ClientID, Now: now}),
	}
	return s.p, nil
}

// AuthCodeURL builds the authorization request. The nonce is echoed back inside
// the ID token and compared by the callback; PKCE makes an intercepted code
// useless without the verifier.
func (s *Service) AuthCodeURL(state, nonce, verifier string) (string, error) {
	s.mu.Lock()
	p := s.p
	s.mu.Unlock()
	if p == nil {
		return "", fmt.Errorf("%w: provider not discovered", ErrProviderUnavailable)
	}
	return p.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce)), nil
}

// ExchangeCode redeems the authorization code and returns the verified ID
// token. Every failure collapses into ErrLoginFailed: the SPA only needs to
// know the attempt failed.
func (s *Service) ExchangeCode(ctx context.Context, code, verifier string) (*oidc.IDToken, error) {
	p, err := s.providerFor(ctx)
	if err != nil {
		return nil, err
	}
	token, err := p.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("%w: code exchange failed: %v", ErrLoginFailed, err)
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return nil, fmt.Errorf("%w: token response carried no id_token", ErrLoginFailed)
	}
	idToken, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("%w: id_token rejected: %v", ErrLoginFailed, err)
	}
	return idToken, nil
}

// IdentityProvider is the value stored in UserIdentity.Provider.
const IdentityProvider = model.IdentityProviderOIDC
