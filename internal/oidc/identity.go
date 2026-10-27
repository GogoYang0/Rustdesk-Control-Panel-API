package oidc

import (
	"context"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/identity"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// Sentinel errors re-exported for the HTTP layer: the binding semantics are
// shared with LDAP (internal/identity), so the sentinels live there and the
// OIDC package keeps its public names stable.
var (
	ErrNoAccount        = identity.ErrNoAccount
	ErrEmailUnverified  = identity.ErrEmailUnverified
	ErrIdentityConflict = identity.ErrIdentityConflict
	ErrIdentityNotFound = identity.ErrIdentityNotFound
	ErrLastCredential   = identity.ErrLastCredential
)

// ListIdentities returns the caller's external bindings, newest first.
func (s *Service) ListIdentities(ctx context.Context, userID uint) ([]model.UserIdentity, error) {
	return s.ident.List(ctx, userID)
}

// Unlink removes one of the caller's bindings (shared semantics, shared guard).
func (s *Service) Unlink(ctx context.Context, userID, identityID uint) error {
	return s.ident.Unlink(ctx, userID, identityID)
}

// StaleIssuerCount reports identities bound under a previous issuer.
func (s *Service) StaleIssuerCount(ctx context.Context) (int64, error) {
	return s.ident.StaleCount(ctx, model.IdentityProviderOIDC, s.cfg.Issuer)
}

// resolve maps the verified ID token onto a panel account through the shared
// binding service.
func (s *Service) resolve(ctx context.Context, c identity.Claims) (model.User, error) {
	return s.ident.Resolve(ctx, c)
}
