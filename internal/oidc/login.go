package oidc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// CallbackResult is what the callback handler needs to build its redirect: the
// ticket to hand to the SPA and the site path it asked to return to.
type CallbackResult struct {
	Ticket       string
	RedirectPath string
}

// FinishCallback completes the authorization leg: it burns the state, redeems
// the code with PKCE, verifies the ID token, checks the nonce and binds the
// identity, then issues a one-shot ticket.
func (s *Service) FinishCallback(ctx context.Context, state, code string) (CallbackResult, error) {
	flow, err := s.consumeState(ctx, state)
	if err != nil {
		return CallbackResult{}, err
	}
	res := CallbackResult{RedirectPath: flow.RedirectPath}

	idToken, err := s.ExchangeCode(ctx, code, flow.PKCEVerifier)
	if err != nil {
		return res, err
	}
	// go-oidc validates signature, issuer, audience and expiry, but explicitly
	// leaves the nonce to the caller. Skipping this comparison would make a
	// replayed ID token usable.
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(flow.Nonce)) != 1 {
		return res, ErrNonceMismatch
	}

	var raw struct {
		Email         string `json:"email"`
		EmailVerified any    `json:"email_verified"`
	}
	if err := idToken.Claims(&raw); err != nil {
		return res, ErrLoginFailed
	}

	user, err := s.resolveIdentity(ctx, identityClaims{
		Issuer:        idToken.Issuer,
		Subject:       idToken.Subject,
		Email:         raw.Email,
		EmailVerified: normalizeEmailVerified(raw.EmailVerified),
	})
	if err != nil {
		return res, err
	}

	ticket, err := randomToken()
	if err != nil {
		return res, err
	}
	// Only the hash is stored: a database dump must not yield usable tickets.
	sum := sha256.Sum256([]byte(ticket))
	if err := s.attachTicket(ctx, state, hex.EncodeToString(sum[:]), user.ID, ticketTTL); err != nil {
		return res, err
	}

	res.Ticket = ticket
	return res, nil
}

// ExchangeTicket redeems the ticket for the account it was issued to. The
// single-use guarantee comes from the conditional update in consumeTicket.
func (s *Service) ExchangeTicket(ctx context.Context, ticket string) (model.User, error) {
	if ticket == "" {
		return model.User{}, ErrInvalidTicket
	}
	sum := sha256.Sum256([]byte(ticket))
	userID, err := s.consumeTicket(ctx, hex.EncodeToString(sum[:]))
	if err != nil {
		return model.User{}, err
	}

	var user model.User
	if err := s.db.WithContext(ctx).Where("id = ?", userID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return model.User{}, ErrInvalidTicket
		}
		return model.User{}, err
	}
	return user, nil
}

// RedirectPathFor reads the site path recorded for a state without consuming
// it. The callback uses it to build an error redirect when the flow never
// completes; an unknown state falls back to "/".
func (s *Service) RedirectPathFor(ctx context.Context, state string) string {
	if state == "" {
		return "/"
	}
	var flow model.ExternalLoginFlow
	if err := s.db.WithContext(ctx).Select("redirect_path").Where("state = ?", state).First(&flow).Error; err != nil {
		return "/"
	}
	if flow.RedirectPath == "" {
		return "/"
	}
	return flow.RedirectPath
}

// ErrorCode maps a failure onto the fixed code the SPA receives in the query
// string. Everything that is not one of the three special cases collapses into
// oidc_failed: the client cannot act differently on the rest, and the details
// could describe the IdP.
func ErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrNoAccount):
		return "no_account"
	case errors.Is(err, ErrEmailUnverified):
		return "email_unverified"
	case errors.Is(err, ErrIdentityConflict):
		return "identity_conflict"
	default:
		return "oidc_failed"
	}
}

// PeekStateForTicket reads the state a live ticket belongs to, without
// consuming it. The HTTP layer uses it to bind the ticket to the browser that
// ran the callback before spending the ticket (CWE-352: a forwarded callback or
// ticket alone must not log a different browser in).
func (s *Service) PeekStateForTicket(ctx context.Context, ticket string) (string, error) {
	if ticket == "" {
		return "", ErrInvalidTicket
	}
	sum := sha256.Sum256([]byte(ticket))
	var flow model.ExternalLoginFlow
	err := s.db.WithContext(ctx).Select("state").
		Where("ticket_hash = ? AND ticket_consumed_at IS NULL AND ticket_expires_at > ?",
			hex.EncodeToString(sum[:]), s.cfg.Now()).
		First(&flow).Error
	if err != nil {
		return "", ErrInvalidTicket
	}
	return flow.State, nil
}
