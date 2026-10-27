package oidc

import "errors"

// Errors returned by the OIDC service. The HTTP layer maps them onto the fixed
// redirect codes the SPA understands (design §3), never onto IdP text.
var (
	// ErrProviderUnavailable means discovery or the token endpoint could not be
	// reached. It maps to 503, not to a login failure: the deployment is
	// misconfigured or the IdP is down, and pretending otherwise would push
	// users towards a password login they may not have.
	ErrProviderUnavailable = errors.New("oidc provider unavailable")

	// ErrLoginFailed covers everything that makes the assertion unusable: a
	// token endpoint error, a missing id_token, a bad signature, a wrong
	// issuer/audience, an expired token. It maps to oidc_failed.
	ErrLoginFailed = errors.New("oidc login failed")

	// ErrNonceMismatch is separated from ErrLoginFailed because the nonce is
	// the one check go-oidc does not perform; a dedicated sentinel keeps the
	// comparison from being dropped silently.
	ErrNonceMismatch = errors.New("oidc nonce mismatch")

	// ErrInvalidState / ErrStateExpired / ErrStateUsed describe the one-shot
	// state row.
	ErrInvalidState = errors.New("oidc state invalid")
	ErrStateExpired = errors.New("oidc state expired")
	ErrStateUsed    = errors.New("oidc state already used")

	// ErrInvalidTicket describes a ticket that does not exist, expired, or was
	// already exchanged.
	ErrInvalidTicket = errors.New("oidc ticket invalid")

	// ErrEmailUnverified means the IdP did not assert a verified mailbox, so
	// the identity cannot be bound to a panel account.
	ErrEmailUnverified = errors.New("oidc email is not verified")

	// ErrNoAccount means the verified mailbox matches no panel account. There
	// is no just-in-time provisioning by design (O2).
	ErrNoAccount = errors.New("no panel account for this identity")

	// ErrIdentityConflict means the binding is unusable: the subject is bound
	// to one account while the mailbox belongs to another (O4), or the account
	// already has a different subject for this issuer.
	ErrIdentityConflict = errors.New("oidc identity conflict")

	// ErrIdentityNotFound is a 404 on the self-service endpoints.
	ErrIdentityNotFound = errors.New("identity not found")

	// ErrLastCredential refuses an unlink that would leave the account with no
	// way to sign in at all.
	ErrLastCredential = errors.New("identity is the only credential")

	// ErrInvalidRedirect refuses a redirect_path that could leave the site.
	ErrInvalidRedirect = errors.New("invalid redirect path")
)
