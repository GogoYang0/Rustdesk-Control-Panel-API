// Package identity binds panel accounts to external identities. It is shared
// by every external login path (OIDC, LDAP): one table, one conflict
// semantics, one lockout guard — the providers only differ in the claim values
// they hand in.
package identity

import (
	"context"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// Errors returned by the service. The HTTP layers map them onto their own
// fixed codes: ErrNoAccount and ErrEmailUnverified are user-facing, and
// ErrIdentityConflict must never silently rebind.
var (
	// ErrNoAccount means the verified mailbox matches no panel account. There
	// is no just-in-time provisioning by design.
	ErrNoAccount = errors.New("no panel account for this identity")

	// ErrEmailUnverified means the proof is not strong enough to bind: either
	// the external claim was not verified, or the panel mailbox is not
	// confirmed.
	ErrEmailUnverified = errors.New("external email is not verified")

	// ErrIdentityConflict means the binding is unusable: the subject is bound
	// to one account while the mailbox belongs to another (O4), or the account
	// already has a different subject for this issuer.
	ErrIdentityConflict = errors.New("external identity conflict")

	// ErrIdentityNotFound is a 404 on the self-service endpoints.
	ErrIdentityNotFound = errors.New("identity not found")

	// ErrLastCredential refuses an unlink that would leave the account with no
	// way to sign in at all.
	ErrLastCredential = errors.New("identity is the only credential")
)

// Claims is the subset of an external identity that decides which panel
// account it belongs to. EmailVerified is normalized by the caller: each
// provider knows its own claim shapes.
type Claims struct {
	Provider      string
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
}

// Service owns the binding table operations shared by all providers.
type Service struct {
	DB  *gorm.DB
	Now func() time.Time
}

// Resolve maps a verified external identity onto a panel account, binding on
// the first login and refusing anything ambiguous.
func (s *Service) Resolve(ctx context.Context, c Claims) (model.User, error) {
	now := s.Now()

	var identity model.UserIdentity
	err := s.DB.WithContext(ctx).
		Where("provider = ? AND issuer = ? AND subject = ?", c.Provider, c.Issuer, c.Subject).
		First(&identity).Error
	switch {
	case err == nil:
		return s.loginExisting(ctx, &identity, c, now)
	case errors.Is(err, gorm.ErrRecordNotFound):
		return s.bindNew(ctx, c, now)
	default:
		return model.User{}, err
	}
}

// loginExisting handles the returning user. The binding wins over the mailbox,
// except when the mailbox now belongs to a different panel account — that is
// the recycled-address takeover path (O4).
func (s *Service) loginExisting(ctx context.Context, identity *model.UserIdentity, c Claims, now time.Time) (model.User, error) {
	if identity.ConflictAt != nil {
		// Already known-broken: external login stays closed until an
		// administrator resets the binding.
		return model.User{}, ErrIdentityConflict
	}

	var user model.User
	if err := s.DB.WithContext(ctx).Where("id = ?", identity.UserID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return model.User{}, ErrNoAccount
		}
		return model.User{}, err
	}

	if email := strings.ToLower(strings.TrimSpace(c.Email)); email != "" {
		var other model.User
		err := s.DB.WithContext(ctx).Where("LOWER(email) = ?", email).First(&other).Error
		switch {
		case err == nil && other.ID != identity.UserID:
			if markErr := s.markConflict(ctx, identity.ID, now); markErr != nil {
				return model.User{}, markErr
			}
			return model.User{}, ErrIdentityConflict
		case err != nil && !errors.Is(err, gorm.ErrRecordNotFound):
			return model.User{}, err
		}
	}

	if !user.EmailVerified {
		return model.User{}, ErrEmailUnverified
	}
	if err := s.DB.WithContext(ctx).Model(&model.UserIdentity{}).
		Where("id = ?", identity.ID).Update("last_login_at", now).Error; err != nil {
		return model.User{}, err
	}
	return user, nil
}

// bindNew handles the first login: the mailbox must be verified and must
// already belong to a panel account (no just-in-time provisioning, O2).
func (s *Service) bindNew(ctx context.Context, c Claims, now time.Time) (model.User, error) {
	if !c.EmailVerified {
		return model.User{}, ErrEmailUnverified
	}
	email := strings.ToLower(strings.TrimSpace(c.Email))
	if email == "" {
		return model.User{}, ErrEmailUnverified
	}

	var user model.User
	if err := s.DB.WithContext(ctx).Where("LOWER(email) = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return model.User{}, ErrNoAccount
		}
		return model.User{}, err
	}
	if !user.EmailVerified {
		return model.User{}, ErrEmailUnverified
	}

	var existing model.UserIdentity
	err := s.DB.WithContext(ctx).
		Where("user_id = ? AND provider = ? AND issuer = ? AND subject <> ?",
			user.ID, c.Provider, c.Issuer, c.Subject).
		First(&existing).Error
	switch {
	case err == nil:
		// The account is bound to a different subject under this issuer: a
		// second human is claiming an account that is already linked.
		return model.User{}, ErrIdentityConflict
	case !errors.Is(err, gorm.ErrRecordNotFound):
		return model.User{}, err
	}

	row := model.UserIdentity{
		UserID:      user.ID,
		Provider:    c.Provider,
		Issuer:      c.Issuer,
		Subject:     c.Subject,
		Email:       email,
		LinkedAt:    now,
		LastLoginAt: &now,
	}
	if err := s.DB.WithContext(ctx).Create(&row).Error; err != nil {
		// A concurrent first login may have won the unique key. Accept that only
		// when it bound the same account; anything else is a conflict.
		var winner model.UserIdentity
		if rerr := s.DB.WithContext(ctx).
			Where("provider = ? AND issuer = ? AND subject = ?", c.Provider, c.Issuer, c.Subject).
			First(&winner).Error; rerr == nil && winner.UserID == user.ID {
			return user, nil
		}
		return model.User{}, ErrIdentityConflict
	}
	return user, nil
}

func (s *Service) markConflict(ctx context.Context, identityID uint, now time.Time) error {
	return s.DB.WithContext(ctx).Model(&model.UserIdentity{}).
		Where("id = ?", identityID).Update("conflict_at", now).Error
}

// List returns the caller's external bindings, newest first.
func (s *Service) List(ctx context.Context, userID uint) ([]model.UserIdentity, error) {
	var rows []model.UserIdentity
	if err := s.DB.WithContext(ctx).
		Where("user_id = ?", userID).Order("id DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// Unlink removes one of the caller's bindings. It refuses the unlink that
// would leave the account with no way to sign in: without a password, without
// passkeys and without another identity there is no self-service recovery.
//
// The whole decision runs in one transaction, and the account row is locked
// first (SELECT ... FOR UPDATE on dialects that support it): two concurrent
// unlinks of a passwordless account's last two credentials therefore serialize
// instead of both passing a stale count. The lock also keeps the count out of
// the DELETE statement — MySQL rejects a same-table subquery there outright
// (ER_UPDATE_TABLE_USED).
func (s *Service) Unlink(ctx context.Context, userID, identityID uint) error {
	return s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Both lookups run under the same account-row lock. The locking read is
		// built per query: `Session(&Session{NewDB: true})` yields a clone=1
		// instance whose first chained call returns a clone=0 instance —
		// chaining `.Clauses(...)` there and reusing the result would let the
		// second `First` inherit the first query's conditions, Model and LIMIT,
		// which on PostgreSQL/MySQL turns every unlink into a 404. Wrapping the
		// locked chain in `Session(&Session{})` (clone=2) makes every chained
		// call clone the locked template instead; on SQLite no lock is needed
		// and the plain fresh session is already chain-safe.
		read := tx.Session(&gorm.Session{NewDB: true})
		if tx.Name() != "sqlite" {
			read = read.Clauses(clause.Locking{Strength: "UPDATE"}).Session(&gorm.Session{})
		}

		var user model.User
		if err := read.Where("id = ?", userID).First(&user).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrIdentityNotFound
			}
			return err
		}

		var identity model.UserIdentity
		if err := read.Where("id = ? AND user_id = ?", identityID, userID).First(&identity).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrIdentityNotFound
			}
			return err
		}

		if !auth.HasPassword(user) {
			// The password cannot vouch for this account; only a passkey or a
			// second binding can remain afterwards.
			var passkeys, others int64
			if err := tx.Model(&model.UserPasskey{}).Where("user_id = ?", userID).Count(&passkeys).Error; err != nil {
				return err
			}
			if err := tx.Model(&model.UserIdentity{}).
				Where("user_id = ? AND id <> ?", userID, identityID).Count(&others).Error; err != nil {
				return err
			}
			if passkeys == 0 && others == 0 {
				return ErrLastCredential
			}
		}

		return tx.Where("id = ? AND user_id = ?", identityID, userID).Delete(&model.UserIdentity{}).Error
	})
}

// StaleCount reports how many identities of one provider are bound under an
// issuer other than the configured one. A deployment that switched IdP keeps
// the old rows: they simply never match again, and this count is what the
// startup warning shows the operator (design O11 and its LDAP counterpart).
func (s *Service) StaleCount(ctx context.Context, provider, issuer string) (int64, error) {
	var count int64
	err := s.DB.WithContext(ctx).Model(&model.UserIdentity{}).
		Where("provider = ? AND issuer <> ?", provider, issuer).
		Count(&count).Error
	return count, err
}

// NewService builds the shared binding service with an explicit clock. The
// caller normalizes nil to time.Now so every provider sees the same default.
func NewService(db *gorm.DB, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{DB: db, Now: now}
}

// MarkSubjectEmailDrift freezes a returning binding whose directory mailbox no
// longer matches the one recorded at bind time. For providers whose subject is
// a user-chosen name (a LDAP username), that drift is the reassigned-username
// signal: whoever holds the name now is not necessarily whoever bound it, and
// the old binding must not keep selecting the former holder's account. The
// binding is marked conflicted, so the login fails closed until an
// administrator resolves it (reset or re-bind). Providers with immutable
// subject identifiers (OIDC `sub`) do not call this: a mailbox change there is
// an ordinary profile edit, and the binding still wins (O4).
func (s *Service) MarkSubjectEmailDrift(ctx context.Context, provider, issuer, subject, email string) (bool, error) {
	var row model.UserIdentity
	err := s.DB.WithContext(ctx).
		Where("provider = ? AND issuer = ? AND subject = ?", provider, issuer, subject).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil // first login: bindNew owns the decision
	}
	if err != nil {
		return false, err
	}
	if row.ConflictAt != nil ||
		strings.EqualFold(strings.TrimSpace(row.Email), strings.TrimSpace(email)) {
		return false, nil
	}
	if err := s.DB.WithContext(ctx).Model(&model.UserIdentity{}).
		Where("id = ?", row.ID).Update("conflict_at", s.Now()).Error; err != nil {
		return false, err
	}
	return true, nil
}
