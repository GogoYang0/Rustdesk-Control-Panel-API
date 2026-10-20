package auth

import (
	"errors"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// ErrEmailNotVerified is returned by RequireVerifiedUser when a login is
// attempted with an account whose mailbox is not confirmed yet.
var ErrEmailNotVerified = errors.New("email not verified")

// RequireVerifiedUser gates every login path — the admin Login handler and
// the RustDesk compatibility layer — on a confirmed mailbox (issue #17).
func RequireVerifiedUser(u model.User) error {
	if !u.EmailVerified {
		return ErrEmailNotVerified
	}
	return nil
}
