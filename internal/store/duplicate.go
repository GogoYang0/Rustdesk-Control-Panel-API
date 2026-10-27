package store

import (
	"errors"
	"strings"

	"gorm.io/gorm"
)

// IsDuplicateKeyError reports whether err is a unique-constraint violation.
// With TranslateError enabled the gorm drivers wrap the raw error into
// gorm.ErrDuplicatedKey ("duplicated key not allowed"), which none of the
// vendor message shapes below match — so that form is checked first. The raw
// message match stays as a fallback for paths that bypass translation, letting
// callers turn a lost race into their domain 409 without re-querying — which
// on PostgreSQL would fail anyway: the transaction is aborted after a unique
// violation and every further statement in it errors.
func IsDuplicateKeyError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint") ||
		strings.Contains(msg, "duplicate key") ||
		strings.Contains(msg, "duplicate entry")
}
