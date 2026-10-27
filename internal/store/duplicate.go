package store

import (
	"strings"
)

// IsDuplicateKeyError reports whether err is a unique-constraint violation.
// It matches the message shapes of SQLite, PostgreSQL and MySQL, so callers
// can turn a lost race into their domain 409 without re-querying — which on
// PostgreSQL would fail anyway: the transaction is aborted after a unique
// violation and every further statement in it errors.
func IsDuplicateKeyError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint") ||
		strings.Contains(msg, "duplicate key") ||
		strings.Contains(msg, "duplicate entry")
}
