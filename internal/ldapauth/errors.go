package ldapauth

import "errors"

// Errors returned by a Directory. The HTTP layer maps them onto fixed status
// codes: bind failures are 401, infrastructure failures are 503, and the two
// are never interchangeable (design L5) — an operator reading the logs must be
// able to tell "the directory is down" from "someone is guessing passwords".
var (
	// ErrInvalidCredentials covers wrong passwords and usernames the search
	// cannot find. One message for both: the directory must not become a user
	// enumeration oracle.
	ErrInvalidCredentials = errors.New("invalid directory credentials")

	// ErrDirectoryUnavailable covers dial, TLS and protocol failures: the
	// deployment cannot reach or talk to the directory.
	ErrDirectoryUnavailable = errors.New("ldap directory unavailable")

	// ErrAmbiguousResult means the search matched more than one entry (design
	// L6): binding the first would risk logging into the wrong account, so the
	// whole attempt fails closed.
	ErrAmbiguousResult = errors.New("ldap search matched more than one entry")

	// ErrMissingMail means the entry matched but carries no usable mail
	// attribute, so it cannot be mapped onto a panel account.
	ErrMissingMail = errors.New("directory entry has no mail attribute")
)
