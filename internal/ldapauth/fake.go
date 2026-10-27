package ldapauth

import (
	"context"
	"strings"
	"sync/atomic"
)

// Directory authenticates one directory account and returns the mail attribute
// its entry carries. Production uses the go-ldap implementation; tests use the
// Fake below. The interface stays single-method on purpose: everything else
// (dialing, searching, TLS) is an implementation detail (design L11).
type Directory interface {
	Authenticate(ctx context.Context, username, password string) (email string, err error)
}

// FakeUser is one directory entry the Fake knows about.
type FakeUser struct {
	Mail     string
	Password string
}

// Fake is an in-memory Directory for HTTP-level tests. DialCount is the L1
// evidence channel: the handler must refuse empty credentials before touching
// the directory, and the test asserts that through this counter.
type Fake struct {
	Users       map[string]FakeUser
	Unavailable bool
	Ambiguous   bool
	dials       atomic.Int64
}

// NewFake builds a Fake directory with the given entries.
func NewFake(users map[string]FakeUser) *Fake {
	return &Fake{Users: users}
}

// DialCount reports how many times the fake simulated opening a connection.
func (f *Fake) DialCount() int64 { return f.dials.Load() }

// Authenticate implements Directory.
func (f *Fake) Authenticate(ctx context.Context, username, password string) (string, error) {
	// Mirror the production precondition: empty credentials are refused before
	// any connection exists, so the dial counter proves the handler ordered its
	// checks correctly.
	if username == "" || password == "" {
		return "", ErrInvalidCredentials
	}
	f.dials.Add(1)

	if f.Unavailable {
		return "", ErrDirectoryUnavailable
	}
	if f.Ambiguous {
		return "", ErrAmbiguousResult
	}
	// Directories match uid/sAMAccountName case-insensitively; model that so
	// handler-level tests exercise real lookup semantics regardless of how the
	// fixture keys are spelled.
	var matched []FakeUser
	for name, user := range f.Users {
		if strings.EqualFold(name, username) {
			matched = append(matched, user)
		}
	}
	if len(matched) > 1 {
		// Same fail-closed semantics as the production directory: two entries
		// matching one username must never let either bind.
		return "", ErrAmbiguousResult
	}
	if len(matched) == 0 || matched[0].Password != password {
		return "", ErrInvalidCredentials
	}
	if matched[0].Mail == "" {
		return "", ErrMissingMail
	}
	return matched[0].Mail, nil
}
