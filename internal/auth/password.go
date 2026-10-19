// Package auth implements password hashing and JWT-based authentication.
package auth

import (
	"fmt"

	"github.com/alexedwards/argon2id"
)

// defaultParams pin OWASP-recommended argon2id parameters (m=19456 KiB, t=2, p=1)
// explicitly instead of relying on library defaults, whose iteration count and
// parallelism may change with the environment. Login is a public-facing surface
// (design C15), so the cost profile must be deterministic.
var defaultParams = &argon2id.Params{
	Memory:      19456,
	Iterations:  2,
	Parallelism: 1,
	SaltLength:  16,
	KeyLength:   32,
}

// HashPassword derives an argon2id hash for the plain-text password.
func HashPassword(plain string) (string, error) {
	if plain == "" {
		return "", fmt.Errorf("password must not be empty")
	}
	hash, err := argon2id.CreateHash(plain, defaultParams)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return hash, nil
}

// VerifyPassword checks the plain-text password against an argon2id hash.
func VerifyPassword(hash, plain string) (bool, error) {
	if hash == "" {
		return false, fmt.Errorf("hash must not be empty")
	}
	return argon2id.ComparePasswordAndHash(plain, hash)
}
