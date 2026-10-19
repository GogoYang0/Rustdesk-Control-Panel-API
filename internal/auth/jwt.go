package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	tokenTypeAccess = "access"
	tokenTypeCompat = "compat"
)

// Issuer mints access JWTs and opaque refresh tokens.
type Issuer struct {
	secret     []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
}

// NewIssuer builds an Issuer; non-positive TTLs are allowed (used by tests).
func NewIssuer(secret string, accessTTL, refreshTTL time.Duration) *Issuer {
	return &Issuer{secret: []byte(secret), accessTTL: accessTTL, refreshTTL: refreshTTL}
}

// AccessTTL returns the configured access token lifetime.
func (i *Issuer) AccessTTL() time.Duration { return i.accessTTL }

// RefreshTTL returns the configured refresh token lifetime.
func (i *Issuer) RefreshTTL() time.Duration { return i.refreshTTL }

// Issue mints an access JWT and an opaque refresh token for the user.
func (i *Issuer) Issue(userID uint) (access, refresh string, err error) {
	now := time.Now()
	jtiRaw := make([]byte, 16)
	if _, err := rand.Read(jtiRaw); err != nil {
		return "", "", fmt.Errorf("generate jti: %w", err)
	}
	claims := jwt.MapClaims{
		"sub": fmt.Sprint(userID),
		"typ": tokenTypeAccess,
		"jti": base64.RawURLEncoding.EncodeToString(jtiRaw),
		"iat": now.Unix(),
		"exp": now.Add(i.accessTTL).Unix(),
	}
	access, err = jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(i.secret)
	if err != nil {
		return "", "", fmt.Errorf("sign access token: %w", err)
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate refresh token: %w", err)
	}
	refresh = base64.RawURLEncoding.EncodeToString(raw)
	return access, refresh, nil
}

// ParseAccess validates an access JWT and returns its user ID.
func (i *Issuer) ParseAccess(token string) (uint, error) {
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return i.secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithExpirationRequired())
	if err != nil {
		return 0, fmt.Errorf("parse access token: %w", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || !parsed.Valid {
		return 0, fmt.Errorf("invalid access token")
	}
	if typ, _ := claims["typ"].(string); typ != tokenTypeAccess {
		return 0, fmt.Errorf("wrong token type %q", typ)
	}
	sub, _ := claims["sub"].(string)
	var uid uint
	if _, err := fmt.Sscan(sub, &uid); err != nil {
		return 0, fmt.Errorf("invalid subject %q", sub)
	}
	return uid, nil
}

// IssueCompat mints a RustDesk-compatibility access token that carries the
// bound organization and a jti matching a persisted CompatSession row. The
// lifetime comes from compat.accessTTL (long-lived by design: 720h).
func (i *Issuer) IssueCompat(userID, orgID uint, ttl time.Duration) (token, jti string, err error) {
	now := time.Now()
	jtiRaw := make([]byte, 16)
	if _, err := rand.Read(jtiRaw); err != nil {
		return "", "", fmt.Errorf("generate jti: %w", err)
	}
	jti = base64.RawURLEncoding.EncodeToString(jtiRaw)
	claims := jwt.MapClaims{
		"sub": fmt.Sprint(userID),
		"typ": tokenTypeCompat,
		"org": fmt.Sprint(orgID),
		"jti": jti,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	}
	token, err = jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(i.secret)
	if err != nil {
		return "", "", fmt.Errorf("sign compat token: %w", err)
	}
	return token, jti, nil
}

// ParseCompat validates a RustDesk-compatibility token and returns its user
// ID, bound organization and jti. Management tokens (typ=access) are
// rejected: the two token families must never be interchangeable.
func (i *Issuer) ParseCompat(token string) (userID, orgID uint, jti string, err error) {
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return i.secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithExpirationRequired())
	if err != nil {
		return 0, 0, "", fmt.Errorf("parse compat token: %w", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || !parsed.Valid {
		return 0, 0, "", fmt.Errorf("invalid compat token")
	}
	if typ, _ := claims["typ"].(string); typ != tokenTypeCompat {
		return 0, 0, "", fmt.Errorf("wrong token type %q", typ)
	}
	if uid, err := parseUintClaim(claims["sub"]); err != nil {
		return 0, 0, "", fmt.Errorf("invalid subject")
	} else {
		userID = uid
	}
	if org, err := parseUintClaim(claims["org"]); err != nil {
		return 0, 0, "", fmt.Errorf("missing organization claim")
	} else {
		orgID = org
	}
	jti, _ = claims["jti"].(string)
	if jti == "" {
		return 0, 0, "", fmt.Errorf("missing jti")
	}
	return userID, orgID, jti, nil
}

// parseUintClaim converts a numeric or string claim into a uint.
func parseUintClaim(v any) (uint, error) {
	switch n := v.(type) {
	case string:
		var uid uint
		if _, err := fmt.Sscan(n, &uid); err != nil {
			return 0, fmt.Errorf("invalid numeric claim %q", n)
		}
		return uid, nil
	case float64:
		if n < 0 {
			return 0, fmt.Errorf("negative numeric claim")
		}
		return uint(n), nil
	default:
		return 0, fmt.Errorf("unsupported claim type %T", v)
	}
}
