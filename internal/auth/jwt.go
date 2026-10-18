package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const tokenTypeAccess = "access"

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
