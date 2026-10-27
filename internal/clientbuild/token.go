package clientbuild

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type bundlePayload struct {
	BuildID uint  `json:"build_id"`
	Exp     int64 `json:"exp"`
}

func SignBundleToken(key []byte, buildID uint, now time.Time, ttl time.Duration) (string, error) {
	if len(key) == 0 || buildID == 0 || ttl <= 0 {
		return "", fmt.Errorf("%w: cannot sign bundle token", ErrTokenInvalid)
	}
	payload, err := json.Marshal(bundlePayload{BuildID: buildID, Exp: now.Add(ttl).Unix()})
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func VerifyBundleToken(key []byte, token string, now time.Time) (uint, error) {
	if len(key) == 0 {
		return 0, fmt.Errorf("%w: bundle key is not configured", ErrTokenInvalid)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return 0, fmt.Errorf("%w: malformed token", ErrTokenInvalid)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, fmt.Errorf("%w: malformed payload", ErrTokenInvalid)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, fmt.Errorf("%w: malformed signature", ErrTokenInvalid)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return 0, fmt.Errorf("%w: signature mismatch", ErrTokenInvalid)
	}
	var decoded bundlePayload
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return 0, fmt.Errorf("%w: malformed payload", ErrTokenInvalid)
	}
	if decoded.BuildID == 0 || decoded.Exp <= now.Unix() {
		return 0, fmt.Errorf("%w: token expired", ErrTokenInvalid)
	}
	return decoded.BuildID, nil
}
