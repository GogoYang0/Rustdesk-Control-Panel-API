package clientbuild

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var testBundleKey = []byte("0123456789abcdef0123456789abcdef")

func TestBundleToken_RoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	token, err := SignBundleToken(testBundleKey, 7, now, 24*time.Hour)
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(token, "."))

	buildID, err := VerifyBundleToken(testBundleKey, token, now.Add(time.Hour))
	require.NoError(t, err)
	require.EqualValues(t, 7, buildID)

	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	require.NoError(t, err)
	var decoded struct {
		BuildID uint  `json:"build_id"`
		Exp     int64 `json:"exp"`
	}
	require.NoError(t, json.Unmarshal(payload, &decoded))
	require.EqualValues(t, 7, decoded.BuildID)
	require.Equal(t, now.Add(24*time.Hour).Unix(), decoded.Exp)
}

func TestBundleToken_Invalid(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	token, err := SignBundleToken(testBundleKey, 7, now, 24*time.Hour)
	require.NoError(t, err)
	parts := strings.Split(token, ".")

	cases := []struct {
		name  string
		token string
		key   []byte
		now   time.Time
	}{
		{"tampered payload", "x" + parts[0] + "." + parts[1], testBundleKey, now},
		{"tampered signature", parts[0] + "." + parts[1][:len(parts[1])-1] + "x", testBundleKey, now},
		{"wrong key", token, []byte("abcdef0123456789abcdef0123456789"), now},
		{"expired", token, testBundleKey, now.Add(25 * time.Hour)},
		{"extra segment", token + ".x", testBundleKey, now},
		{"empty", "", testBundleKey, now},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyBundleToken(tc.key, tc.token, tc.now)
			require.ErrorIs(t, err, ErrTokenInvalid)
		})
	}

	_, err = SignBundleToken(testBundleKey, 0, now, 24*time.Hour)
	require.ErrorIs(t, err, ErrTokenInvalid)
	_, err = SignBundleToken(nil, 7, now, 24*time.Hour)
	require.ErrorIs(t, err, ErrTokenInvalid)
	_, err = SignBundleToken(testBundleKey, 7, now, 0)
	require.ErrorIs(t, err, ErrTokenInvalid)
}
