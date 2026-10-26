package captcha

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	altchalib "github.com/altcha-org/altcha-lib-go"
)

// solveAltcha mirrors what the browser widget does: solve the proof of work
// and wrap the result in a base64 payload.
func solveAltcha(t *testing.T, ch Challenge) Proof {
	t.Helper()
	algorithm, _ := ch.Params["algorithm"].(string)
	challenge, _ := ch.Params["challenge"].(string)
	salt, _ := ch.Params["salt"].(string)
	signature, _ := ch.Params["signature"].(string)
	maxNumber, _ := ch.Params["maxNumber"].(int64)

	solution, err := altchalib.SolveChallenge(challenge, salt, altchalib.Algorithm(algorithm), int(maxNumber), 0, nil)
	require.NoError(t, err)

	raw, err := json.Marshal(altchalib.Payload{
		Algorithm: algorithm,
		Challenge: challenge,
		Number:    int64(solution.Number),
		Salt:      salt,
		Signature: signature,
	})
	require.NoError(t, err)

	return Proof{Response: map[string]string{"payload": base64.StdEncoding.EncodeToString(raw)}}
}

func TestAltcha_RoundTrip(t *testing.T) {
	p := newAltchaProvider("test-key", 10000, 5*time.Minute, time.Now)
	ch, err := p.Challenge(context.Background())
	require.NoError(t, err)
	require.Equal(t, "altcha", ch.Provider)
	require.Equal(t, "SHA-256", ch.Params["algorithm"])

	require.NoError(t, p.Verify(context.Background(), solveAltcha(t, ch)))
}

func TestAltcha_SingleUse(t *testing.T) {
	p := newAltchaProvider("test-key", 10000, 5*time.Minute, time.Now)
	ch, err := p.Challenge(context.Background())
	require.NoError(t, err)
	proof := solveAltcha(t, ch)

	require.NoError(t, p.Verify(context.Background(), proof))
	require.ErrorIs(t, p.Verify(context.Background(), proof), ErrInvalid)
}

func TestAltcha_Expired(t *testing.T) {
	// A negative TTL makes the signed expiry land in the past; the library
	// compares it against the wall clock, so no clock injection is needed.
	p := newAltchaProvider("test-key", 10000, -time.Minute, time.Now)
	ch, err := p.Challenge(context.Background())
	require.NoError(t, err)

	require.ErrorIs(t, p.Verify(context.Background(), solveAltcha(t, ch)), ErrInvalid)
}

func TestAltcha_GarbagePayload(t *testing.T) {
	p := newAltchaProvider("test-key", 10000, 5*time.Minute, time.Now)
	for _, payload := range []string{"not-base64!!", base64.StdEncoding.EncodeToString([]byte("{}"))} {
		err := p.Verify(context.Background(), Proof{Response: map[string]string{"payload": payload}})
		require.ErrorIs(t, err, ErrInvalid)
	}
}

func TestAltcha_WrongKey(t *testing.T) {
	issuer := newAltchaProvider("issuer-key", 10000, 5*time.Minute, time.Now)
	ch, err := issuer.Challenge(context.Background())
	require.NoError(t, err)

	verifier := newAltchaProvider("other-key", 10000, 5*time.Minute, time.Now)
	require.ErrorIs(t, verifier.Verify(context.Background(), solveAltcha(t, ch)), ErrInvalid)
}

func TestAltcha_MissingPayload(t *testing.T) {
	p := newAltchaProvider("test-key", 10000, 5*time.Minute, time.Now)
	require.True(t, errors.Is(p.Verify(context.Background(), Proof{}), ErrRequired))
}
