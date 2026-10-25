package captcha

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"time"

	altchalib "github.com/altcha-org/altcha-lib-go"
)

// altchaProvider is the embedded proof-of-work provider: challenges are signed
// and carry their own expiry, so the server stores nothing except the set of
// already consumed signatures.
type altchaProvider struct {
	key       string
	maxNumber int64
	ttl       time.Duration
	now       func() time.Time
	used      *usedStore
}

// maxUsedChallenges bounds the replay table (CWE-770).
const maxUsedChallenges = 8192

func newAltchaProvider(key string, maxNumber int64, ttl time.Duration, now func() time.Time) *altchaProvider {
	now = nowOrDefault(now)
	return &altchaProvider{
		key:       key,
		maxNumber: maxNumber,
		ttl:       ttl,
		now:       now,
		used:      newUsedStore(maxUsedChallenges, now),
	}
}

func (p *altchaProvider) Name() string { return "altcha" }

func (p *altchaProvider) Challenge(context.Context) (Challenge, error) {
	expires := p.now().Add(p.ttl)
	ch, err := altchalib.CreateChallenge(altchalib.ChallengeOptions{
		HMACKey:   p.key,
		MaxNumber: p.maxNumber,
		Expires:   &expires,
	})
	if err != nil {
		return Challenge{}, err
	}
	return Challenge{
		Provider: p.Name(),
		Params: map[string]any{
			"algorithm": ch.Algorithm,
			"challenge": ch.Challenge,
			"maxNumber": ch.MaxNumber,
			"salt":      ch.Salt,
			"signature": ch.Signature,
		},
	}, nil
}

func (p *altchaProvider) Verify(_ context.Context, proof Proof) error {
	payload := proof.Response["payload"]
	if payload == "" {
		return ErrRequired
	}
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return ErrInvalid
	}
	var parsed altchalib.Payload
	if err := json.Unmarshal(raw, &parsed); err != nil || parsed.Signature == "" {
		return ErrInvalid
	}
	// Reserve before verifying: one attempt per challenge, and a replayed
	// payload is rejected even when the first attempt failed.
	if !p.used.Reserve(parsed.Signature, p.ttl) {
		return ErrInvalid
	}
	ok, err := altchalib.VerifySolution(payload, p.key, true)
	if err != nil || !ok {
		return ErrInvalid
	}
	return nil
}
