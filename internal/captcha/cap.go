package captcha

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// capProvider validates tokens issued by a self-hosted Cap Standalone
// instance through its /siteverify endpoint.
type capProvider struct {
	instanceURL string
	siteKey     string
	secret      string
	client      *http.Client
	used        *usedStore
}

func newCapProvider(instanceURL, siteKey, secret string, client *http.Client) *capProvider {
	return &capProvider{
		instanceURL: strings.TrimSuffix(instanceURL, "/"),
		siteKey:     siteKey,
		secret:      secret,
		client:      client,
		used:        newUsedStore(maxUsedChallenges, nil),
	}
}

func (p *capProvider) Name() string { return "cap" }

func (p *capProvider) Challenge(context.Context) (Challenge, error) {
	return Challenge{
		Provider: p.Name(),
		Params: map[string]any{
			// Cap's widget appends challenge/redeem to this endpoint.
			"api_endpoint": p.instanceURL + "/" + p.siteKey + "/",
			"site_key":     p.siteKey,
		},
	}, nil
}

func (p *capProvider) Verify(ctx context.Context, proof Proof) (err error) {
	token := proof.Response["response"]
	if token == "" {
		return ErrRequired
	}
	if !p.used.Reserve(token, singleUseTTL) {
		return ErrInvalid
	}
	// A transport or provider fault is not a verdict; free the reservation so
	// the same token can be retried once the provider recovers.
	defer func() {
		if errors.Is(err, ErrUnavailable) {
			p.used.Release(token)
		}
	}()
	body, err := json.Marshal(map[string]string{"secret": p.secret, "response": token})
	if err != nil {
		return ErrUnavailable
	}
	endpoint := p.instanceURL + "/" + p.siteKey + "/siteverify"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return ErrUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 500 {
		return ErrUnavailable
	}

	// Cap answers a verdict with a non-2xx status: 404 "Token not found" for an
	// unknown or already consumed token, 403 for an expired one or a wrong
	// secret. The body decides, so a server error is the only status class that
	// counts as an outage; a body without a success field (an intermediary
	// error page, say) carries no verdict and stays an outage too.
	var answer struct {
		Success *bool `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&answer); err != nil {
		return ErrUnavailable
	}
	if answer.Success == nil {
		return ErrUnavailable
	}
	if !*answer.Success || resp.StatusCode > 299 {
		return ErrInvalid
	}
	p.used.MarkVerified(token)
	return nil
}
