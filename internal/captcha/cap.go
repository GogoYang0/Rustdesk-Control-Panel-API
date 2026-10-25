package captcha

import (
	"bytes"
	"context"
	"encoding/json"
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
}

func newCapProvider(instanceURL, siteKey, secret string, client *http.Client) *capProvider {
	return &capProvider{
		instanceURL: strings.TrimSuffix(instanceURL, "/"),
		siteKey:     siteKey,
		secret:      secret,
		client:      client,
	}
}

func (p *capProvider) Name() string { return "cap" }

func (p *capProvider) Challenge(context.Context) (Challenge, error) {
	return Challenge{
		Provider: p.Name(),
		Params: map[string]any{
			"api_endpoint": p.instanceURL + "/" + p.siteKey,
			"site_key":     p.siteKey,
		},
	}, nil
}

func (p *capProvider) Verify(ctx context.Context, proof Proof) error {
	token := proof.Response["response"]
	if token == "" {
		return ErrRequired
	}
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
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return ErrUnavailable
	}

	var answer struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&answer); err != nil {
		return ErrUnavailable
	}
	if !answer.Success {
		return ErrInvalid
	}
	return nil
}
