package captcha

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// geetestScriptURL is the client-side widget script; the challenge endpoint
// only publishes it so a frontend can load the widget.
const geetestScriptURL = "https://static.geetest.com/v4/gt4.js"

// geetestProvider validates GeeTest v4 solutions server-side.
type geetestProvider struct {
	captchaID string
	key       string
	endpoint  string
	client    *http.Client
}

func newGeetestProvider(captchaID, key, endpoint string, client *http.Client) *geetestProvider {
	return &geetestProvider{
		captchaID: captchaID,
		key:       key,
		endpoint:  strings.TrimSuffix(endpoint, "/"),
		client:    client,
	}
}

func (p *geetestProvider) Name() string { return "geetest" }

func (p *geetestProvider) Challenge(context.Context) (Challenge, error) {
	return Challenge{
		Provider: p.Name(),
		Params: map[string]any{
			"captcha_id": p.captchaID,
			"script_url": geetestScriptURL,
		},
	}, nil
}

// geetestResponse is the subset of the validation answer the panel needs.
type geetestResponse struct {
	Status string `json:"status"`
	Result string `json:"result"`
}

func (p *geetestProvider) Verify(ctx context.Context, proof Proof) error {
	lotNumber := proof.Response["lot_number"]
	captchaOutput := proof.Response["captcha_output"]
	passToken := proof.Response["pass_token"]
	genTime := proof.Response["gen_time"]
	if lotNumber == "" || captchaOutput == "" || passToken == "" || genTime == "" {
		return ErrInvalid
	}

	mac := hmac.New(sha256.New, []byte(p.key))
	mac.Write([]byte(lotNumber))
	form := url.Values{
		"lot_number":     {lotNumber},
		"captcha_output": {captchaOutput},
		"pass_token":     {passToken},
		"gen_time":       {genTime},
		"sign_token":     {hex.EncodeToString(mac.Sum(nil))},
	}

	endpoint := p.endpoint + "/validate?captcha_id=" + url.QueryEscape(p.captchaID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return ErrUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return ErrUnavailable
	}

	var answer geetestResponse
	if err := json.NewDecoder(resp.Body).Decode(&answer); err != nil {
		// A body the provider cannot produce is a provider fault, not a verdict
		// on the submitted proof.
		return ErrUnavailable
	}
	if answer.Status != "success" || answer.Result != "success" {
		return ErrInvalid
	}
	return nil
}
