package captcha

import (
	"errors"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// Options is the full provider configuration Build needs.
type Options struct {
	Provider     string
	FailMode     string
	ChallengeTTL time.Duration

	AltchaKey string
	MaxNumber int64

	GeetestID       string
	GeetestKey      string
	GeetestEndpoint string

	CapInstanceURL string
	CapSiteKey     string
	CapSecret      string

	// HTTPClient is injectable so tests can point at httptest servers and
	// deployments can tune the timeout.
	HTTPClient *http.Client
	Now        func() time.Time
	Logger     *zap.Logger
}

// defaultVerifyTimeout bounds every outbound provider call: the login path
// must never hang on a slow upstream.
const defaultVerifyTimeout = 3 * time.Second

// Build validates the provider configuration and constructs the service. It is
// the only startup wiring point, so a missing secret fails the process instead
// of booting a captcha that can never pass.
func Build(opts Options) (*Service, error) {
	now := nowOrDefault(opts.Now)
	ttl := opts.ChallengeTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	maxNumber := opts.MaxNumber
	if maxNumber <= 0 {
		maxNumber = 100000
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: defaultVerifyTimeout,
			// Verify requests carry the provider secret in their body. A 307/308
			// would re-send that body to the redirect target — an attacker in
			// control of the configured instance (or a misconfigured scheme)
			// could relay it. Verification endpoints do not legitimately
			// redirect, so redirects are refused outright.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	var provider Provider
	switch opts.Provider {
	case "altcha":
		if opts.AltchaKey == "" {
			return nil, errors.New("captcha: PANEL_CAPTCHA_ALTCHA_KEY is required for the altcha provider")
		}
		// A weak HMAC key lets an attacker forge a challenge/signature pair from
		// a single observation, which removes the proof of work.
		if len(opts.AltchaKey) < 32 {
			return nil, errors.New("captcha: PANEL_CAPTCHA_ALTCHA_KEY must be at least 32 bytes")
		}
		provider = newAltchaProvider(opts.AltchaKey, maxNumber, ttl, now)
	case "geetest":
		if opts.GeetestKey == "" {
			return nil, errors.New("captcha: PANEL_CAPTCHA_GEETEST_KEY is required for the geetest provider")
		}
		if opts.GeetestID == "" {
			return nil, errors.New("captcha: captcha.geetest.captchaId is required for the geetest provider")
		}
		endpoint := opts.GeetestEndpoint
		if endpoint == "" {
			endpoint = "https://gcaptcha4.geetest.com"
		}
		provider = newGeetestProvider(opts.GeetestID, opts.GeetestKey, endpoint, client)
	case "cap":
		if opts.CapSecret == "" {
			return nil, errors.New("captcha: PANEL_CAPTCHA_CAP_SECRET is required for the cap provider")
		}
		if opts.CapInstanceURL == "" || opts.CapSiteKey == "" {
			return nil, errors.New("captcha: captcha.cap.instanceUrl and captcha.cap.siteKey are required for the cap provider")
		}
		provider = newCapProvider(opts.CapInstanceURL, opts.CapSiteKey, opts.CapSecret, client)
	default:
		return nil, errors.New("captcha: unknown provider " + opts.Provider)
	}

	return NewService(provider, ServiceOptions{FailMode: opts.FailMode, Logger: opts.Logger}), nil
}
