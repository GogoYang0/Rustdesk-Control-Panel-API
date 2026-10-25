// Package captcha gates the public credential-checking endpoints behind a
// configurable interactive challenge. Providers are interchangeable: the
// embedded proof-of-work provider (Altcha) needs no external service, while
// GeeTest and Cap delegate verification to their own servers.
package captcha

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"
)

// Sentinel errors the HTTP layer maps onto 400/503 responses.
var (
	// ErrRequired means the request carried no captcha proof at all.
	ErrRequired = errors.New("captcha proof required")
	// ErrInvalid covers a missing, expired, already used or wrong proof, and
	// any provider-side judgement that the solution is not acceptable.
	ErrInvalid = errors.New("captcha proof invalid")
	// ErrUnavailable means the provider could not be reached or answered with
	// a transport-level failure, not a judgement about the proof.
	ErrUnavailable = errors.New("captcha provider unavailable")
)

// Proof is the provider-specific credential submitted with a request.
type Proof struct {
	Response map[string]string
}

// Challenge is the public half of a challenge, ready to be serialized.
type Challenge struct {
	Provider string
	Params   map[string]any
}

// Provider creates challenges and verifies their solutions.
type Provider interface {
	Name() string
	Challenge(ctx context.Context) (Challenge, error)
	Verify(ctx context.Context, proof Proof) error
}

// singleUseTTL bounds the local replay table for provider-issued tokens: the
// panel has no way to learn the provider's own validity window, and one
// solution must never authorise a second attempt through this panel.
const singleUseTTL = 10 * time.Minute

// ServiceOptions tunes the fail-mode policy around a provider.
type ServiceOptions struct {
	// FailMode is "closed" (default) or "open". Open lets a request through
	// when the provider is unreachable; judgement failures are never open.
	FailMode string
	Logger   *zap.Logger
}

// Service is the entry point shared by the three gated endpoints.
type Service struct {
	provider Provider
	enabled  bool
	failMode string
	logger   *zap.Logger
}

// NewService wraps a provider. A nil provider yields a disabled service.
func NewService(p Provider, opts ServiceOptions) *Service {
	logger := opts.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	failMode := opts.FailMode
	if failMode == "" {
		failMode = "closed"
	}
	return &Service{provider: p, enabled: p != nil, failMode: failMode, logger: logger}
}

// Disabled returns a service that never challenges and never rejects.
func Disabled() *Service {
	return &Service{failMode: "closed", logger: zap.NewNop()}
}

// Enabled reports whether the callers must require a proof.
func (s *Service) Enabled() bool { return s != nil && s.enabled }

// Challenge asks the configured provider for a fresh challenge.
func (s *Service) Challenge(ctx context.Context) (Challenge, error) {
	if !s.Enabled() {
		return Challenge{}, ErrUnavailable
	}
	return s.provider.Challenge(ctx)
}

// Verify checks a proof. An empty response is a missing proof; a provider
// outage is converted according to the fail mode, and a provider judgement is
// always returned as ErrInvalid by the provider itself.
func (s *Service) Verify(ctx context.Context, proof Proof) error {
	if !s.Enabled() {
		return nil
	}
	if len(proof.Response) == 0 {
		return ErrRequired
	}
	err := s.provider.Verify(ctx, proof)
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrUnavailable) && s.failMode == "open" {
		// Operational window only: the deployment decided an outage must not
		// block logins. Logged at error level so it is never silent.
		s.logger.Error("captcha provider unavailable; fail-mode open let the request through",
			zap.String("provider", s.provider.Name()), zap.Error(err))
		return nil
	}
	return err
}

// nowOrDefault normalizes an injected clock.
func nowOrDefault(now func() time.Time) func() time.Time {
	if now == nil {
		return time.Now
	}
	return now
}
