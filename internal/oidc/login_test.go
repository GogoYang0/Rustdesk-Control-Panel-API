package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth/oidctest"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

func newLoginHarness(t *testing.T) (*Service, *oidctest.Server, *testClock) {
	t.Helper()

	svc, clock := newFlowService(t)
	fake := oidctest.New(t, "panel-client")
	svc.cfg.Issuer = fake.Issuer
	svc.cfg.ClientID = "panel-client"
	svc.cfg.ClientSecret = "s3cret-value"
	svc.cfg.Scopes = []string{"openid", "profile", "email"}
	svc.cfg.CallbackURL = "https://panel.example.com/api/v1/auth/oidc/callback"
	svc.cfg.ClockSkew = time.Minute
	// The fake IdP signs with the real clock, so verification must use it too;
	// the frozen test clock is only for the flow rows.
	svc.cfg.Now = time.Now
	return svc, fake, clock
}

func seedUser(t *testing.T, s *Service, email string, verified bool) model.User {
	t.Helper()

	u := model.User{Email: strings.ToLower(email), PasswordHash: "argon2id-placeholder", EmailVerified: verified}
	if err := s.db.Create(&u).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return u
}

// beginCallback runs start and returns the state plus the nonce the IdP must
// echo, mirroring the browser leg without a browser.
func beginCallback(t *testing.T, s *Service, redirectPath string) (state, nonce string) {
	t.Helper()

	authURL, state, err := s.Start(context.Background(), redirectPath)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse auth url: %v", err)
	}
	return state, parsed.Query().Get("nonce")
}

func TestFinishCallback_HappyPathBindsFirstLogin(t *testing.T) {
	svc, fake, _ := newLoginHarness(t)
	u := seedUser(t, svc, "oidc-alice@example.com", true)

	state, nonce := beginCallback(t, svc, "/devices")
	fake.Nonce = nonce
	fake.Sub = "idp-subject-alice"
	fake.Email = "OIDC-Alice@example.com" // the IdP may differ in case
	fake.EmailVerified = true

	res, err := svc.FinishCallback(context.Background(), state, "code-1")
	if err != nil {
		t.Fatalf("FinishCallback: %v", err)
	}
	if res.Ticket == "" {
		t.Fatal("no ticket issued")
	}
	if res.RedirectPath != "/devices" {
		t.Fatalf("redirect path = %q", res.RedirectPath)
	}

	var identity model.UserIdentity
	if err := svc.db.Where("provider = ? AND issuer = ? AND subject = ?",
		model.IdentityProviderOIDC, fake.Issuer, "idp-subject-alice").First(&identity).Error; err != nil {
		t.Fatalf("identity row: %v", err)
	}
	if identity.UserID != u.ID {
		t.Fatalf("identity bound to user %d, want %d", identity.UserID, u.ID)
	}
	if identity.LastLoginAt == nil {
		t.Fatal("last_login_at not recorded")
	}
	if identity.ConflictAt != nil {
		t.Fatal("a fresh binding is marked conflicted")
	}

	// The ticket must resolve to the same account, exactly once.
	got, err := svc.ExchangeTicket(context.Background(), res.Ticket)
	if err != nil {
		t.Fatalf("ExchangeTicket: %v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("ticket resolved to user %d, want %d", got.ID, u.ID)
	}
	if _, err := svc.ExchangeTicket(context.Background(), res.Ticket); !errors.Is(err, ErrInvalidTicket) {
		t.Fatalf("ticket reuse = %v, want ErrInvalidTicket", err)
	}
}

func TestFinishCallback_SecondLoginSkipsEmail(t *testing.T) {
	svc, fake, _ := newLoginHarness(t)
	u := seedUser(t, svc, "oidc-bob@example.com", true)

	state, nonce := beginCallback(t, svc, "/")
	fake.Nonce = nonce
	fake.Sub = "subject-bob"
	fake.Email = "oidc-bob@example.com"
	fake.EmailVerified = true
	if _, err := svc.FinishCallback(context.Background(), state, "code-1"); err != nil {
		t.Fatalf("first login: %v", err)
	}

	// The IdP now reports a different (recycled) mailbox; the binding must win.
	state2, nonce2 := beginCallback(t, svc, "/")
	fake.Nonce = nonce2
	fake.Email = "someone-else@example.com"
	if _, err := svc.FinishCallback(context.Background(), state2, "code-2"); err != nil {
		t.Fatalf("second login: %v", err)
	}

	var identity model.UserIdentity
	if err := svc.db.Where("subject = ?", "subject-bob").First(&identity).Error; err != nil {
		t.Fatalf("identity: %v", err)
	}
	if identity.UserID != u.ID {
		t.Fatalf("identity moved to user %d", identity.UserID)
	}
}

func TestFinishCallback_NonceMismatch(t *testing.T) {
	svc, fake, _ := newLoginHarness(t)
	seedUser(t, svc, "oidc-nonce@example.com", true)

	state, _ := beginCallback(t, svc, "/")
	fake.Nonce = "a-different-nonce"
	fake.Sub = "subject-nonce"
	fake.Email = "oidc-nonce@example.com"
	fake.EmailVerified = true

	if _, err := svc.FinishCallback(context.Background(), state, "code-1"); !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("FinishCallback = %v, want ErrNonceMismatch", err)
	}
}

func TestFinishCallback_RejectsBadTokens(t *testing.T) {
	cases := []struct {
		name  string
		apply func(*oidctest.Server)
	}{
		{"wrong audience", func(f *oidctest.Server) { f.Audience = []string{"another-client"} }},
		{"wrong issuer", func(f *oidctest.Server) { f.IssuerClaim = "https://evil.example.com" }},
		{"expired token", func(f *oidctest.Server) { f.IDTokenTTL = -2 * time.Minute }},
		{"token endpoint failure", func(f *oidctest.Server) { f.TokenStatus = 400 }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, fake, _ := newLoginHarness(t)
			seedUser(t, svc, "oidc-bad@example.com", true)

			state, nonce := beginCallback(t, svc, "/")
			fake.Nonce = nonce
			fake.Sub = "subject-bad"
			fake.Email = "oidc-bad@example.com"
			fake.EmailVerified = true
			tc.apply(fake)

			if _, err := svc.FinishCallback(context.Background(), state, "code-1"); !errors.Is(err, ErrLoginFailed) {
				t.Fatalf("FinishCallback = %v, want ErrLoginFailed", err)
			}
		})
	}
}

func TestFinishCallback_EmailVerifiedShapes(t *testing.T) {
	cases := []struct {
		name  string
		value any
		ok    bool
	}{
		{"boolean true", true, true},
		{"string true", "true", true},
		{"boolean false", false, false},
		{"string false", "false", false},
		{"missing claim", nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, fake, _ := newLoginHarness(t)
			seedUser(t, svc, "oidc-shape@example.com", true)

			state, nonce := beginCallback(t, svc, "/")
			fake.Nonce = nonce
			fake.Sub = "subject-shape"
			fake.Email = "oidc-shape@example.com"
			fake.EmailVerified = tc.value

			_, err := svc.FinishCallback(context.Background(), state, "code-1")
			if tc.ok {
				if err != nil {
					t.Fatalf("FinishCallback = %v, want success", err)
				}
				return
			}
			if !errors.Is(err, ErrEmailUnverified) {
				t.Fatalf("FinishCallback = %v, want ErrEmailUnverified", err)
			}
		})
	}
}

func TestFinishCallback_NoAccount(t *testing.T) {
	svc, fake, _ := newLoginHarness(t)
	state, nonce := beginCallback(t, svc, "/")
	fake.Nonce = nonce
	fake.Sub = "subject-orphan"
	fake.Email = "oidc-nobody@example.com"
	fake.EmailVerified = true

	if _, err := svc.FinishCallback(context.Background(), state, "code-1"); !errors.Is(err, ErrNoAccount) {
		t.Fatalf("FinishCallback = %v, want ErrNoAccount (no JIT provisioning)", err)
	}
}

func TestFinishCallback_UnverifiedPanelAccountIsRefused(t *testing.T) {
	svc, fake, _ := newLoginHarness(t)
	seedUser(t, svc, "oidc-unverified@example.com", false)

	state, nonce := beginCallback(t, svc, "/")
	fake.Nonce = nonce
	fake.Sub = "subject-unverified"
	fake.Email = "oidc-unverified@example.com"
	fake.EmailVerified = true

	if _, err := svc.FinishCallback(context.Background(), state, "code-1"); !errors.Is(err, ErrEmailUnverified) {
		t.Fatalf("FinishCallback = %v, want ErrEmailUnverified for an unconfirmed account", err)
	}
}

// TestFinishCallback_SubjectConflictMarksRow covers the recycled-mailbox
// takeover path: subject stays bound to A while the mailbox now belongs to B.
func TestFinishCallback_SubjectConflictMarksRow(t *testing.T) {
	svc, fake, _ := newLoginHarness(t)
	alice := seedUser(t, svc, "oidc-conflict-a@example.com", true)
	bob := seedUser(t, svc, "oidc-conflict-b@example.com", true)

	state, nonce := beginCallback(t, svc, "/")
	fake.Nonce = nonce
	fake.Sub = "subject-shared"
	fake.Email = "oidc-conflict-a@example.com"
	fake.EmailVerified = true
	if _, err := svc.FinishCallback(context.Background(), state, "code-1"); err != nil {
		t.Fatalf("first bind: %v", err)
	}

	// The IdP recycles alice's subject to bob's mailbox.
	state2, nonce2 := beginCallback(t, svc, "/")
	fake.Nonce = nonce2
	fake.Email = "oidc-conflict-b@example.com"
	if _, err := svc.FinishCallback(context.Background(), state2, "code-2"); !errors.Is(err, ErrIdentityConflict) {
		t.Fatalf("FinishCallback = %v, want ErrIdentityConflict", err)
	}

	var identity model.UserIdentity
	if err := svc.db.Where("subject = ?", "subject-shared").First(&identity).Error; err != nil {
		t.Fatalf("identity: %v", err)
	}
	if identity.UserID != alice.ID {
		t.Fatalf("binding moved to %d; a conflict must not rebind", identity.UserID)
	}
	if identity.ConflictAt == nil {
		t.Fatal("conflict_at not set; the operator cannot tell which binding is broken")
	}
	if bob.ID == alice.ID {
		t.Fatal("fixture bug: the two accounts must differ")
	}
}

// TestFinishCallback_IssuerChangeBindsFresh pins O11: after switching IdP the
// same subject string is a different person, so it must bind by the new
// issuer rather than matching the old row.
func TestFinishCallback_IssuerChangeBindsFresh(t *testing.T) {
	svc, fake, _ := newLoginHarness(t)
	alice := seedUser(t, svc, "oidc-issuer-a@example.com", true)
	bob := seedUser(t, svc, "oidc-issuer-b@example.com", true)

	state, nonce := beginCallback(t, svc, "/")
	fake.Nonce = nonce
	fake.Sub = "same-subject"
	fake.Email = "oidc-issuer-a@example.com"
	fake.EmailVerified = true
	if _, err := svc.FinishCallback(context.Background(), state, "code-1"); err != nil {
		t.Fatalf("first bind: %v", err)
	}

	// Point the service at a second IdP that happens to use the same subject.
	second := oidctest.New(t, "panel-client")
	svc.cfg.Issuer = second.Issuer
	svc.mu.Lock()
	svc.p = nil // force discovery against the new issuer
	svc.mu.Unlock()

	state2, nonce2 := beginCallback(t, svc, "/")
	second.Nonce = nonce2
	second.Sub = "same-subject"
	second.Email = "oidc-issuer-b@example.com"
	second.EmailVerified = true
	if _, err := svc.FinishCallback(context.Background(), state2, "code-2"); err != nil {
		t.Fatalf("second bind: %v", err)
	}

	var rows []model.UserIdentity
	if err := svc.db.Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("list identities: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("identities = %d, want 2 (one per issuer)", len(rows))
	}
	if rows[0].UserID != alice.ID || rows[1].UserID != bob.ID {
		t.Fatalf("issuer change bound the wrong accounts: %+v", rows)
	}
	if rows[0].Issuer == rows[1].Issuer {
		t.Fatal("both rows carry the same issuer")
	}
}

// TestErrorCode pins the redirect codes the SPA matches on.
func TestErrorCode(t *testing.T) {
	cases := map[error]string{
		ErrNonceMismatch:                        "oidc_failed",
		ErrLoginFailed:                          "oidc_failed",
		ErrInvalidState:                         "oidc_failed",
		ErrStateExpired:                         "oidc_failed",
		ErrStateUsed:                            "oidc_failed",
		ErrInvalidTicket:                        "oidc_failed",
		ErrNoAccount:                            "no_account",
		ErrEmailUnverified:                      "email_unverified",
		ErrIdentityConflict:                     "identity_conflict",
		fmt.Errorf("%w: wrapped", ErrNoAccount): "no_account",
	}
	for err, want := range cases {
		if got := ErrorCode(err); got != want {
			t.Fatalf("ErrorCode(%v) = %q, want %q", err, got, want)
		}
	}
	if got := ErrorCode(errors.New("boom")); got != "oidc_failed" {
		t.Fatalf("unknown error maps to %q, want oidc_failed", got)
	}
}

// TestFinishCallback_ConcurrentFirstBind pins the race two browsers create when
// the same mailbox signs in for the first time twice at once: both attempts
// succeed, exactly one identity row exists (the unique-key loser re-reads and
// finds its own account).
func TestFinishCallback_ConcurrentFirstBind(t *testing.T) {
	svc, fake, _ := newLoginHarness(t)
	u := seedUser(t, svc, "oidc-race-bind@example.com", true)

	state1, nonce1 := beginCallback(t, svc, "/")
	state2, nonce2 := beginCallback(t, svc, "/")
	// Each flow echoes its own authorize-time nonce, like a real IdP.
	fake.NoncesByCode = map[string]string{
		"code-" + state1: nonce1,
		"code-" + state2: nonce2,
	}
	fake.Sub = "subject-race"
	fake.Email = u.Email
	fake.EmailVerified = true

	var wg sync.WaitGroup
	var errs [2]error
	run := func(i int, state string) {
		defer wg.Done()
		_, errs[i] = svc.FinishCallback(context.Background(), state, "code-"+state)
	}
	wg.Add(2)
	go run(0, state1)
	go run(1, state2)
	wg.Wait()

	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("both first logins must succeed, got %v / %v", errs[0], errs[1])
	}
	var count int64
	if err := svc.db.Model(&model.UserIdentity{}).Where("user_id = ?", u.ID).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("identity rows = %d, want exactly 1", count)
	}
}

// TestExchangeTicket_Concurrent pins the ticket's single-use guarantee under
// concurrency: one winner, one loser, one token pair ever issued.
func TestExchangeTicket_Concurrent(t *testing.T) {
	svc, fake, _ := newLoginHarness(t)
	u := seedUser(t, svc, "oidc-race-ticket@example.com", true)

	state, nonce := beginCallback(t, svc, "/")
	fake.Nonce = nonce
	fake.Sub = "subject-ticket-race"
	fake.Email = u.Email
	fake.EmailVerified = true
	res, err := svc.FinishCallback(context.Background(), state, "code-1")
	if err != nil {
		t.Fatalf("FinishCallback: %v", err)
	}

	var wg sync.WaitGroup
	var wins atomic.Int64
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := svc.ExchangeTicket(context.Background(), res.Ticket); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := wins.Load(); got != 1 {
		t.Fatalf("successful exchanges = %d, want exactly 1", got)
	}
}
