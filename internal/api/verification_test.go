package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/mail"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// failingMailer simulates an SMTP outage: every send fails.
type failingMailer struct{}

func (failingMailer) Send(context.Context, mail.Message) error {
	return errors.New("smtp unavailable")
}

// newMailHarness is a harness whose mailer renders every message into a
// buffer, so tests can assert recipients and follow the links inside.
func newMailHarness(t *testing.T) (*harness, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	h := newHarnessWith(t, func(d *api.Deps) {
		d.Mailer = mail.NewDev(&buf)
		d.WebBaseURL = "https://panel.example.com"
		d.ResendCooldown = time.Minute
	})
	return h, &buf
}

// extractToken pulls the plaintext token out of a captured mail body by
// matching the link the backend built for the given frontend route.
func extractToken(t *testing.T, buf *bytes.Buffer, route string) string {
	t.Helper()
	re := regexp.MustCompile(regexp.QuoteMeta("https://panel.example.com/"+route) + `\?token=([A-Za-z0-9_-]+)`)
	m := re.FindStringSubmatch(buf.String())
	require.NotNil(t, m, "no %s link found in captured mail: %s", route, buf.String())
	return m[1]
}

// countLinks counts how many verification links have been sent so far.
func countVerificationLinks(buf *bytes.Buffer) int {
	return strings.Count(buf.String(), "verify-email?token=")
}

// An unverified mailbox must not be able to log in, and verification must
// unlock both the account and the rest of the flow.
func TestLogin_RejectsUnverifiedEmail(t *testing.T) {
	h, _ := newMailHarness(t)
	h.seedUnverifiedUser(t, "unv@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/auth/login",
		map[string]string{"email": "unv@example.com", "password": "password123"}, "")
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "email_not_verified")

	// The same password on a verified account logs in fine.
	h.seedUser(t, "ver@example.com", "password123")
	w = h.do(t, http.MethodPost, "/api/v1/auth/login",
		map[string]string{"email": "ver@example.com", "password": "password123"}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

// The verification token is redeemed exactly once: the first call marks the
// mailbox verified, any later call conflicts.
func TestVerifyEmail_RedeemsAndSingleUse(t *testing.T) {
	h, buf := newMailHarness(t)
	u := h.seedUnverifiedUser(t, "redeem@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/auth/resend-verification",
		map[string]string{"email": "redeem@example.com"}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	token := extractToken(t, buf, "verify-email")

	w = h.do(t, http.MethodPost, "/api/v1/auth/verify-email",
		map[string]string{"token": token}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var got model.User
	require.NoError(t, h.db.DB.First(&got, u.ID).Error)
	require.True(t, got.EmailVerified, "the mailbox must be marked verified")

	// Second use of the same token must not succeed.
	w = h.do(t, http.MethodPost, "/api/v1/auth/verify-email",
		map[string]string{"token": token}, "")
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	// And the account can now log in.
	w = h.do(t, http.MethodPost, "/api/v1/auth/login",
		map[string]string{"email": "redeem@example.com", "password": "password123"}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

// Resend must never reveal whether an email has an account: identical 200
// for existing and unknown mailboxes, mail only for the real unverified one.
func TestResendVerification_NoEnumeration(t *testing.T) {
	h, buf := newMailHarness(t)
	h.seedUnverifiedUser(t, "real@example.com", "password123")

	// Unknown mailbox: 200, nothing sent.
	w := h.do(t, http.MethodPost, "/api/v1/auth/resend-verification",
		map[string]string{"email": "ghost@example.com"}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, 0, countVerificationLinks(buf))

	// Real unverified mailbox: 200, one mail with the panel link.
	w = h.do(t, http.MethodPost, "/api/v1/auth/resend-verification",
		map[string]string{"email": "real@example.com"}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, 1, countVerificationLinks(buf))

	// Already verified mailbox: 200, no mail.
	h.seedUser(t, "done@example.com", "password123")
	w = h.do(t, http.MethodPost, "/api/v1/auth/resend-verification",
		map[string]string{"email": "done@example.com"}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, 1, countVerificationLinks(buf))

	// Immediate repeat hits the cooldown: still 200, no second mail.
	w = h.do(t, http.MethodPost, "/api/v1/auth/resend-verification",
		map[string]string{"email": "real@example.com"}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, 1, countVerificationLinks(buf))
}

// When a delivery fails, the token created for that mail must be removed:
// a leftover token would make verificationCooldownActive swallow the
// user's immediate retry for the whole cooldown window.
func TestSendVerificationMail_Failure_CleansUpToken(t *testing.T) {
	h := newHarnessWith(t, func(d *api.Deps) {
		d.Mailer = failingMailer{}
		d.WebBaseURL = "https://panel.example.com"
	})
	h.seedUser(t, "owner5@example.com", "password123")
	ownerToken := h.login(t, "owner5@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "failing-org"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code)
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))

	// Invitation delivery fails hard: 500, no token row left behind.
	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgResp.Data.Id)+"/invitations",
		map[string]string{"email": "stranded@example.com", "role": "member"}, ownerToken)
	require.Equal(t, http.StatusInternalServerError, w.Code)

	// The invitee accepts through a directly inserted invitation; the
	// verification mail fails softly (warn) but its token must be cleaned.
	inviteToken := h.newInvitationForTest(t, orgResp.Data.Id, "stranded@example.com", "member")
	w = h.do(t, http.MethodPost, "/api/v1/invitations/accept",
		map[string]string{"token": inviteToken, "password": "strangepass1"}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// The immediate resend goes through (the failed-delivery token was
	// deleted, so no cooldown applies) and also cleans up after itself.
	w = h.do(t, http.MethodPost, "/api/v1/auth/resend-verification",
		map[string]string{"email": "stranded@example.com"}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var tokens int64
	require.NoError(t, h.db.DB.Model(&model.VerificationToken{}).Count(&tokens).Error)
	require.Zero(t, tokens, "failed deliveries must not leave token rows behind")
}

// Two concurrent redeems of the same token must yield exactly one success:
// the conditional used_at update serialises the race, and no request may
// observe a redeem that later rolls back.
func TestVerifyEmail_ConcurrentRedeem_ExactlyOnce(t *testing.T) {
	h, buf := newMailHarness(t)
	h.seedUnverifiedUser(t, "race@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/auth/resend-verification",
		map[string]string{"email": "race@example.com"}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	token := extractToken(t, buf, "verify-email")

	const attempts = 2
	results := make([]*httptest.ResponseRecorder, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = h.do(t, http.MethodPost, "/api/v1/auth/verify-email",
				map[string]string{"token": token}, "")
		}(i)
	}
	wg.Wait()

	ok, rejected := 0, 0
	for _, rec := range results {
		switch rec.Code {
		case http.StatusOK:
			ok++
		case http.StatusConflict, http.StatusInternalServerError:
			// 409 means the token was already consumed; 500 can surface
			// from SQLite busy under concurrent writers. Both are "not
			// redeemed" — never a second success.
			rejected++
		default:
			require.Failf(t, "unexpected status", "got %d: %s", rec.Code, rec.Body.String())
		}
	}
	require.Equal(t, 1, ok, "exactly one redeem may succeed")
	require.Equal(t, attempts-1, rejected)

	var used int64
	require.NoError(t, h.db.DB.Model(&model.VerificationToken{}).
		Where("used_at IS NOT NULL").Count(&used).Error)
	require.EqualValues(t, 1, used, "the token must be consumed exactly once")

	var u model.User
	require.NoError(t, h.db.DB.Where("email = ?", "race@example.com").First(&u).Error)
	require.True(t, u.EmailVerified)
}

// Expired tokens are rejected exactly like unknown ones (409), so a leaked
// old link is worthless.
func TestVerifyEmail_ExpiredToken_409(t *testing.T) {
	h, _ := newMailHarness(t)
	u := h.seedUnverifiedUser(t, "late@example.com", "password123")

	token := "expired-token-0123456789abcdef"
	sum := sha256.Sum256([]byte(token))
	vt := model.VerificationToken{
		UserID:    u.ID,
		TokenHash: hex.EncodeToString(sum[:]),
		Purpose:   model.VerificationPurposeEmail,
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	require.NoError(t, h.db.DB.Create(&vt).Error)

	w := h.do(t, http.MethodPost, "/api/v1/auth/verify-email",
		map[string]string{"token": token}, "")
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	var got model.User
	require.NoError(t, h.db.DB.First(&got, u.ID).Error)
	require.False(t, got.EmailVerified)
}

// Creating an invitation must deliver the token by email only: the response
// carries no token and the stored hash matches the mailed one.
func TestCreateInvitation_SendsEmail_NoTokenInResponse(t *testing.T) {
	h, buf := newMailHarness(t)
	h.seedUser(t, "inv-owner@example.com", "password123")
	ownerToken := h.login(t, "inv-owner@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "mail-org"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code)
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))

	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgResp.Data.Id)+"/invitations",
		map[string]string{"email": "invited@example.com", "role": "member"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	require.NotContains(t, w.Body.String(), `"token"`)

	token := extractToken(t, buf, "accept-invitation")
	require.Contains(t, buf.String(), "invited@example.com", "the invitation must be addressed to the invitee")

	var stored model.Invitation
	require.NoError(t, store.ScopedByOrg(h.db.DB, uint(orgResp.Data.Id)).First(&stored).Error)
	sum := sha256.Sum256([]byte(token))
	require.Equal(t, hex.EncodeToString(sum[:]), stored.TokenHash,
		"the mailed token must be the one whose hash is stored")
}

// Accepting an invitation creates an unverified account and emails the
// verification link; the fresh account cannot log in until it verifies.
func TestAcceptInvitation_CreatesUnverifiedUser_AndSendsMail(t *testing.T) {
	h, buf := newMailHarness(t)
	h.seedUser(t, "acc-owner@example.com", "password123")
	ownerToken := h.login(t, "acc-owner@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "acc-org"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code)
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))

	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgResp.Data.Id)+"/invitations",
		map[string]string{"email": "newbie@example.com", "role": "member"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code)
	inviteToken := extractToken(t, buf, "accept-invitation")

	w = h.do(t, http.MethodPost, "/api/v1/invitations/accept",
		map[string]string{"token": inviteToken, "password": "newpass123"}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var u model.User
	require.NoError(t, h.db.DB.Where("email = ?", "newbie@example.com").First(&u).Error)
	require.False(t, u.EmailVerified, "an invitation-created account starts unverified")
	require.Equal(t, 1, countVerificationLinks(buf), "a verification mail must be sent")
	require.Contains(t, buf.String(), "newbie@example.com")

	// The password is correct but the mailbox is not confirmed yet.
	w = h.do(t, http.MethodPost, "/api/v1/auth/login",
		map[string]string{"email": "newbie@example.com", "password": "newpass123"}, "")
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}
