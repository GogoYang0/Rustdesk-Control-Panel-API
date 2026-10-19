package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

type harness struct {
	router *gin.Engine
	db     store.Store
	issuer *auth.Issuer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	gin.SetMode(gin.TestMode)

	// One named in-memory database per test keeps runs independent, so
	// go test -count=2 does not collide on unique indexes.
	dsn := "file:apitest_" + sanitize(t.Name()) + "?mode=memory&cache=shared"
	st, err := store.Open(config.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(
		&model.User{}, &model.RefreshToken{},
		&model.Organization{}, &model.Membership{}, &model.Invitation{},
		&model.AuditLog{}, &model.Device{}, &model.DeviceHeartbeat{},
	))

	issuer := auth.NewIssuer("test-secret", time.Minute, time.Hour)
	svc := auth.NewService(st.DB, issuer, nil)

	r := api.NewRouter(api.Deps{
		DB:            st.DB,
		Auth:          svc,
		Devices:       device.NewService(st.DB, nil),
		Issuer:        issuer,
		AccessTTL:     time.Minute,
		RefreshTTL:    time.Hour,
		InvitationTTL: time.Hour,
	})

	return &harness{router: r, db: *st, issuer: issuer}
}

func (h *harness) do(t *testing.T, method, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.10:1234"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, req)
	return w
}

// doFrom issues the request from a specific client address so per-IP limits
// can be exercised independently of the other calls in a test.
func (h *harness) doFrom(t *testing.T, ip, method, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":4321"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, req)
	return w
}

func (h *harness) seedUser(t *testing.T, email, password string) model.User {
	t.Helper()
	hash, err := auth.HashPassword(password)
	require.NoError(t, err)
	u := model.User{Email: email, PasswordHash: hash}
	require.NoError(t, h.db.DB.Create(&u).Error)
	return u
}

func (h *harness) login(t *testing.T, email, password string) string {
	t.Helper()
	w := h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"email": email, "password": password,
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.Data.AccessToken)
	return resp.Data.AccessToken
}

func TestHealthz_ReturnsOK(t *testing.T) {
	h := newHarness(t)
	w := h.do(t, http.MethodGet, "/healthz", nil, "")
	require.Equal(t, http.StatusOK, w.Code)
}

func TestProtectedEndpoint_NoToken_401(t *testing.T) {
	h := newHarness(t)
	w := h.do(t, http.MethodGet, "/api/v1/orgs", nil, "")
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLogin_ReturnsTokens(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "alice@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"email": "alice@example.com", "password": "password123",
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp struct {
		Code string `json:"code"`
		Data struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Equal(t, "ok", resp.Code)
	require.NotEmpty(t, resp.Data.AccessToken)
	require.NotEmpty(t, resp.Data.RefreshToken)
}

func TestLogin_BadPassword_401(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "bob@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"email": "bob@example.com", "password": "wrong-password",
	}, "")
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

// The sixth attempt from one IP within a minute must be rate limited.
func TestLogin_RateLimited(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "carol@example.com", "password123")

	for i := 0; i < 5; i++ {
		w := h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
			"email": "carol@example.com", "password": "wrong-password",
		}, "")
		require.NotEqual(t, http.StatusTooManyRequests, w.Code, "attempt %d should not be limited yet", i+1)
	}

	w := h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"email": "carol@example.com", "password": "wrong-password",
	}, "")
	require.Equal(t, http.StatusTooManyRequests, w.Code)
}

func TestCreateOrg_BecomesOwner(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "dave@example.com", "password123")
	token := h.login(t, "dave@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "acme"}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	var resp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotZero(t, resp.Data.Id)

	var m model.Membership
	require.NoError(t, store.ScopedByOrg(h.db.DB, uint(resp.Data.Id)).First(&m).Error)
	require.Equal(t, model.RoleOwner, m.Role)
}

func TestListMembers_CrossOrg_Forbidden(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "erin@example.com", "password123")
	h.seedUser(t, "frank@example.com", "password123")

	erinToken := h.login(t, "erin@example.com", "password123")
	frankToken := h.login(t, "frank@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "erin-org"}, erinToken)
	require.Equal(t, http.StatusCreated, w.Code)
	w = h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "frank-org"}, frankToken)
	require.Equal(t, http.StatusCreated, w.Code)

	var frankResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &frankResp))

	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(frankResp.Data.Id)+"/members", nil, erinToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}

func TestAcceptInvitation_JoinsAsRole(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "owner@example.com", "password123")
	ownerToken := h.login(t, "owner@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "invite-org"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code)
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))

	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgResp.Data.Id)+"/invitations",
		map[string]string{"email": "newbie@example.com", "role": "admin"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	var invResp struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &invResp))
	require.NotEmpty(t, invResp.Data.Token)

	// Only the hash is stored.
	var stored model.Invitation
	require.NoError(t, store.ScopedByOrg(h.db.DB, uint(orgResp.Data.Id)).First(&stored).Error)
	require.NotEqual(t, invResp.Data.Token, stored.TokenHash)
	require.NotEmpty(t, stored.TokenHash)

	w = h.do(t, http.MethodPost, "/api/v1/invitations/accept",
		map[string]string{"token": invResp.Data.Token, "password": "newpass123"}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var member model.Membership
	require.NoError(t, store.ScopedByOrg(h.db.DB, uint(orgResp.Data.Id)).
		Where("role = ?", model.RoleAdmin).First(&member).Error)
	require.NotZero(t, member.UserID)

	// Reusing the token must fail with a conflict.
	w = h.do(t, http.MethodPost, "/api/v1/invitations/accept",
		map[string]string{"token": invResp.Data.Token, "password": "newpass123"}, "")
	require.Equal(t, http.StatusConflict, w.Code)
}

func itoa(v int64) string {
	return json.Number(func() string {
		b, _ := json.Marshal(v)
		return string(b)
	}()).String()
}

// sanitize turns a test name into a safe sqlite database suffix.
func sanitize(name string) string {
	r := strings.NewReplacer("/", "_", " ", "_", "-", "_")
	return r.Replace(name)
}

// Accepting an invitation for an email that already has an account requires
// that account's password (no pre-hijack of the mailbox).
func TestAcceptInvitation_ExistingUserWrongPassword_401(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "owner2@example.com", "password123")
	h.seedUser(t, "existing@example.com", "originalpass1")
	ownerToken := h.login(t, "owner2@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "hijack-org"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code)
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))

	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgResp.Data.Id)+"/invitations",
		map[string]string{"email": "existing@example.com", "role": "member"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code)
	var invResp struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &invResp))

	// Wrong password for an existing account must be rejected.
	w = h.do(t, http.MethodPost, "/api/v1/invitations/accept",
		map[string]string{"token": invResp.Data.Token, "password": "attacker-pass1"}, "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())

	// The real password still works.
	w = h.do(t, http.MethodPost, "/api/v1/invitations/accept",
		map[string]string{"token": invResp.Data.Token, "password": "originalpass1"}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

// Accepting an invitation must share the login guard, otherwise the public
// route becomes an unlimited password oracle.
func TestAcceptInvitation_PasswordGuessing_IsRateLimited(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "owner3@example.com", "password123")
	h.seedUser(t, "victim@example.com", "correct-pass1")
	ownerToken := h.login(t, "owner3@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "oracle-org"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code)
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))

	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgResp.Data.Id)+"/invitations",
		map[string]string{"email": "victim@example.com", "role": "member"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code)
	var invResp struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &invResp))

	body := map[string]string{"token": invResp.Data.Token, "password": "guess-guess1"}
	const attackerIP = "198.51.100.77"
	for i := 0; i < 5; i++ {
		w = h.doFrom(t, attackerIP, http.MethodPost, "/api/v1/invitations/accept", body, "")
		require.Equal(t, http.StatusUnauthorized, w.Code, "attempt %d", i+1)
	}

	// The sixth attempt from the same IP is throttled before verification runs.
	w = h.doFrom(t, attackerIP, http.MethodPost, "/api/v1/invitations/accept", body, "")
	require.Equal(t, http.StatusTooManyRequests, w.Code, w.Body.String())
}

func TestCreateDevice_WritesAndHeartbeats(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "dev-owner@example.com", "password123")
	token := h.login(t, "dev-owner@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "device-org"}, token)
	require.Equal(t, http.StatusCreated, w.Code)
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))

	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgResp.Data.Id)+"/devices",
		map[string]string{"name": "laptop", "rustdesk_id": "555000111"}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	var devResp struct {
		Data struct {
			Id         int64  `json:"id"`
			Status     string `json:"status"`
			RustdeskId string `json:"rustdesk_id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &devResp))
	require.Equal(t, "555000111", devResp.Data.RustdeskId)
	require.Equal(t, "offline", devResp.Data.Status, "a new device has no heartbeat yet")

	// Re-registering the same rustdesk id must not create a second row.
	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgResp.Data.Id)+"/devices",
		map[string]string{"name": "laptop-2", "rustdesk_id": "555000111"}, token)
	require.Equal(t, http.StatusCreated, w.Code)

	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgResp.Data.Id)+"/devices/"+itoa(devResp.Data.Id)+"/heartbeat", nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var hbResp struct {
		Data struct {
			Status     string `json:"status"`
			LastSeenAt string `json:"last_seen_at"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &hbResp))
	require.Equal(t, "online", hbResp.Data.Status)
	require.NotEmpty(t, hbResp.Data.LastSeenAt)
}

func TestCreateDevice_MemberRole_Forbidden(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "owner4@example.com", "password123")
	ownerToken := h.login(t, "owner4@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "rbac-org"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code)
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))

	// Invite a second user as member, accept, then try to write a device.
	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgResp.Data.Id)+"/invitations",
		map[string]string{"email": "plain@example.com", "role": "member"}, ownerToken)
	require.Equal(t, http.StatusCreated, w.Code)
	var invResp struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &invResp))

	w = h.do(t, http.MethodPost, "/api/v1/invitations/accept",
		map[string]string{"token": invResp.Data.Token, "password": "memberpass1"}, "")
	require.Equal(t, http.StatusOK, w.Code)

	memberToken := h.login(t, "plain@example.com", "memberpass1")
	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgResp.Data.Id)+"/devices",
		map[string]string{"name": "nope", "rustdesk_id": "1"}, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
}
