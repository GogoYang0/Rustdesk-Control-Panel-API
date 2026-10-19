package compatapi

import (
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// loginRequest mirrors the client's login body (rustdesk 1.5): the device
// identity (id/uuid) travels with the credentials so the server can bind the
// device to the session's organization.
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	ID       string `json:"id"`
	UUID     string `json:"uuid"`
}

// userPayload mirrors the client's UserPayload serde struct
// (rustdesk src/hbbs_http/account.rs).
type userPayload struct {
	Name        string         `json:"name"`
	DisplayName *string        `json:"display_name,omitempty"`
	Avatar      *string        `json:"avatar,omitempty"`
	Email       *string        `json:"email,omitempty"`
	Note        *string        `json:"note,omitempty"`
	Status      int            `json:"status"`
	Info        map[string]any `json:"info"`
	IsAdmin     bool           `json:"is_admin"`
}

// authBody mirrors the client's AuthBody serde struct.
type authBody struct {
	AccessToken string      `json:"access_token"`
	Type        string      `json:"type"`
	User        userPayload `json:"user"`
}

func userPayloadOf(u model.User) userPayload {
	email := u.Email
	return userPayload{
		Name:   email,
		Email:  &email,
		Status: 1,
		Info:   map[string]any{},
	}
}

// dummyCompatHash is verified for unknown accounts to keep login timing flat.
var dummyCompatHash = sync.OnceValue(func() string {
	hash, err := auth.HashPassword("dummy-password-for-compat-timing")
	if err != nil {
		return ""
	}
	return hash
})

// login authenticates a RustDesk client and binds the session to exactly
// one organization (issue C16): username is either "email" (single-org
// accounts bind automatically) or "email#orgID" (multi-org disambiguation).
func (s *Server) login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Username == "" || req.Password == "" {
		compatError(c, http.StatusBadRequest, "invalid login payload")
		return
	}
	ip := c.ClientIP()

	if !s.deps.Guard.AllowIP(ip) {
		compatError(c, http.StatusTooManyRequests, "too many login attempts")
		return
	}
	if s.deps.Guard.Locked(req.Username, ip) {
		compatError(c, http.StatusTooManyRequests, "account temporarily locked")
		return
	}

	email, orgSelector, hasOrgSelector := strings.Cut(req.Username, "#")

	// Always run one Argon2id verification so the response time does not
	// reveal whether the email exists (CWE-208).
	var user model.User
	err := store.WithoutTenantScope(s.deps.DB).Where("email = ?", email).First(&user).Error
	hashToCheck := dummyCompatHash()
	if err == nil {
		hashToCheck = user.PasswordHash
	}
	valid := false
	if ok, verr := auth.VerifyPassword(hashToCheck, req.Password); verr == nil && err == nil && ok {
		valid = true
	}
	if !valid {
		s.deps.Guard.RecordFailure(req.Username, ip)
		compatError(c, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if !user.EmailVerified {
		// Issue #17: the mailbox must be confirmed before any login path
		// issues tokens.
		compatError(c, http.StatusForbidden, "email is not verified; confirm it via the panel")
		return
	}

	orgID, status, msg, ok := s.resolveOrg(user.ID, orgSelector, hasOrgSelector)
	if !ok {
		compatError(c, status, msg)
		return
	}

	s.deps.Guard.Reset(req.Username, ip)

	token, jti, err := s.deps.Issuer.IssueCompat(user.ID, orgID, s.deps.AccessTTL)
	if err != nil {
		compatError(c, http.StatusInternalServerError, "login failed")
		return
	}
	session := model.CompatSession{
		OrganizationID: orgID,
		UserID:         user.ID,
		JTI:            jti,
		DeviceID:       req.ID,
		UUID:           req.UUID,
		ExpiresAt:      s.deps.Now().Add(s.deps.AccessTTL),
	}
	if err := store.WithoutTenantScope(s.deps.DB).Create(&session).Error; err != nil {
		compatError(c, http.StatusInternalServerError, "login failed")
		return
	}

	// Bind the device to the organization so heartbeats/sysinfo from this
	// client land on a device row even before the admin registers one. A
	// failed binding keeps the session valid; heartbeats then simply cannot
	// resolve a device row yet.
	if req.ID != "" {
		_, _ = s.deps.Devices.Register(c.Request.Context(), orgID, device.RegisterInput{
			Name:       req.ID,
			RustdeskID: req.ID,
		})
	}

	c.JSON(http.StatusOK, authBody{
		AccessToken: token,
		Type:        "access_token",
		User:        userPayloadOf(user),
	})
}

// resolveOrg applies the C16 disambiguation: no selector requires exactly
// one membership; a selector must name a membership of this user. The
// message guides multi-org users to the management panel.
func (s *Server) resolveOrg(userID uint, selector string, hasSelector bool) (uint, int, string, bool) {
	var memberships []model.Membership
	if err := store.WithoutTenantScope(s.deps.DB).
		Where("user_id = ?", userID).
		Order("organization_id").
		Find(&memberships).Error; err != nil {
		return 0, http.StatusInternalServerError, "login failed", false
	}
	if hasSelector {
		orgID, err := strconv.ParseUint(selector, 10, 64)
		if err != nil {
			return 0, http.StatusForbidden, "invalid organization selector; use email#orgID", false
		}
		for _, m := range memberships {
			if uint64(m.OrganizationID) == orgID {
				return m.OrganizationID, 0, "", true
			}
		}
		return 0, http.StatusForbidden, "you are not a member of that organization", false
	}
	switch len(memberships) {
	case 1:
		return memberships[0].OrganizationID, 0, "", true
	case 0:
		return 0, http.StatusForbidden, "no organization membership; ask your administrator for an invitation", false
	default:
		return 0, http.StatusForbidden,
			"you belong to multiple organizations; sign in as email#orgID (see the panel for your organization ids)",
			false
	}
}

// logout revokes the caller's compat session by jti: the token itself stays
// cryptographically valid but fails the session lookup.
func (s *Server) logout(c *gin.Context) {
	_, _, jti := sessionFrom(c)
	if err := store.WithoutTenantScope(s.deps.DB).
		Model(&model.CompatSession{}).
		Where("jti = ? AND revoked_at IS NULL", jti).
		Update("revoked_at", s.deps.Now()).Error; err != nil {
		compatError(c, http.StatusInternalServerError, "logout failed")
		return
	}
	ok(c)
}

// currentUser answers with the caller's user payload.
func (s *Server) currentUser(c *gin.Context) {
	uid, _, _ := sessionFrom(c)
	var user model.User
	if err := store.WithoutTenantScope(s.deps.DB).First(&user, uid).Error; err != nil {
		compatError(c, http.StatusUnauthorized, "user not found")
		return
	}
	c.JSON(http.StatusOK, userPayloadOf(user))
}

// loginOptions is the client's capability probe; an empty list means "no
// extra login options" (e.g. no OIDC providers configured).
func (s *Server) loginOptions(c *gin.Context) {
	c.JSON(http.StatusOK, []any{})
}
