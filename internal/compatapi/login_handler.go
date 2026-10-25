package compatapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

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

// userPayloadOf maps a panel user to the RustDesk client's user payload.
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

	// The lockout key is the normalized email part of the username, never
	// the raw value: rotating an "#orgID" suffix or changing letter case
	// must not create independent failure counters for one account
	// (CWE-307). Credential checks and the guard share this key.
	email, orgSelector, hasOrgSelector := strings.Cut(req.Username, "#")
	lockKey := strings.ToLower(strings.TrimSpace(email))
	if s.deps.Guard.Locked(lockKey, ip) {
		compatError(c, http.StatusTooManyRequests, "account temporarily locked")
		return
	}

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
		s.deps.Guard.RecordFailure(lockKey, ip)
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

	// The identity bounds apply to the session row too, so they are checked even
	// when the client sent no device id: the uuid still lands in
	// CompatSession.UUID, and an over-long value would fail that insert.
	if len(req.ID) > maxDeviceIDLen || len(req.UUID) > maxDeviceUUIDLen {
		compatError(c, http.StatusBadRequest, "invalid device identity")
		return
	}

	// The device claim and the session row land in one transaction (#40): a
	// login that fails to persist its session must not leave a binding
	// behind, and a session must never exist without the binding it was
	// issued under. A login without a device id skips the claim entirely.
	token, jti, err := s.deps.Issuer.IssueCompat(user.ID, orgID, s.deps.AccessTTL)
	if err != nil {
		compatError(c, http.StatusInternalServerError, "login failed")
		return
	}

	if req.ID != "" {
		err = s.deps.DB.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
			generation, cerr := s.claimDeviceTx(tx, orgID, req.ID, req.UUID)
			if cerr != nil {
				// Roll back everything: errDeviceBound is answered below from
				// the returned error, and any other failure must not commit
				// a half state (a binding without its session).
				return cerr
			}
			session := model.CompatSession{
				OrganizationID:    orgID,
				UserID:            user.ID,
				JTI:               jti,
				DeviceID:          req.ID,
				UUID:              req.UUID,
				BindingGeneration: generation,
				ExpiresAt:         s.deps.Now().Add(s.deps.AccessTTL),
			}
			if err := store.WithoutTenantScope(tx).Create(&session).Error; err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			if errors.Is(err, errDeviceBound) {
				compatError(c, http.StatusForbidden,
					"device is already bound to another client; ask your administrator to reset it")
				return
			}
			if errors.Is(err, errDeviceDisabled) {
				compatError(c, http.StatusForbidden,
					"device is disabled; ask your administrator to re-enable it")
				return
			}
			compatError(c, http.StatusInternalServerError, "login failed")
			return
		}
	} else {
		session := model.CompatSession{
			OrganizationID: orgID,
			UserID:         user.ID,
			JTI:            jti,
			ExpiresAt:      s.deps.Now().Add(s.deps.AccessTTL),
		}
		if err := store.WithoutTenantScope(s.deps.DB).Create(&session).Error; err != nil {
			compatError(c, http.StatusInternalServerError, "login failed")
			return
		}
	}

	s.deps.Guard.Reset(lockKey, ip)

	// Heartbeats and sysinfo resolve devices only through the session-bound
	// id and the generation snapshotted above (see device_handler.go).

	c.JSON(http.StatusOK, authBody{
		AccessToken: token,
		Type:        "access_token",
		User:        userPayloadOf(user),
	})
}

// errDeviceBound reports a login that tried to bind a rustdesk id already
// claimed by another client instance.
var errDeviceBound = errors.New("device already bound")

// errDeviceDisabled reports a login against a device an administrator stopped.
var errDeviceDisabled = errors.New("device is disabled")

// claimDeviceTx binds the logging-in device to the organization on the
// caller's transaction, and returns the device's binding generation for the
// session snapshot. The client protocol carries no ownership secret
// (heartbeat/sysinfo travel without credentials), so the device uuid — a
// stable hardware identifier — is the strongest ownership signal available:
// the first client presenting a rustdesk id claims it, an unbound row is
// claimed on arrival, and a login presenting a different uuid is rejected
// instead of taking the binding over (CWE-863). Admins reset a lost binding
// through POST /api/v1/orgs/{orgId}/devices/{deviceId}/rebind, which clears the
// binding and advances the generation in one audited transaction.
func (s *Server) claimDeviceTx(tx *gorm.DB, orgID uint, rustdeskID, uuid string) (uint64, error) {
	var dev model.Device
	err := store.ScopedByOrg(tx, orgID).
		Where("rustdesk_id = ?", rustdeskID).First(&dev).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		created, rerr := device.RegisterTx(tx, orgID, model.Device{
			OrganizationID: orgID,
			RustdeskID:     rustdeskID,
			Name:           rustdeskID,
			BoundUUID:      uuid,
		})
		if rerr != nil {
			return 0, rerr
		}
		// A concurrent request may have registered and claimed the row
		// first: the upsert never overwrites an existing binding, so the
		// race loser must judge on the actually stored value.
		dev = *created
	case err != nil:
		return 0, err
	}
	if dev.Disabled {
		return 0, errDeviceDisabled
	}
	if dev.BoundUUID != "" && uuid != "" && dev.BoundUUID != uuid {
		return 0, errDeviceBound
	}
	if dev.BoundUUID == "" && uuid != "" {
		res := store.ScopedByOrg(tx, orgID).Model(&model.Device{}).
			Where("id = ? AND bound_uuid = ''", dev.ID).
			Updates(map[string]any{
				"bound_uuid":         uuid,
				"binding_generation": gorm.Expr("binding_generation + 1"),
			})
		if res.Error != nil {
			return 0, res.Error
		}
		if res.RowsAffected == 0 {
			// Another request claimed the row first: re-read and compare
			// against the stored binding before issuing anything.
			// Caveat (not reproducible on SQLite): under MySQL REPEATABLE
			// READ this re-read sees the transaction's snapshot, so a
			// concurrent same-uuid claimer can be misjudged as
			// errDeviceBound (the client retries and wins) and the
			// registration-conflict re-read inside RegisterTx can hit
			// ErrRecordNotFound (a 500 instead of the 403). Both are
			// self-healing; Postgres Read Committed and SQLite are exact.
			reRead := store.ScopedByOrg(tx, orgID)
			if tx.Name() != "sqlite" {
				// Current read — same REPEATABLE READ reasoning as
				// device.RegisterTx.
				reRead = reRead.Clauses(clause.Locking{Strength: "UPDATE"})
			}
			if err := reRead.First(&dev, dev.ID).Error; err != nil {
				return 0, err
			}
			if dev.BoundUUID != uuid {
				return 0, errDeviceBound
			}
		}
	}
	// Re-read so the returned generation reflects the row the session will
	// be judged against (current read on non-SQLite dialects, same as
	// device.RegisterTx).
	final := model.Device{}
	finalRead := store.ScopedByOrg(tx, orgID)
	if tx.Name() != "sqlite" {
		finalRead = finalRead.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	if err := finalRead.First(&final, dev.ID).Error; err != nil {
		return 0, err
	}
	// A disable that committed while this login was claiming must win: the
	// final read takes the row lock on the served dialects, so a login that
	// raced the administrator is refused instead of persisting a session.
	if final.Disabled {
		return 0, errDeviceDisabled
	}
	return final.BindingGeneration, nil
}

// resolveOrg applies the C16 disambiguation: no selector requires exactly
// one active membership; a selector must name an active membership of this
// user. A disabled membership is invisible to both paths.
func (s *Server) resolveOrg(userID uint, selector string, hasSelector bool) (uint, int, string, bool) {
	var memberships []model.Membership
	if err := store.WithoutTenantScope(s.deps.DB).
		Where("user_id = ? AND disabled = ?", userID, false).
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
		// Distinguish "never joined" from "disabled": the client's next step
		// differs (ask for an invitation vs ask an administrator to re-enable).
		var total int64
		if err := store.WithoutTenantScope(s.deps.DB).
			Model(&model.Membership{}).
			Where("user_id = ?", userID).
			Count(&total).Error; err != nil {
			return 0, http.StatusInternalServerError, "login failed", false
		}
		if total > 0 {
			return 0, http.StatusForbidden, "membership is disabled; ask your administrator to re-enable it", false
		}
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
