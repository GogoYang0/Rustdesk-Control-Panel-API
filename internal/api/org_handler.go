package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// CreateOrg creates an organization and makes the caller its owner.
func (a *AdminAPI) CreateOrg(c *gin.Context) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	var req gen.OrgCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Name == "" {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "name is required")
		return
	}

	org := model.Organization{Name: req.Name}
	err := a.deps.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&org).Error; err != nil {
			return err
		}
		return store.ScopedByOrg(tx, org.ID).Create(&model.Membership{
			OrganizationID: org.ID,
			UserID:         uid,
			Role:           model.RoleOwner,
		}).Error
	})
	if err != nil {
		a.deps.Logger.Error("create org failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not create organization")
		return
	}

	// Provisioning is slow (container start), so it runs after the response.
	// The context must not be the request one: it is cancelled on return.
	if a.deps.Provision != nil {
		orgID := org.ID
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			if _, err := a.deps.Provision.ProvisionForOrg(ctx, orgID); err != nil {
				a.deps.Logger.Error("provision hbbs/hbbr failed", zap.Uint("org_id", orgID), zap.Error(err))
			}
		}()
	}

	c.JSON(http.StatusCreated, gen.OrgResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    gen.Org{Id: int64(org.ID), Name: org.Name, CreatedAt: org.CreatedAt},
	})
}

// ListOrgs returns every organization the caller belongs to.
func (a *AdminAPI) ListOrgs(c *gin.Context) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}

	// Listing the caller's own memberships is inherently cross-tenant.
	var memberships []model.Membership
	if err := store.WithoutTenantScope(a.deps.DB).
		Where("user_id = ?", uid).
		Order("organization_id").
		Find(&memberships).Error; err != nil {
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not list organizations")
		return
	}

	ids := make([]uint, 0, len(memberships))
	for _, m := range memberships {
		ids = append(ids, m.OrganizationID)
	}

	var orgs []model.Organization
	if len(ids) > 0 {
		if err := a.deps.DB.Where("id IN ?", ids).Order("id").Find(&orgs).Error; err != nil {
			abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not list organizations")
			return
		}
	}

	out := make([]gen.Org, 0, len(orgs))
	for _, o := range orgs {
		out = append(out, gen.Org{Id: int64(o.ID), Name: o.Name, CreatedAt: o.CreatedAt})
	}

	c.JSON(http.StatusOK, gen.OrgListResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: out})
}

// ListMembers lists the members of an organization.
func (a *AdminAPI) ListMembers(c *gin.Context, orgId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if _, member := a.membershipFor(c, uid, uint(orgId)); !member {
		return
	}

	var memberships []model.Membership
	if err := store.ScopedByOrg(a.deps.DB, uint(orgId)).
		Order("id").
		Find(&memberships).Error; err != nil {
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not list members")
		return
	}

	userIDs := make([]uint, 0, len(memberships))
	for _, m := range memberships {
		userIDs = append(userIDs, m.UserID)
	}
	emails := map[uint]string{}
	if len(userIDs) > 0 {
		var users []model.User
		if err := a.deps.DB.Where("id IN ?", userIDs).Find(&users).Error; err != nil {
			abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not list members")
			return
		}
		for _, u := range users {
			emails[u.ID] = u.Email
		}
	}

	out := make([]gen.Member, 0, len(memberships))
	for _, m := range memberships {
		out = append(out, gen.Member{
			Id:        int64(m.ID),
			UserId:    int64(m.UserID),
			Email:     openapi_types.Email(emails[m.UserID]),
			Role:      gen.MemberRole(m.Role),
			CreatedAt: m.CreatedAt,
		})
	}

	c.JSON(http.StatusOK, gen.MemberListResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: out})
}

// CreateInvitation issues an invitation token for an email address.
func (a *AdminAPI) CreateInvitation(c *gin.Context, orgId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermMemberManage) {
		return
	}

	var req gen.InvitationCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid invitation payload")
		return
	}
	role := string(req.Role)
	if role != model.RoleAdmin && role != model.RoleMember {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "role must be admin or member")
		return
	}

	token, err := newInvitationToken()
	if err != nil {
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not create invitation")
		return
	}

	inv := model.Invitation{
		OrganizationID: uint(orgId),
		Email:          string(req.Email),
		Role:           role,
		TokenHash:      hashInvitationToken(token),
		ExpiresAt:      a.deps.Now().Add(a.deps.InvitationTTL),
	}
	if err := store.ScopedByOrg(a.deps.DB, uint(orgId)).Create(&inv).Error; err != nil {
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not create invitation")
		return
	}

	c.JSON(http.StatusCreated, gen.InvitationResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.Invitation{
			Id:        int64(inv.ID),
			Email:     openapi_types.Email(inv.Email),
			Role:      gen.InvitationRole(inv.Role),
			ExpiresAt: inv.ExpiresAt,
			Token:     &token,
		},
	})
}

// AcceptInvitation joins the caller (created on the fly) to the organization.
func (a *AdminAPI) AcceptInvitation(c *gin.Context) {
	var req gen.InvitationAcceptRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid accept payload")
		return
	}
	if len(req.Password) < 8 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "password must be at least 8 characters")
		return
	}

	// The token itself identifies the organization, so this lookup must look
	// across tenants before the org context is known.
	var inv model.Invitation
	err := store.WithoutTenantScope(a.deps.DB).
		Where("token_hash = ?", hashInvitationToken(req.Token)).
		First(&inv).Error
	if err != nil {
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "invitation is not valid")
		return
	}
	if err := inv.Acceptable(a.deps.Now()); err != nil {
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "invitation is expired or already used")
		return
	}

	// This route is public and verifies a password for existing accounts, so it
	// shares the login guard: otherwise the invitation token would become an
	// unlimited password oracle (CWE-307).
	ip := c.ClientIP()
	if !a.guard.allowIP(ip) {
		abortError(c, http.StatusTooManyRequests, gen.ErrorCodeRateLimited, "too many attempts")
		return
	}
	if a.guard.locked(inv.Email, ip) {
		abortError(c, http.StatusTooManyRequests, gen.ErrorCodeRateLimited, "account temporarily locked")
		return
	}

	var member model.Membership
	err = a.deps.DB.Transaction(func(tx *gorm.DB) error {
		var user model.User
		err := tx.Where("email = ?", inv.Email).First(&user).Error
		switch {
		case err == nil:
			// The mailbox already has an account: the invitation must not be
			// accepted without proving ownership of the account (CWE-287).
			ok, verr := auth.VerifyPassword(user.PasswordHash, req.Password)
			if verr != nil || !ok {
				return errInvitationCredentials
			}
		case errors.Is(err, gorm.ErrRecordNotFound):
			hash, herr := auth.HashPassword(req.Password)
			if herr != nil {
				return herr
			}
			user = model.User{Email: inv.Email, PasswordHash: hash}
			if cerr := tx.Create(&user).Error; cerr != nil {
				return cerr
			}
		default:
			return err
		}

		member = model.Membership{OrganizationID: inv.OrganizationID, UserID: user.ID, Role: inv.Role}
		if err := store.ScopedByOrg(tx, inv.OrganizationID).Create(&member).Error; err != nil {
			return err
		}

		now := a.deps.Now()
		return store.ScopedByOrg(tx, inv.OrganizationID).
			Model(&model.Invitation{}).
			Where("id = ? AND accepted_at IS NULL", inv.ID).
			Updates(map[string]any{"accepted_at": now, "accepted_by": user.ID}).Error
	})
	if errors.Is(err, errInvitationCredentials) {
		a.guard.recordFailure(inv.Email, ip)
		abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, "invalid credentials for this email")
		return
	}
	if err != nil {
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "could not accept invitation")
		return
	}
	a.guard.reset(inv.Email, ip)

	c.JSON(http.StatusOK, gen.MemberResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.Member{
			Id:        int64(member.ID),
			UserId:    int64(member.UserID),
			Email:     openapi_types.Email(inv.Email),
			Role:      gen.MemberRole(member.Role),
			CreatedAt: member.CreatedAt,
		},
	})
}

// newInvitationToken returns a URL-safe random token.
func newInvitationToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// hashInvitationToken mirrors the storage rule: only the SHA-256 hash is kept.
func hashInvitationToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// errInvitationCredentials signals that the email already has an account and
// the supplied password did not match it.
var errInvitationCredentials = errors.New("invalid credentials for invitation email")
