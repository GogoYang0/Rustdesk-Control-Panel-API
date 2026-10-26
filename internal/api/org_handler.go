package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/access"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/mail"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// errOrgQuotaReached aborts the transaction that would exceed the per-user
// organization quota.
var errOrgQuotaReached = errors.New("organization quota reached")

// lockUserRow takes a write lock on the caller's row so concurrent creations
// serialise on the quota check instead of both reading the same count. SQLite
// has no SELECT ... FOR UPDATE and serialises writers itself, so the clause is
// skipped there.
func (a *AdminAPI) lockUserRow(tx *gorm.DB, uid uint) error {
	query := tx
	if tx.Name() != "sqlite" {
		query = tx.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var user model.User
	return query.Select("id").First(&user, uid).Error
}

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
	// The quota is checked inside the transaction with the user row locked.
	// Reading the count outside would let two concurrent requests both pass the
	// check and create an organization each (CWE-770, TOCTOU).
	err := a.deps.DB.Transaction(func(tx *gorm.DB) error {
		if a.deps.OrgsPerUser > 0 {
			if err := a.lockUserRow(tx, uid); err != nil {
				return err
			}
			var owned int64
			if err := store.WithoutTenantScope(tx).
				Model(&model.Membership{}).
				Joins("JOIN roles ON roles.id = memberships.role_id AND roles.organization_id = memberships.organization_id").
				Where("memberships.user_id = ? AND roles.kind = ?", uid, model.RoleKindOwner).
				Count(&owned).Error; err != nil {
				return err
			}
			if owned >= int64(a.deps.OrgsPerUser) {
				return errOrgQuotaReached
			}
		}
		if err := tx.Create(&org).Error; err != nil {
			return err
		}
		if err := a.deps.Roles.EnsureBuiltinsTx(tx, org.ID); err != nil {
			return err
		}
		ownerRole, err := authz.RoleByKindTx(tx, org.ID, model.RoleKindOwner)
		if err != nil {
			return err
		}
		if err := store.ScopedByOrg(tx, org.ID).Create(&model.Membership{
			OrganizationID: org.ID,
			UserID:         uid,
			RoleID:         ownerRole.ID,
			Role:           ownerRole.Name,
		}).Error; err != nil {
			return err
		}
		// The access-control defaults (reserved everyone group + its all-devices
		// rule) commit with the organization: without them every member of a new
		// organization would start with an empty device list.
		if err := access.EnsureDefaultsTx(tx, org.ID); err != nil {
			return err
		}
		// Record the audit entry on the same transaction (issue #19): the
		// organization and its audit trail commit or roll back together.
		// Tenant creation is a security-relevant event: without a transactional
		// auditor the organization must not be created at all (fail closed).
		tr, ok := a.deps.Auditor.(audit.TxRecorder)
		if !ok {
			return errAuditUnavailable
		}
		if err := tr.RecordTx(tx, audit.Entry{
			OrganizationID: org.ID,
			ActorUserID:    uid,
			Action:         "organization.create",
			TargetType:     "organization",
			TargetID:       fmt.Sprint(org.ID),
			Detail:         map[string]any{"name": org.Name},
		}); err != nil {
			return err
		}
		return nil
	})
	switch {
	case errors.Is(err, errOrgQuotaReached):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "organization quota reached")
		return
	case errors.Is(err, errAuditUnavailable):
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "audit unavailable")
		return
	case err != nil:
		a.deps.Logger.Error("create org failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not create organization")
		return
	}

	// The domain audit record committed with the transaction; skip the
	// middleware fallback for this request (issue #19).
	c.Set(contextAuditRecorded, true)

	// Provisioning is slow (container start), so it runs on a bounded worker
	// queue after the response. Enqueue failures are recoverable: the
	// organization row is the durable record, and the queue reconciler
	// re-enqueues every organization that has no server group yet.
	if a.deps.ProvisionQueue != nil {
		if err := a.deps.ProvisionQueue.Enqueue(org.ID); err != nil {
			a.deps.Logger.Warn("provisioning deferred to reconciler",
				zap.Uint("org_id", org.ID), zap.Error(err))
		}
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

	roleIdx, err := a.roleIndex(uint(orgId))
	if err != nil {
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not list members")
		return
	}
	out := make([]gen.Member, 0, len(memberships))
	for _, m := range memberships {
		name := roleNameOf(roleIdx, m.RoleID)
		if name == "" {
			name = m.Role
		}
		out = append(out, gen.Member{
			Id:        int64(m.ID),
			UserId:    int64(m.UserID),
			Email:     openapi_types.Email(emails[m.UserID]),
			Role:      name,
			RoleId:    int64(m.RoleID),
			RoleName:  name,
			Disabled:  m.Disabled,
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

	token, err := newRandomToken()
	if err != nil {
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not create invitation")
		return
	}

	inv := model.Invitation{
		OrganizationID: uint(orgId),
		Email:          string(req.Email),
		Role:           role,
		TokenHash:      hashToken(token),
		ExpiresAt:      a.deps.Now().Add(a.deps.InvitationTTL),
	}
	if err := store.ScopedByOrg(a.deps.DB, uint(orgId)).Create(&inv).Error; err != nil {
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not create invitation")
		return
	}

	// Issue #17: the plaintext token travels to the invitee mailbox only.
	// A delivery failure must surface to the admin — there is no recovery
	// path for an invitation that nobody ever received (the row simply
	// expires, and a retry creates a fresh one).
	link := fmt.Sprintf("%s/accept-invitation?token=%s", strings.TrimRight(a.deps.WebBaseURL, "/"), token)
	hours := int(a.deps.InvitationTTL / time.Hour)
	if err := a.deps.Mailer.Send(c.Request.Context(), mail.Message{
		To:      []string{inv.Email},
		Subject: "组织邀请",
		TextBody: fmt.Sprintf("您好！\n\n您被邀请以 %s 身份加入组织。请点击以下链接完成加入并设置密码：\n\n%s\n\n"+
			"该链接 %d 小时内有效，且仅可使用一次。如果您不认识邀请方，请忽略此邮件。\n", role, link, hours),
	}); err != nil {
		a.deps.Logger.Warn("invitation mail delivery failed",
			zap.Uint("invitation_id", inv.ID), zap.Error(err))
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not deliver invitation email")
		return
	}

	// Contract 0.3.0: the invitation token is no longer returned in the
	// response — it is delivered to the invitee mailbox only (issue #17).
	// Mail delivery lands with the email verification task; until then
	// newly created invitations cannot be accepted by anyone (M2 interim).
	c.JSON(http.StatusCreated, gen.InvitationResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.Invitation{
			Id:        int64(inv.ID),
			Email:     openapi_types.Email(inv.Email),
			Role:      gen.InvitationRole(inv.Role),
			ExpiresAt: inv.ExpiresAt,
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
		Where("token_hash = ?", hashToken(req.Token)).
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
	if !a.guard.AllowIP(ip) {
		abortError(c, http.StatusTooManyRequests, gen.ErrorCodeRateLimited, "too many attempts")
		return
	}
	if a.guard.Locked(inv.Email, ip) {
		abortError(c, http.StatusTooManyRequests, gen.ErrorCodeRateLimited, "account temporarily locked")
		return
	}
	// Accepting an invitation verifies a password for an existing account, so
	// it is behind the same captcha as the login endpoint. The invitation is
	// not touched before this point: a missing proof leaves it redeemable.
	if !a.requireCaptcha(c, req.Captcha) {
		return
	}

	var member model.Membership
	var joined model.User
	needVerify := false
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
			// A fresh account starts unverified; the verification mail goes
			// out after the transaction commits.
			user = model.User{Email: inv.Email, PasswordHash: hash, EmailVerified: false}
			if cerr := tx.Create(&user).Error; cerr != nil {
				return cerr
			}
			needVerify = true
		default:
			return err
		}

		// Remember the account for the post-commit mail step.
		joined = user

		joinerRole, rerr := authz.RoleByNameTx(tx, inv.OrganizationID, inv.Role)
		if rerr != nil {
			return rerr
		}
		member = model.Membership{
			OrganizationID: inv.OrganizationID,
			UserID:         user.ID,
			RoleID:         joinerRole.ID,
			Role:           joinerRole.Name,
		}
		if err := store.ScopedByOrg(tx, inv.OrganizationID).Create(&member).Error; err != nil {
			return err
		}

		// Record the audit entry on the same transaction (issue #19): the
		// membership and its audit trail commit or roll back together.
		// Joining a tenant grants a role, so an unrecorded join must not commit
		// (fail closed when the auditor is not transactional).
		tr, ok := a.deps.Auditor.(audit.TxRecorder)
		if !ok {
			return errAuditUnavailable
		}
		if err := tr.RecordTx(tx, audit.Entry{
			OrganizationID: inv.OrganizationID,
			ActorUserID:    user.ID,
			Action:         "invitation.accept",
			TargetType:     "membership",
			TargetID:       fmt.Sprint(member.ID),
			Detail:         map[string]any{"role": inv.Role, "invitation_id": inv.ID},
		}); err != nil {
			return err
		}

		now := a.deps.Now()
		return store.ScopedByOrg(tx, inv.OrganizationID).
			Model(&model.Invitation{}).
			Where("id = ? AND accepted_at IS NULL", inv.ID).
			Updates(map[string]any{"accepted_at": now, "accepted_by": user.ID}).Error
	})
	if errors.Is(err, errInvitationCredentials) {
		a.guard.RecordFailure(inv.Email, ip)
		abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, "invalid credentials for this email")
		return
	}
	if errors.Is(err, errAuditUnavailable) {
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "audit unavailable")
		return
	}
	if err != nil {
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "could not accept invitation")
		return
	}
	a.guard.Reset(inv.Email, ip)

	if needVerify {
		if err := a.sendVerificationMail(c.Request.Context(), joined); err != nil {
			// Membership is durable and the user can recover through
			// POST /auth/resend-verification, so delivery failure is not fatal.
			a.deps.Logger.Warn("verification mail delivery failed",
				zap.Uint("user_id", joined.ID), zap.Error(err))
		}
	}

	// The domain audit record committed with the transaction; skip the
	// middleware fallback for this request (issue #19).
	c.Set(contextAuditRecorded, true)

	c.JSON(http.StatusOK, gen.MemberResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.Member{
			Id:        int64(member.ID),
			UserId:    int64(member.UserID),
			Email:     openapi_types.Email(inv.Email),
			Role:      member.Role,
			RoleId:    int64(member.RoleID),
			RoleName:  member.Role,
			Disabled:  false,
			CreatedAt: member.CreatedAt,
		},
	})
}

// newRandomToken returns a URL-safe random token.
func newRandomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// hashToken mirrors the storage rule: only the SHA-256 hash is kept, for
// invitations and verification tokens alike.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// errInvitationCredentials signals that the email already has an account and
// the supplied password did not match it.
var errInvitationCredentials = errors.New("invalid credentials for invitation email")
