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
	"unicode/utf8"

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
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/controlrole"
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

// maxOrgNameLen mirrors the contract's 1–128 code-point bound.
const maxOrgNameLen = 128

// normaliseOrgName trims surrounding whitespace and enforces the contract bound.
// Create and rename share it so a name that fits one endpoint fits the other.
func normaliseOrgName(name string) (string, error) {
	// The contract's maxLength applies to the raw string; trim only decides
	// whether the name is empty. Keeping both checks on the raw value makes a
	// schema validator and this server agree on the same input.
	if utf8.RuneCountInString(name) > maxOrgNameLen {
		return "", fmt.Errorf("name must be between 1 and %d characters", maxOrgNameLen)
	}
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", fmt.Errorf("name must be between 1 and %d characters", maxOrgNameLen)
	}
	return trimmed, nil
}

// CreateOrg creates an organization and makes the caller its owner.
func (a *AdminAPI) CreateOrg(c *gin.Context) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	var req gen.OrgCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "name is required")
		return
	}
	name, err := normaliseOrgName(req.Name)
	if err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
		return
	}

	org := model.Organization{Name: name}
	// The quota is checked inside the transaction with the user row locked.
	// Reading the count outside would let two concurrent requests both pass the
	// check and create an organization each (CWE-770, TOCTOU).
	err = a.deps.DB.Transaction(func(tx *gorm.DB) error {
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
		}).Error; err != nil {
			return err
		}
		// The access-control defaults (reserved everyone group + its all-devices
		// rule) commit with the organization: without them every member of a new
		// organization would start with an empty device list.
		if err := access.EnsureDefaultsTx(tx, org.ID); err != nil {
			return err
		}
		// The built-in default control role commits with the organization too:
		// every member without an assignment falls back to it, so a missing row
		// would leave the organization with no permission set at all.
		if err := controlrole.EnsureDefaultsTx(tx, org.ID); err != nil {
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

// UpdateOrg renames an organization. Only the owner holds org.admin; members
// are rejected before the name is touched. Names are not unique by contract.
func (a *AdminAPI) UpdateOrg(c *gin.Context, orgId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}

	// Organization is the tenant root, not an org-scoped row: load it directly.
	// A missing id is 404; an existing id the caller cannot administer is 403.
	var existing model.Organization
	if err := a.deps.DB.First(&existing, uint(orgId)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "organization not found")
			return
		}
		a.deps.Logger.Error("load organization for rename failed", zap.Error(err))
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not rename organization")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermOrgAdmin) {
		return
	}

	var req gen.OrgUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "name is required")
		return
	}
	name, err := normaliseOrgName(req.Name)
	if err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
		return
	}

	var updated model.Organization
	err = a.deps.DB.Transaction(func(tx *gorm.DB) error {
		// The request guard runs before the transaction; another owner can revoke
		// this membership in between. Re-read and lock the actor row so a stale
		// permission cannot rename the organization, matching member mutations.
		if _, err := lockActor(tx, uint(orgId), uid, false, authz.PermOrgAdmin); err != nil {
			return err
		}
		query := tx
		if tx.Name() != "sqlite" {
			query = query.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := query.First(&updated, uint(orgId)).Error; err != nil {
			return err
		}
		if updated.Name == name {
			return nil
		}
		oldName := updated.Name
		if err := tx.Model(&model.Organization{}).
			Where("id = ?", orgId).
			Update("name", name).Error; err != nil {
			return fmt.Errorf("update organization name: %w", err)
		}
		updated.Name = name
		tr, ok := a.deps.Auditor.(audit.TxRecorder)
		if !ok {
			return errAuditUnavailable
		}
		return tr.RecordTx(tx, audit.Entry{
			OrganizationID: uint(orgId),
			ActorUserID:    uid,
			Action:         "organization.rename",
			TargetType:     "organization",
			TargetID:       fmt.Sprint(orgId),
			Detail:         map[string]any{"old_name": oldName, "new_name": name},
		})
	})
	switch {
	case errors.Is(err, errActorNoLongerAuthorized):
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "insufficient permissions")
		return
	case errors.Is(err, gorm.ErrRecordNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "organization not found")
		return
	case errors.Is(err, errAuditUnavailable):
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "audit unavailable")
		return
	case err != nil:
		a.deps.Logger.Error("rename organization failed", zap.Error(err))
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not rename organization")
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.OrgResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    gen.Org{Id: int64(updated.ID), Name: updated.Name, CreatedAt: updated.CreatedAt},
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
		// The role row is the only source; a missing row leaves the name empty
		// rather than guessing from a stale string (fail closed).
		name := roleNameOf(roleIdx, m.RoleID)
		out = append(out, gen.Member{
			Id:            int64(m.ID),
			UserId:        int64(m.UserID),
			Email:         openapi_types.Email(emails[m.UserID]),
			Role:          name,
			RoleId:        int64(m.RoleID),
			RoleName:      name,
			ControlRoleId: controlRoleIDOf(m),
			StrategyId:    strategyIDToAPI(m.StrategyID),
			Disabled:      m.Disabled,
			CreatedAt:     m.CreatedAt,
		})
	}

	c.JSON(http.StatusOK, gen.MemberListResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: out})
}

// ListInvitations returns the organization's pending invitations. Tokens are
// never stored in plaintext, so only the public invitation fields are mapped.
func (a *AdminAPI) ListInvitations(c *gin.Context, orgId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if !a.loadOrgForManagement(c, uint(orgId)) {
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermMemberManage) {
		return
	}

	var rows []model.Invitation
	if err := store.ScopedByOrg(a.deps.DB, uint(orgId)).
		Where("accepted_at IS NULL AND revoked_at IS NULL").
		Order("id DESC").
		Find(&rows).Error; err != nil {
		a.deps.Logger.Error("list invitations failed", zap.Error(err))
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not list invitations")
		return
	}
	now := a.deps.Now()
	out := make([]gen.Invitation, 0, len(rows))
	for _, inv := range rows {
		// Expiry is filtered in Go: SQLite stores timestamps as text, and a SQL
		// comparison would be sensitive to the stored offset.
		if !now.Before(inv.ExpiresAt) {
			continue
		}
		out = append(out, gen.Invitation{
			Id:        int64(inv.ID),
			Email:     openapi_types.Email(inv.Email),
			Role:      gen.InvitationRole(inv.Role),
			ExpiresAt: inv.ExpiresAt,
		})
	}
	c.JSON(http.StatusOK, gen.InvitationListResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    out,
	})
}

// RevokeInvitation closes a pending invitation. Repeated calls are idempotent
// and do not append a second domain audit entry; an accepted invitation is a
// conflict because the membership already exists.
func (a *AdminAPI) RevokeInvitation(c *gin.Context, orgId int64, invitationId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || invitationId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid invitation id")
		return
	}
	if !a.loadOrgForManagement(c, uint(orgId)) {
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermMemberManage) {
		return
	}

	audited := false
	err := a.deps.DB.Transaction(func(tx *gorm.DB) error {
		// The request guard runs before the transaction; another owner can
		// revoke this membership in between. Re-read and lock the actor row so
		// a stale permission cannot revoke an invitation.
		if _, err := lockActor(tx, uint(orgId), uid, false, authz.PermMemberManage); err != nil {
			return err
		}
		query := store.ScopedByOrg(tx, uint(orgId))
		if tx.Name() != "sqlite" {
			query = query.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		var inv model.Invitation
		if err := query.First(&inv, uint(invitationId)).Error; err != nil {
			return err
		}
		if inv.AcceptedAt != nil {
			return errInvitationAccepted
		}
		if inv.RevokedAt != nil {
			return nil
		}
		now := a.deps.Now()
		res := store.ScopedByOrg(tx, uint(orgId)).Model(&model.Invitation{}).
			Where("id = ? AND revoked_at IS NULL", inv.ID).
			Update("revoked_at", now)
		if res.Error != nil {
			return fmt.Errorf("revoke invitation: %w", res.Error)
		}
		if res.RowsAffected != 1 {
			// A concurrent revoke won the row; the invitation is already closed.
			return nil
		}
		tr, ok := a.deps.Auditor.(audit.TxRecorder)
		if !ok {
			return errAuditUnavailable
		}
		if err := tr.RecordTx(tx, audit.Entry{
			OrganizationID: uint(orgId),
			ActorUserID:    uid,
			Action:         "organization.invitation.revoke",
			TargetType:     "invitation",
			TargetID:       fmt.Sprint(inv.ID),
			Detail:         map[string]any{"email": inv.Email, "role": inv.Role},
		}); err != nil {
			return err
		}
		audited = true
		return nil
	})
	switch {
	case errors.Is(err, errActorNoLongerAuthorized):
		abortError(c, http.StatusForbidden, gen.ErrorCodeForbidden, "insufficient permissions")
		return
	case errors.Is(err, errInvitationAccepted):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "invitation already accepted")
		return
	case errors.Is(err, gorm.ErrRecordNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "invitation not found")
		return
	case errors.Is(err, errAuditUnavailable):
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "audit unavailable")
		return
	case err != nil:
		a.deps.Logger.Error("revoke invitation failed", zap.Error(err))
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not revoke invitation")
		return
	}
	if audited {
		c.Set(contextAuditRecorded, true)
	}
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
}

// loadOrgForManagement resolves the tenant root before authorization, so a
// missing organization is 404 rather than the membership lookup's 403.
func (a *AdminAPI) loadOrgForManagement(c *gin.Context, orgID uint) bool {
	var org model.Organization
	if err := a.deps.DB.Select("id").First(&org, orgID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "organization not found")
			return false
		}
		a.deps.Logger.Error("load organization failed", zap.Error(err))
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not load organization")
		return false
	}
	return true
}

// errInvitationAccepted marks a revoke attempt against an invitation whose
// membership already exists.
var errInvitationAccepted = errors.New("invitation already accepted")

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
		// The invitation was read before the transaction so the organization is
		// known. Re-read it under a row lock: a concurrent revoke must either
		// commit first (this accept then fails) or wait for this transaction.
		lockedQuery := store.ScopedByOrg(tx, inv.OrganizationID)
		if tx.Name() != "sqlite" {
			lockedQuery = lockedQuery.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		var locked model.Invitation
		if err := lockedQuery.First(&locked, inv.ID).Error; err != nil {
			return err
		}
		if err := locked.Acceptable(a.deps.Now()); err != nil {
			return err
		}
		inv = locked
		// Match on the normalized mailbox: an invite addressed to a case
		// variant of an existing account must join THAT account, never create
		// a shadow one. More than one match is a legacy data conflict — refuse
		// the acceptance instead of picking a row.
		var users []model.User
		err := tx.Where("LOWER(email) = ?", model.NormalizeEmail(inv.Email)).Find(&users).Error
		if err != nil {
			return err
		}
		var user model.User
		switch {
		case len(users) == 1:
			// The mailbox already has an account: the invitation must not be
			// accepted without proving ownership of the account (CWE-287).
			user = users[0]
			ok, verr := auth.VerifyPassword(user.PasswordHash, req.Password)
			if verr != nil || !ok {
				return errInvitationCredentials
			}
		case len(users) > 1:
			// Legacy case-variant rows: refusing beats picking one of them.
			return errInvitationCredentials
		default:
			hash, herr := auth.HashPassword(req.Password)
			if herr != nil {
				return herr
			}
			// A fresh account starts unverified; the verification mail goes
			// out after the transaction commits. The hook normalizes the
			// mailbox, so the stored value is canonical even when the invite
			// spelled it differently.
			user = model.User{Email: model.NormalizeEmail(inv.Email), PasswordHash: hash, EmailVerified: false}
			if cerr := tx.Create(&user).Error; cerr != nil {
				return cerr
			}
			needVerify = true
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
		res := store.ScopedByOrg(tx, inv.OrganizationID).
			Model(&model.Invitation{}).
			Where("id = ? AND accepted_at IS NULL AND revoked_at IS NULL", inv.ID).
			Updates(map[string]any{"accepted_at": now, "accepted_by": user.ID})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return model.ErrInvitationUsed
		}
		return nil
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
	if errors.Is(err, gorm.ErrRecordNotFound) ||
		errors.Is(err, model.ErrInvitationUsed) ||
		errors.Is(err, model.ErrInvitationExpired) ||
		errors.Is(err, model.ErrInvitationRevoked) {
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "invitation is expired or already used")
		return
	}
	if err != nil {
		a.deps.Logger.Error("accept invitation failed", zap.Error(err))
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not accept invitation")
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

	// The membership row carries only the role id; the display name comes from
	// the role row, and stays empty if that row cannot be resolved (fail closed
	// rather than guessing a name).
	joinedName := ""
	if role, rerr := a.deps.Roles.RoleByID(inv.OrganizationID, member.RoleID); rerr == nil {
		joinedName = role.Name
	}
	c.JSON(http.StatusOK, gen.MemberResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.Member{
			Id:            int64(member.ID),
			UserId:        int64(member.UserID),
			Email:         openapi_types.Email(inv.Email),
			Role:          joinedName,
			RoleId:        int64(member.RoleID),
			RoleName:      joinedName,
			ControlRoleId: controlRoleIDOf(member),
			StrategyId:    strategyIDToAPI(member.StrategyID),
			Disabled:      false,
			CreatedAt:     member.CreatedAt,
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
