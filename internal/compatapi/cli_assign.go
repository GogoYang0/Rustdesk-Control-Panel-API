package compatapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// ContextAuditRecorded mirrors api.contextAuditRecorded (same key): a compat
// handler that committed its domain audit rows inside the entity transaction
// sets it so the management audit middleware skips its request-level fallback.
// The two packages cannot share the constant (api imports compatapi), exactly
// like the Context* keys above.
const ContextAuditRecorded = "audit.domainRecorded"

// cliAssignFields is the whitelist of the client's `--assign` payload, checked
// against the upstream client: id, uuid, user_name, device_group_name,
// device_name, note, strategy_name (wave 4 reversed D5 for strategies).
// Anything else (address_book_*, device_username) is refused by name instead of
// silently dropped: a field this deployment does not implement must not look
// like a successful assignment.
var cliAssignFields = map[string]bool{
	"id":                true,
	"uuid":              true,
	"user_name":         true,
	"device_group_name": true,
	"device_name":       true,
	"note":              true,
	"strategy_name":     true,
}

// cliAssign implements POST /api/devices/cli, the endpoint the RustDesk client
// calls for `--assign` (already confirmed against upstream src/core_main.rs).
// Authentication is a personal token with device.write, re-intersected with the
// owner's live role; the write itself goes through the same audited device
// service the management API uses, so one request produces one audit row per
// changed field and no second, CLI-only write path exists. The client binding
// (bound_uuid / binding_generation) is never touched here: it belongs to the
// login path.
func (s *Server) cliAssign(c *gin.Context) {
	plaintext, ok := bearerToken(c)
	if !ok {
		abortUnauthorized(c, "missing bearer token")
		return
	}
	token, err := s.deps.Tokens.Authenticate(c.Request.Context(), plaintext)
	if err != nil {
		abortUnauthorized(c, "invalid or expired token")
		return
	}
	// Attribute the request for the audit middleware even before the body is
	// judged: a rejected assignment is still an action an operator asks about.
	c.Set(ContextUserID, token.UserID)
	c.Set(ContextOrgID, token.OrganizationID)
	if !s.tokenHasDeviceWrite(token) {
		compatError(c, http.StatusForbidden, "insufficient permissions")
		return
	}

	var body map[string]json.RawMessage
	if err := c.ShouldBindJSON(&body); err != nil {
		compatError(c, http.StatusBadRequest, "invalid request body")
		return
	}
	for field := range body {
		if !cliAssignFields[field] {
			compatError(c, http.StatusBadRequest, "unsupported field: "+field)
			return
		}
	}

	rustdeskID, present := body["id"]
	if !present {
		compatError(c, http.StatusBadRequest, "id is required")
		return
	}
	id, ok := cliStringValue(rustdeskID)
	if !ok || id == "" || len(id) > maxDeviceIDLen {
		compatError(c, http.StatusBadRequest, "id must be a non-empty string")
		return
	}
	if raw, present := body["uuid"]; present {
		// The uuid is part of the client payload but is deliberately not
		// persisted: the device binding belongs to the login path, and letting a
		// CLI call write it would either hand the device to an arbitrary uuid or
		// lock the legitimate client out with errDeviceBound.
		uuid, ok := cliStringValue(raw)
		if !ok || len(uuid) > maxDeviceUUIDLen {
			compatError(c, http.StatusBadRequest, "uuid must be a string")
			return
		}
	}

	var dev model.Device
	err = store.ScopedByOrg(s.deps.DB, token.OrganizationID).
		Where("rustdesk_id = ?", id).First(&dev).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		compatError(c, http.StatusNotFound, "device not found")
		return
	}
	if err != nil {
		compatError(c, http.StatusInternalServerError, "assign failed")
		return
	}

	in := device.UpdateInput{}
	if raw, present := body["user_name"]; present {
		email, ok := cliStringValue(raw)
		if !ok || email == "" {
			compatError(c, http.StatusBadRequest, "user_name must be a string")
			return
		}
		var user model.User
		err := store.WithoutTenantScope(s.deps.DB).Where("email = ?", email).First(&user).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Same answer as a registered outsider below: the users table is
			// platform-global, so a distinct message here would turn this
			// endpoint into an account oracle for every deployment tenant
			// (CWE-204).
			compatError(c, http.StatusNotFound, "target not found")
			return
		}
		if err != nil {
			compatError(c, http.StatusInternalServerError, "assign failed")
			return
		}
		ownerID := user.ID
		in.OwnerUserID = &ownerID
	}
	if raw, present := body["device_group_name"]; present {
		name, ok := cliStringValue(raw)
		if !ok || name == "" {
			compatError(c, http.StatusBadRequest, "device_group_name must be a string")
			return
		}
		groupID, found, err := s.deviceGroupByName(token.OrganizationID, name)
		if err != nil {
			compatError(c, http.StatusInternalServerError, "assign failed")
			return
		}
		if !found {
			compatError(c, http.StatusNotFound, "device group not found")
			return
		}
		in.DeviceGroupID = &groupID
	}
	if raw, present := body["device_name"]; present {
		name, ok := cliStringValue(raw)
		if !ok {
			compatError(c, http.StatusBadRequest, "device_name must be a string")
			return
		}
		in.Name = &name
	}
	if raw, present := body["note"]; present {
		note, ok := cliStringValue(raw)
		if !ok {
			compatError(c, http.StatusBadRequest, "note must be a string")
			return
		}
		in.Note = &note
	}

	// strategy_name is resolved before the device update so a typo fails the
	// whole request instead of leaving a half-applied assignment behind.
	var strategyID *uint
	if raw, present := body["strategy_name"]; present {
		name, ok := cliStringValue(raw)
		if !ok || name == "" {
			compatError(c, http.StatusBadRequest, "strategy_name must be a non-empty string")
			return
		}
		// Assigning a strategy needs the same permission the management
		// endpoints demand. device.write is delegable and strategy.manage is
		// not, so checking only the former would let a custom role reach the
		// capability the catalog withholds from it.
		if !s.tokenHasPerm(token, authz.PermStrategyManage) {
			compatError(c, http.StatusForbidden, "insufficient permissions")
			return
		}
		id, found, serr := s.strategyByName(c.Request.Context(), token.OrganizationID, name)
		if serr != nil {
			compatError(c, http.StatusInternalServerError, "assign failed")
			return
		}
		if !found {
			compatError(c, http.StatusNotFound, "strategy not found")
			return
		}
		strategyID = &id
	}

	_, err = s.deps.Devices.Update(c.Request.Context(), token.OrganizationID, dev.ID, token.UserID, in)
	switch {
	case errors.Is(err, device.ErrDeviceNotFound),
		errors.Is(err, device.ErrOwnerNotMember),
		errors.Is(err, device.ErrDeviceGroupNotFound):
		// The three "target does not exist here" answers stay indistinguishable:
		// the response must not confirm whether an id or name exists in another
		// tenant, or whether it exists at all.
		compatError(c, http.StatusNotFound, "target not found")
		return
	case errors.Is(err, device.ErrInvalidInput):
		compatError(c, http.StatusBadRequest, err.Error())
		return
	case err != nil:
		compatError(c, http.StatusInternalServerError, "assign failed")
		return
	}

	if strategyID != nil {
		// A second transaction with its own `strategy.assign` entry: the
		// strategy service refuses unaudited writes, and the trail must show
		// the assignment separately from the device update.
		if err := s.deps.Strategies.AssignDevice(c.Request.Context(), token.OrganizationID, token.UserID, dev.ID, strategyID); err != nil {
			s.deps.Logger.Error("cli strategy assignment failed: " + err.Error())
			compatError(c, http.StatusInternalServerError, "assign failed")
			return
		}
	}

	// The domain rows committed with the changes; the request-level fallback
	// would only duplicate them.
	c.Set(ContextAuditRecorded, true)
	c.JSON(http.StatusOK, gin.H{"code": "ok"})
}

// tokenPermissions returns the token's effective permission set: the
// intersection of the owner's live role and the token's own codes. A token can
// never exceed its owner's role, and a role that lost a permission takes it
// away from every token it issued.
func (s *Server) tokenPermissions(token *model.APIToken) []string {
	var membership model.Membership
	err := store.WithoutTenantScope(s.deps.DB).
		Where("organization_id = ? AND user_id = ?", token.OrganizationID, token.UserID).
		First(&membership).Error
	if err != nil || membership.Disabled {
		return nil
	}
	role, err := s.deps.Roles.Resolve(token.OrganizationID, membership)
	if err != nil {
		return nil
	}
	return auth.IntersectPermissions(role.PermissionList(), token.PermissionList())
}

// tokenHasPerm reports whether the token still carries the permission.
func (s *Server) tokenHasPerm(token *model.APIToken, perm string) bool {
	return authz.Has(s.tokenPermissions(token), perm)
}

// tokenHasDeviceWrite reports whether the token's holder still holds
// device.write, the gate for `--assign`.
func (s *Server) tokenHasDeviceWrite(token *model.APIToken) bool {
	return s.tokenHasPerm(token, authz.PermDeviceWrite)
}

// strategyByName resolves a strategy by name, folding case in Go so the answer
// matches the case-insensitive uniqueness rule the management API enforces.
func (s *Server) strategyByName(ctx context.Context, orgID uint, name string) (uint, bool, error) {
	rows, err := s.deps.Strategies.List(ctx, orgID)
	if err != nil {
		return 0, false, err
	}
	for _, row := range rows {
		if strings.EqualFold(row.Name, name) {
			return row.ID, true, nil
		}
	}
	return 0, false, nil
}

// deviceGroupByName resolves a device group by name, folding case in Go so all
// three dialects agree with the uniqueness rule group creation uses.
func (s *Server) deviceGroupByName(orgID uint, name string) (uint, bool, error) {
	var groups []model.DeviceGroup
	if err := store.ScopedByOrg(s.deps.DB, orgID).
		Select("id", "name").Find(&groups).Error; err != nil {
		return 0, false, err
	}
	for _, group := range groups {
		if strings.EqualFold(group.Name, name) {
			return group.ID, true, nil
		}
	}
	return 0, false, nil
}

// bearerToken extracts the bearer credential, mirroring the strict form the
// management middleware accepts.
func bearerToken(c *gin.Context) (string, bool) {
	header := c.GetHeader("Authorization")
	const prefix = "bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(prefix):])
	return token, token != ""
}

// cliStringValue decodes one raw JSON value as a string.
func cliStringValue(raw json.RawMessage) (string, bool) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	return value, true
}
