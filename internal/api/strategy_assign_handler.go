package api

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
)

// strategyAssignment decodes a StrategyAssignmentRequest.
//
// The field is read from a raw map because the generated struct cannot tell
// "absent" from "explicit null", and treating {} as "clear the assignment"
// would let a typo silently drop a policy. The contract marks it required.
func strategyAssignment(c *gin.Context) (*uint, bool) {
	var body map[string]json.RawMessage
	if err := c.ShouldBindJSON(&body); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid strategy assignment")
		return nil, false
	}
	raw, present := body["strategy_id"]
	if !present {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest,
			"strategy_id is required (use null to clear)")
		return nil, false
	}
	var requested *int64
	if err := json.Unmarshal(raw, &requested); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest,
			"strategy_id must be an integer or null")
		return nil, false
	}
	if requested == nil {
		return nil, true
	}
	if *requested <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest,
			"strategy_id must be positive or null")
		return nil, false
	}
	id := uint(*requested)
	return &id, true
}

// AssignDeviceStrategy sets or clears the device-level assignment.
func (a *AdminAPI) AssignDeviceStrategy(c *gin.Context, orgId, deviceId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || deviceId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization or device id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermStrategyManage) {
		return
	}
	strategyID, ok := strategyAssignment(c)
	if !ok {
		return
	}
	if err := a.deps.Strategies.AssignDevice(c.Request.Context(), uint(orgId), uid, uint(deviceId), strategyID); err != nil {
		a.writeStrategyError(c, err, "assign device strategy failed")
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "assigned"})
}

// AssignDeviceGroupStrategy sets or clears the group-level assignment.
func (a *AdminAPI) AssignDeviceGroupStrategy(c *gin.Context, orgId, deviceGroupId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || deviceGroupId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization or device group id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermStrategyManage) {
		return
	}
	strategyID, ok := strategyAssignment(c)
	if !ok {
		return
	}
	if err := a.deps.Strategies.AssignGroup(c.Request.Context(), uint(orgId), uid, uint(deviceGroupId), strategyID); err != nil {
		a.writeStrategyError(c, err, "assign device group strategy failed")
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "assigned"})
}

// AssignMemberStrategy sets or clears the member-level default.
func (a *AdminAPI) AssignMemberStrategy(c *gin.Context, orgId, userId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || userId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization or user id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermStrategyManage) {
		return
	}
	strategyID, ok := strategyAssignment(c)
	if !ok {
		return
	}
	if err := a.deps.Strategies.AssignMember(c.Request.Context(), uint(orgId), uid, uint(userId), strategyID); err != nil {
		a.writeStrategyError(c, err, "assign member strategy failed")
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "assigned"})
}

// strategyIDToAPI renders a nullable assignment for response schemas.
func strategyIDToAPI(id *uint) *int64 {
	if id == nil {
		return nil
	}
	v := int64(*id)
	return &v
}
