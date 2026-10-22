package api

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/session"
)

// ListAlerts returns the organization's policy-violation alerts. Reading is a
// member-level capability: the list is the operator's inbox for native
// violations the panel cannot block (D10).
func (a *AdminAPI) ListAlerts(c *gin.Context, orgId int64, params gen.ListAlertsParams) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if _, ok := a.membershipFor(c, uid, uint(orgId)); !ok {
		return
	}

	filter := session.AlertFilter{}
	if params.Severity != nil {
		// The generated binding converts the query string without checking the
		// enum: an unknown severity would silently filter to an empty page,
		// which a client would read as "all clear" instead of a bad parameter.
		if !params.Severity.Valid() {
			abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid severity")
			return
		}
		filter.Severity = (*string)(params.Severity)
	}
	if params.Kind != nil {
		if len(*params.Kind) > 64 {
			abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "kind must be at most 64 characters")
			return
		}
		filter.Kind = params.Kind
	}
	if params.Since != nil {
		filter.Since = params.Since
	}
	if params.Page != nil {
		filter.Page = *params.Page
	}
	if params.PageSize != nil {
		filter.PageSize = *params.PageSize
	}

	items, total, err := a.tickets.ListAlerts(c.Request.Context(), uint(orgId), filter)
	if err != nil {
		a.writeAlertError(c, err)
		return
	}
	page, pageSize := filter.NormalisedPagination()
	// The list is polled; the request-level audit fallback would add a row
	// per poll, which is exactly the noise #19 removed.
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.AlertListResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.AlertPage{
			Items:    alertsToAPI(items),
			Page:     page,
			PageSize: int64(pageSize),
			Total:    total,
		},
	})
}

// writeAlertError maps alert domain errors onto the contract's status codes.
func (a *AdminAPI) writeAlertError(c *gin.Context, err error) {
	// Every failure so far is a service-level invariant break, not a caller
	// error: keep it opaque but logged.
	a.deps.Logger.Sugar().Errorf("alert operation failed: %v", err)
	abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not list alerts")
}

func alertToAPI(p model.Alert) gen.Alert {
	out := gen.Alert{
		Id:             int64(p.ID),
		OrganizationId: int64(p.OrganizationID),
		Kind:           p.Kind,
		Severity:       gen.AlertSeverity(p.Severity),
		CreatedAt:      p.CreatedAt,
	}
	if p.SessionID != nil {
		id := int64(*p.SessionID)
		out.SessionId = &id
	}
	if p.DeviceID != nil {
		id := int64(*p.DeviceID)
		out.DeviceId = &id
	}
	if p.DetailJSON != "" {
		var detail map[string]interface{}
		if err := json.Unmarshal([]byte(p.DetailJSON), &detail); err == nil {
			out.Detail = &detail
		}
	}
	return out
}

func alertsToAPI(items []model.Alert) []gen.Alert {
	out := make([]gen.Alert, 0, len(items))
	for _, p := range items {
		out = append(out, alertToAPI(p))
	}
	return out
}
