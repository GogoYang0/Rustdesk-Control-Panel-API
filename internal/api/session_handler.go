package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/session"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/strategy"
)

// ListSessions returns one page of the organization's session records.
//
// Reading is member-level. The response carries the unpaginated total because
// these tables grow without bound and a client cannot drive a pager from a page
// alone.
func (a *AdminAPI) ListSessions(c *gin.Context, orgId int64, params gen.ListSessionsParams) {
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

	filter := session.SessionFilter{}
	// The generated binding converts the query strings without checking the
	// enums: an unknown origin/status would silently filter to an empty page,
	// which a client would read as "nothing in this state" instead of a bad
	// parameter (same ruling as the approval status filter, task 6 review).
	if params.Origin != nil && !params.Origin.Valid() {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid origin")
		return
	}
	if params.Status != nil && !params.Status.Valid() {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid status")
		return
	}
	if params.Origin != nil {
		origin := string(*params.Origin)
		filter.Origin = &origin
	}
	if params.Status != nil {
		status := string(*params.Status)
		filter.Status = &status
	}
	if params.DeviceId != nil {
		// int64 → uint without a sign check turns -1 into 2^64-1, which reaches
		// the database as a device id nobody has and comes back as a 500 from
		// the driver rather than a 400 from us.
		if *params.DeviceId <= 0 {
			abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "deviceId must be positive")
			return
		}
		device := uint(*params.DeviceId)
		filter.DeviceID = &device
	}
	filter.Since, filter.Until = params.Since, params.Until
	if params.Page != nil {
		filter.Page = *params.Page
	}
	if params.PageSize != nil {
		filter.PageSize = *params.PageSize
	}

	items, total, err := a.tickets.ListSessions(c.Request.Context(), uint(orgId), filter)
	if err != nil {
		a.writeSessionError(c, err)
		return
	}

	page, pageSize := filter.NormalisedPagination()
	// Polled read: skip the request-level audit fallback (#19), otherwise a
	// dashboard refreshing every few seconds writes a row per poll.
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.SessionListResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.SessionPage{
			Items:    sessionsToAPI(items),
			Page:     page,
			PageSize: int64(pageSize),
			Total:    total,
		},
	})
}

// GetSession returns one session with its timeline.
func (a *AdminAPI) GetSession(c *gin.Context, orgId int64, sessionId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || sessionId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return
	}
	if _, ok := a.membershipFor(c, uid, uint(orgId)); !ok {
		return
	}

	sess, events, truncated, err := a.tickets.SessionDetail(c.Request.Context(), uint(orgId), uint(sessionId))
	if err != nil {
		a.writeSessionError(c, err)
		return
	}

	// Unlike the list, the detail view is not polled, so it keeps its
	// request-level audit row: knowing who inspected which session is exactly
	// what an investigator wants later. This matches GetTicket (T4).
	c.JSON(http.StatusOK, gen.SessionDetailResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data: gen.SessionDetail{
			Session:   sessionToAPI(*sess),
			Events:    a.sessionEventsToAPI(events),
			Truncated: truncated,
		},
	})
}

// EndSession closes an open session record and queues a best-effort device
// disconnect. The panel is not in the signalling path, so the transport ends
// when the client consumes the request on its next heartbeat.
func (a *AdminAPI) EndSession(c *gin.Context, orgId int64, sessionId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || sessionId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermDeviceDisconnect) {
		return
	}
	sess, err := a.tickets.EndByAdmin(c.Request.Context(), uint(orgId), uint(sessionId), uid)
	switch {
	case errors.Is(err, session.ErrSessionNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "session not found")
		return
	case errors.Is(err, session.ErrSessionNotOpen):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "session is not open")
		return
	case err != nil:
		a.deps.Logger.Error("end session failed", zap.Error(err))
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not end session")
		return
	}
	requested := false
	_, derr := a.deps.Strategies.RequestDisconnect(c.Request.Context(), uint(orgId), uid,
		sess.DeviceID, "session ended by administrator")
	switch {
	case derr == nil, errors.Is(derr, strategy.ErrDisconnectPending):
		requested = true
	default:
		a.deps.Logger.Warn("session ended without a queued disconnect",
			zap.Uint("session_id", sess.ID), zap.Error(derr))
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.SessionEndResponse{
		Code:    gen.ErrorCodeOk,
		Message: "ok",
		Data:    gen.SessionEndResult{DisconnectRequested: requested},
	})
}

func (a *AdminAPI) writeSessionError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, session.ErrInvalidInput):
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
	case errors.Is(err, session.ErrSessionNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, err.Error())
	default:
		a.deps.Logger.Error("session query failed", zap.Error(err))
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not load sessions")
	}
}

func sessionsToAPI(sessions []model.Session) []gen.Session {
	out := make([]gen.Session, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, sessionToAPI(s))
	}
	return out
}

func (a *AdminAPI) sessionEventsToAPI(events []model.SessionEvent) []gen.SessionEvent {
	out := make([]gen.SessionEvent, 0, len(events))
	for _, e := range events {
		event := gen.SessionEvent{
			Id:   int64(e.ID),
			Kind: e.Kind,
			At:   e.At,
		}
		if e.DetailJSON != "" {
			var detail map[string]interface{}
			if err := json.Unmarshal([]byte(e.DetailJSON), &detail); err != nil {
				// The column is text and the contract allows null, so this is a
				// data bug rather than a request error — log it instead of
				// dropping the event's context without a trace.
				a.deps.Logger.Warn("session event detail is not valid JSON",
					zap.Uint64("event_id", uint64(e.ID)),
					zap.Error(err))
			} else {
				event.Detail = &detail
			}
		}
		out = append(out, event)
	}
	return out
}
