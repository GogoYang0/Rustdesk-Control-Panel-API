package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/strategy"
)

// strategyResponse maps a stored strategy onto the wire shape.
//
// An unreadable config blob is an error, not an empty map: silently returning
// "no options" would turn a corrupted row into a policy that looks harmless
// while delivering nothing, which is exactly the state an operator must see.
func strategyResponse(row *model.Strategy) (gen.Strategy, error) {
	options := map[string]string{}
	if row.ConfigOptionsJSON != "" {
		if err := json.Unmarshal([]byte(row.ConfigOptionsJSON), &options); err != nil {
			return gen.Strategy{}, err
		}
	}
	// Cleared keys are part of the operator-facing contract: without reading
	// them back, the console cannot explain why a removed option keeps being
	// delivered as an empty value.
	cleared := []string{}
	if row.ClearedKeysJSON != "" {
		if err := json.Unmarshal([]byte(row.ClearedKeysJSON), &cleared); err != nil {
			return gen.Strategy{}, err
		}
	}
	return gen.Strategy{
		Id:            int64(row.ID),
		Name:          row.Name,
		ConfigOptions: options,
		ClearedKeys:   &cleared,
		Version:       row.Version,
		Enabled:       row.Enabled,
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
	}, nil
}

// writeStrategyError maps strategy sentinels onto HTTP responses.
func (a *AdminAPI) writeStrategyError(c *gin.Context, err error, logMsg string) {
	switch {
	case errors.Is(err, strategy.ErrNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "strategy not found")
	case errors.Is(err, strategy.ErrDuplicateName):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "strategy name is already in use")
	case errors.Is(err, strategy.ErrInvalidName),
		errors.Is(err, strategy.ErrUnknownOption),
		errors.Is(err, strategy.ErrInvalidOptionValue):
		// The error text names the offending key: an operator who typed
		// "API-SERVER" needs to see why it was refused, not a generic 400.
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
	case errors.Is(err, strategy.ErrUnaudited):
		a.deps.Logger.Error(logMsg + ": transactional auditor unavailable")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "audit unavailable")
	default:
		a.deps.Logger.Error(logMsg)
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not apply strategy change")
	}
}

// bindStrategyJSON decodes a strategy payload rejecting unknown fields.
//
// The client protocol has an `extra` map and the contract deliberately does not
// expose it; a plain ShouldBindJSON would drop it silently and answer 201, which
// is exactly the "looks like it worked" failure the CLI whitelist refuses. A
// typo in a field name must fail the request instead.
func bindStrategyJSON(c *gin.Context, out any) error {
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

// GetStrategy returns one strategy.
func (a *AdminAPI) GetStrategy(c *gin.Context, orgId, strategyId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || strategyId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization or strategy id")
		return
	}
	if _, ok := a.membershipFor(c, uid, uint(orgId)); !ok {
		return
	}
	row, err := a.deps.Strategies.Get(c.Request.Context(), uint(orgId), uint(strategyId))
	if err != nil {
		a.writeStrategyError(c, err, "get strategy failed")
		return
	}
	out, rerr := strategyResponse(row)
	if rerr != nil {
		a.deps.Logger.Error("stored strategy is unreadable: " + rerr.Error())
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "stored strategy is unreadable")
		return
	}
	c.JSON(http.StatusOK, gen.StrategyResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: out})
}

// ListStrategies returns the organization's strategies. Any member may read
// them: the console needs the list to render assignments.
func (a *AdminAPI) ListStrategies(c *gin.Context, orgId int64) {
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
	rows, err := a.deps.Strategies.List(c.Request.Context(), uint(orgId))
	if err != nil {
		a.deps.Logger.Error("list strategies failed")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "could not list strategies")
		return
	}
	out := make([]gen.Strategy, 0, len(rows))
	for i := range rows {
		item, rerr := strategyResponse(&rows[i])
		if rerr != nil {
			a.deps.Logger.Error("stored strategy is unreadable: " + rerr.Error())
			abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "a stored strategy is unreadable")
			return
		}
		out = append(out, item)
	}
	c.JSON(http.StatusOK, gen.StrategyListResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: out})
}

// CreateStrategy adds a strategy.
func (a *AdminAPI) CreateStrategy(c *gin.Context, orgId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermStrategyManage) {
		return
	}
	var req gen.StrategyCreateRequest
	if err := bindStrategyJSON(c, &req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid strategy payload: "+err.Error())
		return
	}
	options := map[string]string{}
	if req.ConfigOptions != nil {
		options = *req.ConfigOptions
	}
	row, err := a.deps.Strategies.Create(c.Request.Context(), uint(orgId), uid, req.Name, options)
	if err != nil {
		a.writeStrategyError(c, err, "create strategy failed")
		return
	}
	// The service wrote its audit entry on the entity transaction; mark the
	// request so the middleware does not add a second HTTP-fallback row.
	c.Set(contextAuditRecorded, true)
	out, rerr := strategyResponse(row)
	if rerr != nil {
		a.deps.Logger.Error("created strategy is unreadable: " + rerr.Error())
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "stored strategy is unreadable")
		return
	}
	c.JSON(http.StatusCreated, gen.StrategyResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: out})
}

// UpdateStrategy patches a strategy.
func (a *AdminAPI) UpdateStrategy(c *gin.Context, orgId, strategyId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || strategyId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization or strategy id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermStrategyManage) {
		return
	}
	var req gen.StrategyUpdateRequest
	if err := bindStrategyJSON(c, &req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid strategy payload: "+err.Error())
		return
	}
	if req.Name == nil && req.ConfigOptions == nil && req.Enabled == nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "at least one field is required")
		return
	}
	row, err := a.deps.Strategies.Update(c.Request.Context(), uint(orgId), uid, uint(strategyId), strategy.UpdateInput{
		Name:    req.Name,
		Options: req.ConfigOptions,
		Enabled: req.Enabled,
	})
	if err != nil {
		a.writeStrategyError(c, err, "update strategy failed")
		return
	}
	// The service wrote its audit entry on the entity transaction; mark the
	// request so the middleware does not add a second HTTP-fallback row.
	c.Set(contextAuditRecorded, true)
	out, rerr := strategyResponse(row)
	if rerr != nil {
		a.deps.Logger.Error("updated strategy is unreadable: " + rerr.Error())
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "stored strategy is unreadable")
		return
	}
	c.JSON(http.StatusOK, gen.StrategyResponse{Code: gen.ErrorCodeOk, Message: "ok", Data: out})
}

// DeleteStrategy removes a strategy and clears its assignments.
func (a *AdminAPI) DeleteStrategy(c *gin.Context, orgId, strategyId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || strategyId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization or strategy id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermStrategyManage) {
		return
	}
	if err := a.deps.Strategies.Delete(c.Request.Context(), uint(orgId), uid, uint(strategyId)); err != nil {
		a.writeStrategyError(c, err, "delete strategy failed")
		return
	}
	// The service wrote its audit entry on the entity transaction; mark the
	// request so the middleware does not add a second HTTP-fallback row.
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "deleted"})
}
