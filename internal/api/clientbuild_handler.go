package api

import (
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/clientbuild"
)

func (a *AdminAPI) clientBuildService(c *gin.Context) (*clientbuild.Service, bool) {
	if a.clientBuilds == nil {
		c.Set(contextAuditRecorded, true)
		abortError(c, http.StatusServiceUnavailable, gen.ErrorCodeInternal, "client build is not configured")
		return nil, false
	}
	return a.clientBuilds, true
}

func (a *AdminAPI) writeClientBuildError(c *gin.Context, err error, logMsg string) {
	switch {
	case errors.Is(err, clientbuild.ErrNotFound):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "client build resource not found")
	case errors.Is(err, clientbuild.ErrArtifactUnavailable):
		abortError(c, http.StatusNotFound, gen.ErrorCodeNotFound, "artifact is unavailable")
	case errors.Is(err, clientbuild.ErrInvalidInput):
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, err.Error())
	case errors.Is(err, clientbuild.ErrDuplicateName):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "profile name is already in use")
	case errors.Is(err, clientbuild.ErrConflict):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, err.Error())
	case errors.Is(err, clientbuild.ErrProfileInUse):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, "profile has active builds")
	case errors.Is(err, clientbuild.ErrQuotaExceeded):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, err.Error())
	case errors.Is(err, clientbuild.ErrServerNotReady):
		abortError(c, http.StatusConflict, gen.ErrorCodeConflict, err.Error())
	case errors.Is(err, clientbuild.ErrDisabled):
		abortError(c, http.StatusServiceUnavailable, gen.ErrorCodeInternal, "client build is not enabled")
	case errors.Is(err, clientbuild.ErrTokenInvalid):
		abortError(c, http.StatusUnauthorized, gen.ErrorCodeUnauthorized, "invalid or expired bundle token")
	case errors.Is(err, clientbuild.ErrUnaudited):
		a.deps.Logger.Error(logMsg + ": transactional auditor unavailable")
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "audit unavailable")
	default:
		a.deps.Logger.Error(logMsg)
		abortError(c, http.StatusInternalServerError, gen.ErrorCodeInternal, "client build operation failed")
	}
}

func (a *AdminAPI) GetClientBuildCapabilities(c *gin.Context, orgId int64) {
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
	c.Set(contextAuditRecorded, true)
	svc, ok := a.clientBuildService(c)
	if !ok {
		return
	}
	caps, err := svc.Capabilities(c.Request.Context(), uint(orgId))
	if err != nil {
		a.writeClientBuildError(c, err, "client build capabilities failed")
		return
	}
	c.JSON(http.StatusOK, gen.ClientBuildCapabilitiesResponse{
		Code: gen.ErrorCodeOk, Message: "ok", Data: clientBuildCapabilitiesToAPI(caps),
	})
}

func (a *AdminAPI) ListClientBuildProfiles(c *gin.Context, orgId int64, params gen.ListClientBuildProfilesParams) {
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
	c.Set(contextAuditRecorded, true)
	svc, ok := a.clientBuildService(c)
	if !ok {
		return
	}
	page, size := 0, 0
	if params.Page != nil {
		page = *params.Page
	}
	if params.PageSize != nil {
		size = *params.PageSize
	}
	out, err := svc.ListProfiles(c.Request.Context(), uint(orgId), page, size)
	if err != nil {
		a.writeClientBuildError(c, err, "list client build profiles failed")
		return
	}
	c.JSON(http.StatusOK, gen.ClientBuildProfileListResponse{
		Code: gen.ErrorCodeOk, Message: "ok", Data: clientBuildProfilePageToAPI(out),
	})
}

func (a *AdminAPI) CreateClientBuildProfile(c *gin.Context, orgId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermClientBuildManage) {
		return
	}
	svc, ok := a.clientBuildService(c)
	if !ok {
		return
	}
	var req gen.ClientBuildProfileCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid profile payload")
		return
	}
	row, err := svc.CreateProfile(c.Request.Context(), uint(orgId), uid,
		clientbuild.ProfileInput{Name: req.Name, AppName: req.AppName})
	if err != nil {
		a.writeClientBuildError(c, err, "create client build profile failed")
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusCreated, gen.ClientBuildProfileResponse{
		Code: gen.ErrorCodeOk, Message: "ok", Data: clientBuildProfileToAPI(row),
	})
}

func (a *AdminAPI) GetClientBuildProfile(c *gin.Context, orgId, profileId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || profileId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization or profile id")
		return
	}
	if _, ok := a.membershipFor(c, uid, uint(orgId)); !ok {
		return
	}
	c.Set(contextAuditRecorded, true)
	svc, ok := a.clientBuildService(c)
	if !ok {
		return
	}
	row, err := svc.GetProfile(c.Request.Context(), uint(orgId), uint(profileId))
	if err != nil {
		a.writeClientBuildError(c, err, "get client build profile failed")
		return
	}
	c.JSON(http.StatusOK, gen.ClientBuildProfileResponse{
		Code: gen.ErrorCodeOk, Message: "ok", Data: clientBuildProfileToAPI(row),
	})
}

func (a *AdminAPI) UpdateClientBuildProfile(c *gin.Context, orgId, profileId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || profileId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization or profile id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermClientBuildManage) {
		return
	}
	svc, ok := a.clientBuildService(c)
	if !ok {
		return
	}
	var req gen.ClientBuildProfileUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid profile payload")
		return
	}
	row, err := svc.UpdateProfile(c.Request.Context(), uint(orgId), uid, uint(profileId),
		clientbuild.ProfileUpdate{Name: req.Name, AppName: req.AppName})
	if err != nil {
		a.writeClientBuildError(c, err, "update client build profile failed")
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.ClientBuildProfileResponse{
		Code: gen.ErrorCodeOk, Message: "ok", Data: clientBuildProfileToAPI(row),
	})
}

func (a *AdminAPI) DeleteClientBuildProfile(c *gin.Context, orgId, profileId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || profileId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization or profile id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermClientBuildManage) {
		return
	}
	svc, ok := a.clientBuildService(c)
	if !ok {
		return
	}
	if err := svc.DeleteProfile(c.Request.Context(), uint(orgId), uid, uint(profileId)); err != nil {
		a.writeClientBuildError(c, err, "delete client build profile failed")
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
}

func (a *AdminAPI) PutClientBuildProfileLogo(c *gin.Context, orgId, profileId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || profileId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization or profile id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermClientBuildManage) {
		return
	}
	svc, ok := a.clientBuildService(c)
	if !ok {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 2<<20)
	var req gen.ClientBuildLogoUploadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid logo payload")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(req.PngBase64)
	if err != nil || len(raw) == 0 || len(raw) > 1<<20 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "logo must be a base64 PNG up to 1 MiB")
		return
	}
	row, err := svc.SetProfileLogo(c.Request.Context(), uint(orgId), uid, uint(profileId), raw)
	if err != nil {
		a.writeClientBuildError(c, err, "set client build logo failed")
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.ClientBuildProfileResponse{
		Code: gen.ErrorCodeOk, Message: "ok", Data: clientBuildProfileToAPI(row),
	})
}

func (a *AdminAPI) GetClientBuildProfileLogo(c *gin.Context, orgId, profileId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || profileId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization or profile id")
		return
	}
	if _, ok := a.membershipFor(c, uid, uint(orgId)); !ok {
		return
	}
	c.Set(contextAuditRecorded, true)
	svc, ok := a.clientBuildService(c)
	if !ok {
		return
	}
	logo, err := svc.OpenProfileLogo(c.Request.Context(), uint(orgId), uint(profileId))
	if err != nil {
		a.writeClientBuildError(c, err, "get client build logo failed")
		return
	}
	defer logo.File.Close()
	etag := `"` + logo.SHA256 + `"`
	if c.GetHeader("If-None-Match") == etag {
		c.Status(http.StatusNotModified)
		return
	}
	c.Header("ETag", etag)
	c.Header("Cache-Control", "private, max-age=60")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Content-Type", "image/png")
	http.ServeContent(c.Writer, c.Request, "", time.Time{}, logo.File)
}

func (a *AdminAPI) DeleteClientBuildProfileLogo(c *gin.Context, orgId, profileId int64) {
	uid, ok := requireUserID(c)
	if !ok {
		return
	}
	if orgId <= 0 || profileId <= 0 {
		abortError(c, http.StatusBadRequest, gen.ErrorCodeInvalidRequest, "invalid organization or profile id")
		return
	}
	if !a.requirePerm(c, uid, uint(orgId), authz.PermClientBuildManage) {
		return
	}
	svc, ok := a.clientBuildService(c)
	if !ok {
		return
	}
	if err := svc.DeleteProfileLogo(c.Request.Context(), uint(orgId), uid, uint(profileId)); err != nil {
		a.writeClientBuildError(c, err, "delete client build logo failed")
		return
	}
	c.Set(contextAuditRecorded, true)
	c.JSON(http.StatusOK, gen.OkResponse{Code: gen.ErrorCodeOk, Message: "ok"})
}
