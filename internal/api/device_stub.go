package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
)

// Device endpoints land with the device registration task; until then they
// answer 501 so the server keeps a truthful contract surface.
func (a *AdminAPI) CreateDevice(c *gin.Context, _ int64) {
	abortError(c, http.StatusNotImplemented, gen.ErrorCodeInternal, "endpoint not implemented yet")
}

// DeviceHeartbeat is implemented with the device registration task.
func (a *AdminAPI) DeviceHeartbeat(c *gin.Context, _ int64, _ int64) {
	abortError(c, http.StatusNotImplemented, gen.ErrorCodeInternal, "endpoint not implemented yet")
}
