package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
)

// Contract 0.3.0 placeholder handler. Implemented by M2 task 10; until then
// it answers 501 so the generated interface stays satisfied and CI remains
// green between tasks.
func notImplemented(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gen.ErrorResponse{
		Code:    gen.ErrorCodeInternal,
		Message: "not implemented yet",
	})
}

func (a *AdminAPI) ListLogEvents(c *gin.Context, orgId int64, params gen.ListLogEventsParams) {
	notImplemented(c)
}
