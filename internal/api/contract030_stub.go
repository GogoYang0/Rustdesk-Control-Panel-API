package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
)

// Contract 0.3.0 placeholder handlers. Each is implemented by a later M2
// task (address book: task 4; email verification: task 6; log events:
// task 10); until then they answer 501 so the generated interface stays
// satisfied and CI remains green between tasks.
func notImplemented(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gen.ErrorResponse{
		Code:    gen.ErrorCodeInternal,
		Message: "not implemented yet",
	})
}

func (a *AdminAPI) ListAddressBooks(c *gin.Context, orgId int64) { notImplemented(c) }

func (a *AdminAPI) CreateAddressBook(c *gin.Context, orgId int64) { notImplemented(c) }

func (a *AdminAPI) GetAddressBook(c *gin.Context, orgId int64, bookId int64) { notImplemented(c) }

func (a *AdminAPI) UpdateAddressBook(c *gin.Context, orgId int64, bookId int64) { notImplemented(c) }

func (a *AdminAPI) DeleteAddressBook(c *gin.Context, orgId int64, bookId int64) { notImplemented(c) }

func (a *AdminAPI) ReplaceAddressBookPeers(c *gin.Context, orgId int64, bookId int64) {
	notImplemented(c)
}

func (a *AdminAPI) ReplaceAddressBookTags(c *gin.Context, orgId int64, bookId int64) {
	notImplemented(c)
}

func (a *AdminAPI) ListLogEvents(c *gin.Context, orgId int64, params gen.ListLogEventsParams) {
	notImplemented(c)
}

func (a *AdminAPI) VerifyEmail(c *gin.Context) { notImplemented(c) }

func (a *AdminAPI) ResendVerification(c *gin.Context) { notImplemented(c) }
