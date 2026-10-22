package compatapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// heartbeatRequest carries the client identity: the device binding comes
// from the most recent active session with that uuid (裁定 C16), and the
// request id must match the device the session was bound to at login —
// the uuid is a stable hardware identifier, not a secret (CWE-639).
type heartbeatRequest struct {
	ID         string `json:"id"`
	UUID       string `json:"uuid"`
	Ver        int    `json:"ver"`
	Conns      []any  `json:"conns"`
	ModifiedAt int64  `json:"modified_at"`
}

// heartbeat refreshes the device's last-seen timestamp (issue C11: client
// heartbeats are the primary online/offline source).
func (s *Server) heartbeat(c *gin.Context) {
	var req heartbeatRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.ID == "" || req.UUID == "" {
		compatError(c, http.StatusBadRequest, "invalid heartbeat payload")
		return
	}
	session, found := s.activeSessionByUUID(req.UUID, req.ID)
	if !found || session.DeviceID == "" || session.DeviceID != req.ID {
		// Fire-and-forget endpoint: an unknown device must not produce
		// client-visible errors, the client just retries later.
		ok(c)
		return
	}
	if err := s.touchDevice(c, session, session.DeviceID); err != nil {
		compatError(c, http.StatusInternalServerError, "heartbeat failed")
		return
	}
	ok(c)
}

// sysinfo receives the client's system information dump. The panel only
// needs the liveness signal for now (structured sysinfo storage lands with
// the log-events task), so it is handled like a heartbeat.
func (s *Server) sysinfo(c *gin.Context) {
	var req map[string]any
	if err := c.ShouldBindJSON(&req); err != nil {
		compatError(c, http.StatusBadRequest, "invalid sysinfo payload")
		return
	}
	id, _ := req["id"].(string)
	uuid, _ := req["uuid"].(string)
	if id == "" || uuid == "" {
		compatError(c, http.StatusBadRequest, "invalid sysinfo payload")
		return
	}
	session, found := s.activeSessionByUUID(uuid, id)
	if !found || session.DeviceID == "" || session.DeviceID != id {
		ok(c)
		return
	}
	if err := s.touchDevice(c, session, session.DeviceID); err != nil {
		compatError(c, http.StatusInternalServerError, "sysinfo failed")
		return
	}
	ok(c)
}

// touchDevice records a heartbeat for the device bound to the session's
// organization. The row must exist and carry this session's binding: a
// deleted row is not resurrected here — the admin's delete is the binding
// reset, and the client re-claims the device through a fresh login
// (claimDevice); a row re-bound to another client instance is left alone.
func (s *Server) touchDevice(c *gin.Context, session *model.CompatSession, rustdeskID string) error {
	orgID := session.OrganizationID
	var dev model.Device
	err := store.ScopedByOrg(s.deps.DB, orgID).Where("rustdesk_id = ?", rustdeskID).First(&dev).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// The admin deleted the row to reset the binding; the old session
		// must not resurrect or re-claim it.
		return nil
	}
	if err != nil {
		// A transient query failure must not be mistaken for a missing row.
		return err
	}
	if dev.BoundUUID != session.UUID {
		// The binding moved to another client instance meanwhile.
		return nil
	}
	if dev.BindingGeneration != session.BindingGeneration {
		// The binding was re-issued (administrator re-bind) after this
		// session was logged in: the session is stale no matter which uuid
		// it carries, so its activity is dropped (#40).
		return nil
	}
	_, err = s.deps.Devices.Heartbeat(c.Request.Context(), orgID, dev.ID)
	return err
}

// peers lists the devices of the session's organization (issue C14: the
// client sees exactly its own tenant).
func (s *Server) peers(c *gin.Context) {
	_, orgID, _ := sessionFrom(c)
	var devices []model.Device
	if err := store.ScopedByOrg(s.deps.DB, orgID).Order("id").Find(&devices).Error; err != nil {
		compatError(c, http.StatusInternalServerError, "could not list peers")
		return
	}
	now := time.Now()
	peers := make([]gin.H, 0, len(devices))
	for _, d := range devices {
		peers = append(peers, gin.H{
			"id":     d.RustdeskID,
			"name":   d.Name,
			"online": device.Status(&d, now) == "online",
		})
	}
	c.JSON(http.StatusOK, gin.H{"peers": peers})
}
