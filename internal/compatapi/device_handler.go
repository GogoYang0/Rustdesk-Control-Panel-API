package compatapi

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

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
	session, found := s.activeSessionByUUID(req.UUID)
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
	session, found := s.activeSessionByUUID(uuid)
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
// organization; the device row is created on demand.
func (s *Server) touchDevice(c *gin.Context, session *model.CompatSession, rustdeskID string) error {
	orgID := session.OrganizationID
	var dev model.Device
	err := store.ScopedByOrg(s.deps.DB, orgID).Where("rustdesk_id = ?", rustdeskID).First(&dev).Error
	if err != nil {
		// The binding at login creates it; a missing row means the admin
		// deleted it meanwhile — recreate so the heartbeat is not lost.
		created, rerr := s.deps.Devices.Register(c.Request.Context(), orgID, device.RegisterInput{
			Name:       rustdeskID,
			RustdeskID: rustdeskID,
		})
		if rerr != nil {
			return rerr
		}
		dev = *created
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
