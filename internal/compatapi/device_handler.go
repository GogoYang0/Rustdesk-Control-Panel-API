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
	dev, err := s.touchDevice(c, session, session.DeviceID)
	if err != nil {
		compatError(c, http.StatusInternalServerError, "heartbeat failed")
		return
	}
	if dev == nil {
		// The session is stale (disabled device, re-bound uuid, new binding
		// generation): deliver nothing, exactly like an unknown device.
		ok(c)
		return
	}
	s.writeHeartbeatResponse(c, session.OrganizationID, dev.ID, req.ModifiedAt)
}

// writeHeartbeatResponse builds the compat heartbeat body, which is a free-form
// JSON object rather than the management envelope.
//
// Only `strategy` and `modified_at` are set here, and only together: the client
// persists `modified_at` (strategy_timestamp) even when no strategy arrives, so
// a version without options would tell it "you are up to date" while it still
// runs the old configuration — and it would never ask again.
func (s *Server) writeHeartbeatResponse(c *gin.Context, orgID, deviceID uint, clientVersion int64) {
	if s.deps.Strategies == nil {
		ok(c)
		return
	}
	delivery, err := s.deps.Strategies.DeliveryFor(c.Request.Context(), orgID, deviceID, clientVersion)
	if err != nil {
		// Fail closed: a strategy that cannot be resolved or validated is not
		// sent. The client keeps its current configuration and asks again on
		// the next heartbeat; the protocol has no error channel for this.
		s.deps.Logger.Error("heartbeat strategy delivery failed: " + err.Error())
		ok(c)
		return
	}
	if !delivery.Deliver {
		ok(c)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"strategy":    gin.H{"config_options": delivery.Options},
		"modified_at": delivery.Version,
	})
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
	if _, err := s.touchDevice(c, session, session.DeviceID); err != nil {
		compatError(c, http.StatusInternalServerError, "sysinfo failed")
		return
	}
	ok(c)
}

// touchDevice records a heartbeat for the device bound to the session's
// organization. The row must exist and carry this session's binding: a
// deleted row is not resurrected here — an administrator reset (the rebind
// endpoint) is the binding reset, and the client re-claims the device through
// a fresh login (claimDevice); a row re-bound to another client instance is
// left alone.
func (s *Server) touchDevice(c *gin.Context, session *model.CompatSession, rustdeskID string) (*model.Device, error) {
	orgID := session.OrganizationID
	var dev model.Device
	err := store.ScopedByOrg(s.deps.DB, orgID).Where("rustdesk_id = ?", rustdeskID).First(&dev).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// The row was removed out of band (the supported reset is the rebind
		// endpoint); the old session must not resurrect or re-claim it.
		return nil, nil
	}
	if err != nil {
		// A transient query failure must not be mistaken for a missing row.
		return nil, err
	}
	if dev.Disabled {
		// The administrator stopped the device: credential-free activity is
		// dropped silently (the client protocol cannot act on an error here).
		return nil, nil
	}
	if dev.BoundUUID != session.UUID {
		// The binding moved to another client instance meanwhile.
		return nil, nil
	}
	if dev.BindingGeneration != session.BindingGeneration {
		// The binding was re-issued (administrator re-bind) after this
		// session was logged in: the session is stale no matter which uuid
		// it carries, so its activity is dropped (#40).
		return nil, nil
	}
	if _, err := s.deps.Devices.Heartbeat(c.Request.Context(), orgID, dev.ID); err != nil {
		return nil, err
	}
	return &dev, nil
}

// peers lists the devices the session's member may reach (issue C14: the
// client sees exactly its own tenant; D4: and only what the access rules
// allow). Owners and admins keep the whole organization, ordinary members see
// the union of their rules, and a disabled device is never a peer (D8) — the
// management device list stays the place where administrators see it.
func (s *Server) peers(c *gin.Context) {
	uid, orgID, _ := sessionFrom(c)
	all, allowedIDs, err := s.deps.Access.AllowedDeviceIDs(c.Request.Context(), orgID, uid)
	if err != nil {
		compatError(c, http.StatusInternalServerError, "could not list peers")
		return
	}
	// The disabled filter is deliberate even though the evaluation filters
	// disabled devices for the id path: the bypass returns all=true without an
	// id set, and a device stopped between the two queries must not leak here.
	query := store.ScopedByOrg(s.deps.DB, orgID).Where("disabled = ?", false)
	if !all {
		if len(allowedIDs) == 0 {
			c.JSON(http.StatusOK, gin.H{"peers": []gin.H{}})
			return
		}
		query = query.Where("id IN ?", allowedIDs)
	}
	var devices []model.Device
	if err := query.Order("id").Find(&devices).Error; err != nil {
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
