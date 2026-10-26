package compatapi

import (
	"encoding/json"
	"errors"
	"math"
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
	s.writeHeartbeatResponse(c, session.OrganizationID, dev.ID, req)
}

// writeHeartbeatResponse builds the compat heartbeat body, which is a free-form
// JSON object rather than the management envelope. Two optional fields are set:
//
//   - `strategy` + `modified_at`, only together: the client persists
//     `modified_at` even when no strategy arrives, so a version without options
//     would tell it "you are up to date" while it still runs the old config.
//   - `disconnect`, only when a pending request exists and the client just
//     reported live connections; those ids are the client's own, so the panel
//     can never name a connection nobody holds.
func (s *Server) writeHeartbeatResponse(c *gin.Context, orgID, deviceID uint, req heartbeatRequest) {
	body := gin.H{}

	if conns := parseConnIDs(req.Conns); len(conns) > 0 && s.deps.Strategies != nil {
		// Informational only: the disconnect path uses the ids from this very
		// request, so a missing heartbeat row loses nothing but a debug aid.
		if err := s.deps.Strategies.NoteConns(c.Request.Context(), orgID, deviceID, conns); err != nil {
			s.deps.Logger.Warn("heartbeat conn note failed: " + err.Error())
		}

		drop, err := s.takeDisconnect(c, orgID, deviceID, conns)
		if err != nil {
			// Fail closed: a request that cannot be consumed stays pending and
			// is retried on the next heartbeat.
			s.deps.Logger.Error("heartbeat disconnect consume failed: " + err.Error())
		} else if len(drop) > 0 {
			body["disconnect"] = drop
		}
	}

	if s.deps.Strategies != nil {
		delivery, err := s.deps.Strategies.DeliveryFor(c.Request.Context(), orgID, deviceID, req.ModifiedAt)
		switch {
		case err != nil:
			// Fail closed: the client keeps its current configuration and asks
			// again; the protocol has no error channel for this.
			s.deps.Logger.Error("heartbeat strategy delivery failed: " + err.Error())
		case delivery.Deliver:
			body["strategy"] = gin.H{"config_options": delivery.Options}
			body["modified_at"] = delivery.Version
		}
	}

	c.JSON(http.StatusOK, body)
}

// takeDisconnect consumes a pending request inside its own transaction so the
// status change and its audit entry commit together.
func (s *Server) takeDisconnect(c *gin.Context, orgID, deviceID uint, conns []int64) ([]int64, error) {
	var drop []int64
	err := s.deps.DB.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		var terr error
		drop, terr = s.deps.Strategies.TakePendingTx(tx, orgID, deviceID, conns)
		return terr
	})
	return drop, err
}

// maxHeartbeatConns bounds how many connection ids one heartbeat may carry. A
// live client holds a handful; the field comes from an unauthenticated body,
// so an oversized array is treated as garbage rather than partially trusted.
const maxHeartbeatConns = 64

// parseConnIDs converts the client's `conns` array into ids. The client sends
// the ids it holds; anything that is not a positive integer that fits the
// client's own i32 field is dropped rather than guessed at. An oversized array
// is discarded whole: the ids would otherwise be echoed back as disconnect
// targets and serialized into the hottest table.
func parseConnIDs(raw []any) []int64 {
	if len(raw) > maxHeartbeatConns {
		return nil
	}
	out := make([]int64, 0, len(raw))
	seen := make(map[int64]bool, len(raw))
	for _, v := range raw {
		var n int64
		switch x := v.(type) {
		case float64:
			if x <= 0 || x != float64(int64(x)) || x > math.MaxInt32 {
				continue
			}
			n = int64(x)
		case int:
			if x <= 0 || int64(x) > math.MaxInt32 {
				continue
			}
			n = int64(x)
		case int64:
			if x <= 0 || x > math.MaxInt32 {
				continue
			}
			n = x
		case json.Number:
			i, err := x.Int64()
			if err != nil || i <= 0 || i > math.MaxInt32 {
				continue
			}
			n = i
		default:
			continue
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
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
