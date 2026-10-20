// Package compatapi implements the RustDesk client compatibility endpoints
// under /api/* (login, logout, currentUser, login-options, heartbeat,
// sysinfo, peers). The payload semantics follow the official 1.5 client;
// fixtures live in testdata/.
package compatapi

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/addressbook"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/limit"
)

// Context keys for the authenticated compat session.
const (
	ctxUserID = "compat.userID"
	ctxOrgID  = "compat.orgID"
	ctxJTI    = "compat.jti"
)

// Deps carries everything the compat endpoints need.
type Deps struct {
	DB     *gorm.DB
	Issuer *auth.Issuer
	// Devices persists devices and heartbeats; nil falls back to a service
	// on the same DB.
	Devices *device.Service
	Guard   *limit.LoginGuard
	// Books owns the address book domain; nil falls back to a service on
	// the same DB.
	Books     *addressbook.Service
	Now       func() time.Time
	AccessTTL time.Duration
}

// Server holds the resolved dependencies.
type Server struct {
	deps Deps
}

// Client identity bounds. Device.BoundUUID and CompatSession.UUID share the
// same 128 byte column, so a longer uuid would bind the device and then fail to
// create the session, leaving the device claimed by an identity the client can
// never present again.
const (
	maxDeviceIDLen   = 64
	maxDeviceUUIDLen = 128
)

// Mount registers the compat routes on the given router. It must NOT be
// placed behind the management JWT middleware: the compat endpoints
// authenticate with their own compat tokens.
func Mount(r gin.IRouter, d Deps) *Server {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Guard == nil {
		d.Guard = limit.NewLoginGuard()
	}
	if d.Devices == nil && d.DB != nil {
		d.Devices = device.NewService(d.DB, nil)
	}
	if d.Books == nil && d.DB != nil {
		d.Books = addressbook.NewService(d.DB)
	}
	if d.AccessTTL == 0 {
		d.AccessTTL = 720 * time.Hour
	}
	s := &Server{deps: d}

	g := r.Group("/api")
	g.POST("/login", s.login)
	g.GET("/login-options", s.loginOptions)
	// The client sends heartbeat/sysinfo without a bearer token (official
	// protocol); the device binding comes from the most recent active
	// session carrying the same uuid (裁定 C16).
	g.POST("/heartbeat", s.heartbeat)
	g.POST("/sysinfo", s.sysinfo)
	authed := g.Group("", s.requireSession())
	authed.POST("/logout", s.logout)
	authed.POST("/currentUser", s.currentUser)
	authed.GET("/peers", s.peers)

	// Address book client sync (task 9): mode detection plus the legacy
	// whole-book endpoints and the granular 1.4+ client endpoints.
	ab := authed.Group("/ab")
	ab.GET("", s.abLegacyGet)
	ab.GET("/get", s.abLegacyGet) // Sciter-era alias
	ab.POST("", s.abLegacyPost)
	ab.POST("/personal", s.abPersonal)
	ab.POST("/peers", s.abPeersPage)
	ab.POST("/tags/:guid", s.abTagsList)
	ab.POST("/peer/add/:guid", s.abPeerAdd)
	ab.PUT("/peer/update/:guid", s.abPeerUpdate)
	ab.DELETE("/peer/:guid", s.abPeerDelete)
	ab.POST("/tag/add/:guid", s.abTagAdd)
	ab.PUT("/tag/rename/:guid", s.abTagRename)
	ab.PUT("/tag/update/:guid", s.abTagUpdate)
	ab.DELETE("/tag/:guid", s.abTagDelete)
	return s
}

// compatError answers with the client-facing error envelope. The client
// shows the message text; the 403 guidance points multi-org users at the
// management panel (裁定 C16).
func compatError(c *gin.Context, status int, msg string) {
	c.JSON(status, gin.H{"error": msg})
}

// ok answers with an empty JSON object; the client tolerates any body.
func ok(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{})
}
