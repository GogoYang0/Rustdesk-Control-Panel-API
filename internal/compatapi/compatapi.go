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

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/access"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/addressbook"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/limit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/logquery"
)

// Context keys for the authenticated compat session.
const (
	// ContextUserID / ContextOrgID / ContextJTI are the gin context keys the
	// compat session middleware sets. They are exported because the audit
	// middleware must read them to attribute compat mutations; they stay in a
	// separate namespace from the management keys so the two token families can
	// never be confused for each other.
	ContextUserID = "compat.userID"
	ContextOrgID  = "compat.orgID"
	ContextJTI    = "compat.jti"
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
	Books *addressbook.Service
	// Access owns device visibility and reachability. The peer list and (in
	// the ticket task) ticket issue/redemption share this one evaluation; nil
	// falls back to a read-only service on the same DB.
	Access *access.Service
	// Tokens authenticates the personal token the client's `--assign` call
	// carries; nil falls back to a service on the same DB.
	Tokens *auth.TokenService
	// Roles resolves the token owner's live role for the `--assign`
	// authorization; nil falls back to a service on the same DB.
	Roles *authz.RoleService
	// AuditIngest stores the client's connection/file/alarm reports; nil falls
	// back to a service on the same DB with a GORM auditor.
	AuditIngest *logquery.Ingest
	// Auditor records client alarms; nil falls back to a GORM auditor.
	Auditor   audit.Auditor
	Now       func() time.Time
	AccessTTL time.Duration
}

// Server holds the resolved dependencies.
type Server struct {
	deps Deps
}

// Client identity bounds. The uuid also lands in CompatSession.UUID (128 byte
// column), so anything longer must be refused before the device is claimed --
// otherwise the device stays bound to an identity whose session can never be
// created.
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
		d.Devices = device.NewService(d.DB, nil, nil)
	}
	if d.Books == nil && d.DB != nil {
		d.Books = addressbook.NewService(d.DB)
	}
	if d.Access == nil && d.DB != nil {
		// Evaluation only reads; a nil recorder keeps the service read-only,
		// which is all the compat endpoints need.
		d.Access = access.NewService(d.DB, nil, nil)
	}
	if d.Tokens == nil && d.DB != nil {
		d.Tokens = auth.NewTokenService(d.DB, d.Now)
	}
	if d.Roles == nil && d.DB != nil {
		d.Roles = authz.NewRoleService(d.DB)
	}
	if d.AccessTTL == 0 {
		d.AccessTTL = 720 * time.Hour
	}
	if d.AuditIngest == nil && d.DB != nil {
		auditor := d.Auditor
		if auditor == nil {
			auditor = audit.NewGormAuditor(d.DB)
		}
		d.AuditIngest = logquery.New(d.DB, auditor, d.Now)
	}
	s := &Server{deps: d}

	g := r.Group("/api")
	g.POST("/login", s.login)
	g.GET("/login-options", s.loginOptions)
	// The client's `--assign` call: authenticated by a personal token, not by
	// the compat session, so it mounts beside /login instead of in the authed
	// group (D4).
	g.POST("/devices/cli", s.cliAssign)
	// The client sends heartbeat/sysinfo without a bearer token (official
	// protocol); the device binding comes from the most recent active
	// session carrying the same uuid (裁定 C16).
	g.POST("/heartbeat", s.heartbeat)
	g.POST("/sysinfo", s.sysinfo)
	// Client audit reports. They carry no Authorization header (the client
	// posts them with an empty auth argument), so they mount beside /login and
	// authenticate by the (id, uuid) pair matching the device binding.
	g.POST("/audit/conn", s.auditConn)
	g.POST("/audit/file", s.auditFile)
	g.POST("/audit/alarm", s.auditAlarm)
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
