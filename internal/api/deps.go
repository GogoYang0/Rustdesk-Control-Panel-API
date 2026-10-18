// Package api wires the generated HTTP interface to concrete handlers.
package api

import (
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
)

// Deps carries everything the HTTP layer needs.
type Deps struct {
	DB            *gorm.DB
	Auth          *auth.Service
	Issuer        *auth.Issuer
	Auditor       audit.Auditor
	Logger        *zap.Logger
	Now           func() time.Time
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
	InvitationTTL time.Duration
}

// AdminAPI implements the generated gen.ServerInterface.
type AdminAPI struct {
	deps  Deps
	guard *loginGuard
}

// NewAdminAPI builds the handler set.
func NewAdminAPI(d Deps) *AdminAPI {
	if d.Auditor == nil {
		d.Auditor = audit.Nop{}
	}
	if d.Logger == nil {
		d.Logger = zap.NewNop()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.InvitationTTL == 0 {
		d.InvitationTTL = 7 * 24 * time.Hour
	}
	return &AdminAPI{deps: d, guard: newLoginGuard()}
}
