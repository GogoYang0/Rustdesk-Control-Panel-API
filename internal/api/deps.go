// Package api wires the generated HTTP interface to concrete handlers.
package api

import (
	"context"
	"io"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/addressbook"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/mail"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/provision"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/session"
)

// Deps carries everything the HTTP layer needs.
type Deps struct {
	DB             *gorm.DB
	Auth           *auth.Service
	Devices        *device.Service
	ProvisionQueue Provisioner
	Provisioning   ProvisioningManager
	OrgsPerUser    int
	Issuer         *auth.Issuer
	Auditor        audit.Auditor
	Logger         *zap.Logger
	Now            func() time.Time
	AccessTTL      time.Duration
	RefreshTTL     time.Duration
	InvitationTTL  time.Duration

	// Mailer delivers transactional email; tests inject a fake.
	Mailer mail.Mailer

	// WebBaseURL is the panel frontend origin used to build links inside
	// outgoing emails (verify-email, invitation accept).
	WebBaseURL string
	// VerificationTTL bounds the verification token lifetime (default 24h).
	VerificationTTL time.Duration
	// ResendCooldown throttles repeated verification mails per account.
	ResendCooldown time.Duration

	// CompatTTL bounds the RustDesk compatibility session/token lifetime
	// (config compat.accessTTL, default 720h).
	CompatTTL time.Duration

	// Tickets issues and redeems connection tickets. NewAdminAPI builds one
	// from DB/Auditor/Now when it is nil, so tests can leave it out.
	Tickets *session.Service

	// Roles resolves and seeds organization roles. NewAdminAPI derives it from
	// DB when nil.
	Roles *authz.RoleService
}

// Provisioner schedules asynchronous server provisioning.
type Provisioner interface {
	Enqueue(orgID uint) error
}

// ProvisioningManager exposes the per-organization provisioning switch. It is
// optional in tests that never touch the endpoint; a nil manager makes the
// endpoint fail instead of pretending the deployment state is known.
type ProvisioningManager interface {
	State(ctx context.Context, orgID uint) (provision.State, error)
	SetEnabled(ctx context.Context, orgID, actorID uint, enabled bool) (provision.State, bool, error)
}

// AdminAPI implements the generated gen.ServerInterface.
type AdminAPI struct {
	deps    Deps
	guard   *loginGuard
	resend  *loginGuard
	books   *addressbook.Service
	tickets *session.Service
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
	if d.VerificationTTL == 0 {
		d.VerificationTTL = 24 * time.Hour
	}
	if d.ResendCooldown == 0 {
		d.ResendCooldown = 15 * time.Minute
	}
	if d.Mailer == nil {
		// main.go always injects a real mailer; the discard default keeps
		// dependency wiring optional in tests that do not exercise mail.
		d.Mailer = mail.NewDev(io.Discard)
	}
	if d.Roles == nil {
		d.Roles = authz.NewRoleService(d.DB)
	}
	tickets := d.Tickets
	if tickets == nil {
		// The service fails closed without a recorder, and governance
		// mutations without their audit entries are exactly what it refuses
		// to be. Derive the session service only from a transactional
		// auditor (the GormAuditor production wires); anything else is a
		// wiring error and must stop the process at startup, not run with
		// silently discarded audit entries (#58 review).
		recorder, ok := d.Auditor.(audit.TxRecorder)
		if !ok {
			panic("api: transactional auditor required when Tickets is nil")
		}
		tickets = session.NewService(d.DB, recorder, d.Now)
	}

	return &AdminAPI{
		deps:    d,
		guard:   newLoginGuard(),
		resend:  newLoginGuard(),
		books:   addressbook.NewService(d.DB),
		tickets: tickets,
	}
}
