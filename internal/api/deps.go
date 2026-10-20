// Package api wires the generated HTTP interface to concrete handlers.
package api

import (
	"io"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/addressbook"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/mail"
)

// Deps carries everything the HTTP layer needs.
type Deps struct {
	DB             *gorm.DB
	Auth           *auth.Service
	Devices        *device.Service
	ProvisionQueue Provisioner
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
}

// Provisioner schedules asynchronous server provisioning.
type Provisioner interface {
	Enqueue(orgID uint) error
}

// AdminAPI implements the generated gen.ServerInterface.
type AdminAPI struct {
	deps   Deps
	guard  *loginGuard
	resend *loginGuard
	books  *addressbook.Service
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
	return &AdminAPI{
		deps:   d,
		guard:  newLoginGuard(),
		resend: newLoginGuard(),
		books:  addressbook.NewService(d.DB),
	}
}
