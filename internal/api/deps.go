// Package api wires the generated HTTP interface to concrete handlers.
package api

import (
	"context"
	"io"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/access"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/account"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/addressbook"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/captcha"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/clientbuild"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/controlrole"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/device"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/identity"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/ldapauth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/limit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/logquery"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/mail"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/oidc"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/passkey"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/provision"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/session"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/strategy"
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
	// PasswordResetTTL bounds the admin-issued password reset link (default 1h).
	PasswordResetTTL time.Duration
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
	// Me resolves the caller's own profile and organization roles.
	Me *account.Service

	// Access owns user groups, device groups and access rules. NewAdminAPI
	// derives it from DB and the transactional auditor when nil.
	Access *access.Service

	// ControlRoles owns in-session roles and member assignments. NewAdminAPI
	// derives it from DB and the transactional auditor when nil.
	ControlRoles *controlrole.Service

	// LogQuery reads the client-reported connection/file logs. NewAdminAPI
	// derives it from DB when nil.
	LogQuery *logquery.Service

	// Strategies owns client strategies, their assignments and disconnect
	// requests. NewAdminAPI derives it from DB and the transactional auditor
	// when nil.
	Strategies *strategy.Service

	// ClientBuilds owns custom client build profiles, builds and artifacts.
	// It is nil when the deployment did not wire the feature; the endpoints
	// then answer 503 instead of pretending the capability exists.
	ClientBuilds *clientbuild.Service

	// Tokens mints and validates personal API tokens. NewRouter derives it from
	// DB when nil so tests and the entrypoint share the same wiring.
	Tokens *auth.TokenService

	// TOTP owns management-login two-factor state. NewRouter derives it from DB
	// and AuthSecret when nil.
	TOTP *auth.TOTPService
	// AuthSecret seeds the TOTP secret-encryption key (HKDF). The entrypoint
	// passes the configured auth secret; tests may leave it empty.
	AuthSecret string

	// Retention archives and purges audit rows. NewRouter derives it from DB,
	// Auditor and Now when nil.
	Retention *audit.RetentionService

	// Captcha gates the public credential-checking endpoints. NewAdminAPI
	// substitutes a disabled service when nil, so tests and deployments that
	// do not enable it keep today's behavior.
	Captcha *captcha.Service

	// Passkeys owns WebAuthn credentials and ceremonies. It is nil when the
	// deployment did not enable the feature; the endpoints then answer 503
	// instead of pretending the capability exists.
	Passkeys *passkey.Service

	// OIDC owns the external identity provider, its login flows and the
	// identity bindings. Nil means the feature is off and every OIDC endpoint
	// answers 503.
	OIDC *oidc.Service

	// LDAP is the directory-backed Directory implementation. Nil means the
	// feature is off and POST /auth/ldap/login answers 503.
	LDAP ldapauth.Directory
	// LDAPProviderName is the login-button label from config.
	LDAPProviderName string
	// LDAPIssuer is the lowercased directory host: it is the issuer column of
	// the identity binding, so changing the host changes the binding namespace.
	LDAPIssuer string

	// Identity owns the external-identity bindings shared by OIDC and LDAP.
	Identity *identity.Service

	// RequireLocalSecondFactor makes an external login still ask for the
	// panel's own TOTP for accounts that already enabled it (design O12).
	RequireLocalSecondFactor bool
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
	deps      Deps
	guard     *loginGuard
	resend    *loginGuard
	totpGuard *loginGuard
	// totpManageGuard throttles the authenticated self-service 2FA endpoints.
	// It is a separate instance so their requests never drain the
	// unauthenticated login bucket, and their own per-IP bucket still bounds
	// attempts once the shared failure table is full.
	totpManageGuard *loginGuard
	// passkeyGuard bounds unauthenticated passkey login attempts. It is a
	// separate bucket so WebAuthn traffic never drains the password login
	// budget (and vice versa).
	passkeyGuard *loginGuard
	// oidcGuard bounds the unauthenticated OIDC endpoints (start, callback,
	// exchange) so probing the redirect codes cannot drain the password bucket.
	oidcGuard    *loginGuard
	books        *addressbook.Service
	tickets      *session.Service
	totp         *auth.TOTPService
	retention    *audit.RetentionService
	captcha      *captcha.Service
	clientBuilds *clientbuild.Service
	passkeys     *passkey.Service
	oidc         *oidc.Service
	ldap         ldapauth.Directory
	ldapName     string
	ldapIssuer   string
	identity     *identity.Service
	// captchaGuard bounds challenge issuance per IP without spending the
	// login attempt budget.
	captchaGuard *loginGuard
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
	if d.PasswordResetTTL == 0 {
		d.PasswordResetTTL = time.Hour
	}
	if d.Mailer == nil {
		// main.go always injects a real mailer; the discard default keeps
		// dependency wiring optional in tests that do not exercise mail.
		d.Mailer = mail.NewDev(io.Discard)
	}
	if d.Roles == nil {
		d.Roles = authz.NewRoleService(d.DB)
	}
	if d.Me == nil {
		// Shares the role resolver the per-request guard uses, so /me and
		// membershipFor can never disagree about what a role means.
		d.Me = account.NewService(d.DB, d.Roles)
	}
	if d.Access == nil {
		// The service refuses every write without a transactional recorder; a
		// non-transactional auditor therefore leaves the endpoints read-only
		// instead of silently dropping audit entries.
		recorder, _ := d.Auditor.(audit.TxRecorder)
		d.Access = access.NewService(d.DB, recorder, d.Now)
	}
	if d.ControlRoles == nil {
		// Same fail-closed rule as Access: no transactional recorder means every
		// role mutation is refused rather than committed unaudited.
		recorder, _ := d.Auditor.(audit.TxRecorder)
		d.ControlRoles = controlrole.NewService(d.DB, recorder, d.Now)
	}
	if d.LogQuery == nil {
		d.LogQuery = logquery.NewService(d.DB)
	}
	if d.Strategies == nil {
		// Same fail-closed rule as Access: without a transactional recorder
		// every strategy mutation is refused rather than committed unaudited.
		recorder, _ := d.Auditor.(audit.TxRecorder)
		d.Strategies = strategy.NewService(d.DB, recorder, d.Now)
	}
	if d.TOTP == nil {
		d.TOTP = auth.NewTOTPService(d.DB, d.AuthSecret, d.Now)
	}
	if d.Identity == nil {
		d.Identity = identity.NewService(d.DB, d.Now)
	}
	if d.Retention == nil {
		recorder, _ := d.Auditor.(audit.TxRecorder)
		d.Retention = audit.NewRetentionService(d.DB, "./data/audit-archive", recorder, d.Now)
	}
	if d.Captcha == nil {
		// Disabled by default: the captcha is opt-in and must not change any
		// existing login behavior when a deployment leaves it off.
		d.Captcha = captcha.Disabled()
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
		// Wire the control role resolver: issuance snapshots the actor's
		// permissions onto the ticket, and the API tests exercise the real path
		// instead of a service without role awareness.
		tickets = session.NewService(d.DB, recorder, d.Now).
			WithControlRoles(d.ControlRoles).
			WithAccess(d.Access)
	}

	return &AdminAPI{
		deps:      d,
		guard:     newLoginGuard(),
		resend:    newLoginGuard(),
		totpGuard: newLoginGuard(),

		totpManageGuard: newLoginGuard(),
		passkeyGuard:    newLoginGuard(),
		// Three tokens per SSO login (start, callback, exchange): the bucket must
		// fit several logins per shared NAT address, unlike the password bucket.
		oidcGuard:    limit.NewLoginGuardWithLimits(30, 30),
		books:        addressbook.NewService(d.DB),
		tickets:      tickets,
		totp:         d.TOTP,
		retention:    d.Retention,
		captcha:      d.Captcha,
		clientBuilds: d.ClientBuilds,
		passkeys:     d.Passkeys,
		oidc:         d.OIDC,
		ldap:         d.LDAP,
		ldapName:     d.LDAPProviderName,
		ldapIssuer:   d.LDAPIssuer,
		identity:     d.Identity,
		captchaGuard: newLoginGuard(),
	}
}
