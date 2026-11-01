package main

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"time"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/access"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/clientbuild"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/controlrole"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// Options describe the disposable identities a development or CI database
// needs. Passwords are hashed here; nothing is printed.
type Options struct {
	OrgName       string
	AdminEmail    string
	AdminPassword string
	OpsEmail      string
	OpsPassword   string
	AssetDir      string
}

// Result names the rows that were created or reused.
type Result struct {
	OrgID      uint
	AdminEmail string
	OpsEmail   string
}

// Seed creates the organization, builtin roles, access/control-role defaults,
// an owner and a member. It is idempotent: rerunning reuses existing rows.
func Seed(db *gorm.DB, opts Options) (Result, error) {
	if opts.OrgName == "" || opts.AdminEmail == "" || opts.AdminPassword == "" ||
		opts.OpsEmail == "" || opts.OpsPassword == "" || opts.AssetDir == "" {
		return Result{}, errors.New("devseed: all names, emails, passwords and asset dir are required")
	}
	if _, err := clientbuild.NewStorage(opts.AssetDir); err != nil {
		return Result{}, fmt.Errorf("devseed: prepare asset dir: %w", err)
	}
	probe, err := os.CreateTemp(opts.AssetDir, ".devseed-write-probe-*")
	if err != nil {
		return Result{}, fmt.Errorf("devseed: asset dir is not writable: %w", err)
	}
	probeName := probe.Name()
	_ = probe.Close()
	_ = os.Remove(probeName)
	if err := db.AutoMigrate(model.PersistentModels()...); err != nil {
		return Result{}, fmt.Errorf("devseed: migrate: %w", err)
	}

	org, err := ensureOrg(db, opts.OrgName)
	if err != nil {
		return Result{}, err
	}
	if err := authz.NewRoleService(db).EnsureBuiltins(org.ID); err != nil {
		return Result{}, fmt.Errorf("devseed: builtin roles: %w", err)
	}
	if err := db.Transaction(func(tx *gorm.DB) error {
		if err := access.EnsureDefaultsTx(tx, org.ID); err != nil {
			return err
		}
		return controlrole.EnsureDefaultsTx(tx, org.ID)
	}); err != nil {
		return Result{}, fmt.Errorf("devseed: defaults: %w", err)
	}

	admin, err := ensureUser(db, opts.AdminEmail, opts.AdminPassword)
	if err != nil {
		return Result{}, err
	}
	ops, err := ensureUser(db, opts.OpsEmail, opts.OpsPassword)
	if err != nil {
		return Result{}, err
	}
	if err := ensureMembership(db, org.ID, admin.ID, model.RoleKindOwner); err != nil {
		return Result{}, err
	}
	if err := ensureMembership(db, org.ID, ops.ID, model.RoleKindMember); err != nil {
		return Result{}, err
	}
	if err := seedLogEvents(db, org.ID); err != nil {
		return Result{}, err
	}
	if err := seedInvitation(db, org.ID); err != nil {
		return Result{}, err
	}
	if err := seedSessionFixture(db, org.ID); err != nil {
		return Result{}, err
	}
	if err := seedDeleteOrg(db, admin); err != nil {
		return Result{}, err
	}
	if err := seedClientBuilds(db, org.ID, admin.ID, opts.AssetDir); err != nil {
		return Result{}, err
	}
	return Result{OrgID: org.ID, AdminEmail: admin.Email, OpsEmail: ops.Email}, nil
}

// SeedDeleteOrgName is the disposable organization the org-delete e2e removes.
// It is seeded with provisioning_disabled=true so the reconciler never tries
// to start containers in the Docker-less e2e environment; deletion therefore
// has no server group to tear down.
const SeedDeleteOrgName = "E2E 删除组织"

func seedDeleteOrg(db *gorm.DB, admin model.User) error {
	var org model.Organization
	err := db.Where("name = ?", SeedDeleteOrgName).First(&org).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		org = model.Organization{Name: SeedDeleteOrgName, ProvisioningDisabled: true}
		if err := db.Create(&org).Error; err != nil {
			return fmt.Errorf("devseed: create delete fixture org: %w", err)
		}
	case err != nil:
		return fmt.Errorf("devseed: load delete fixture org: %w", err)
	default:
		if err := db.Model(&model.Organization{}).Where("id = ?", org.ID).
			Update("provisioning_disabled", true).Error; err != nil {
			return fmt.Errorf("devseed: disable delete fixture provisioning: %w", err)
		}
	}
	if err := authz.NewRoleService(db).EnsureBuiltins(org.ID); err != nil {
		return fmt.Errorf("devseed: delete fixture roles: %w", err)
	}
	if err := db.Transaction(func(tx *gorm.DB) error {
		if err := access.EnsureDefaultsTx(tx, org.ID); err != nil {
			return err
		}
		return controlrole.EnsureDefaultsTx(tx, org.ID)
	}); err != nil {
		return fmt.Errorf("devseed: delete fixture defaults: %w", err)
	}
	if err := ensureMembership(db, org.ID, admin.ID, model.RoleKindOwner); err != nil {
		return err
	}
	return nil
}

// SeedSessionDeviceID is the RustDesk id of the disposable device that owns
// the open session fixture used by the session-end e2e.
const SeedSessionDeviceID = "E2E-SESSION-1"

// seedSessionFixture keeps one deleted-safe device and one open panel session
// so the session-end e2e has a deterministic target. Reruns reset the device,
// drop its session history and recreate exactly one open session.
func seedSessionFixture(db *gorm.DB, orgID uint) error {
	return db.Transaction(func(tx *gorm.DB) error {
		scoped := store.ScopedByOrg(tx, orgID)
		var device model.Device
		err := scoped.Unscoped().Where("rustdesk_id = ?", SeedSessionDeviceID).First(&device).Error
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			device = model.Device{
				OrganizationID: orgID,
				RustdeskID:     SeedSessionDeviceID,
				Name:           "E2E 会话设备",
			}
			if err := scoped.Create(&device).Error; err != nil {
				return fmt.Errorf("devseed: create session device: %w", err)
			}
		case err != nil:
			return fmt.Errorf("devseed: load session device: %w", err)
		default:
			if err := scoped.Unscoped().Model(&model.Device{}).Where("id = ?", device.ID).
				Updates(map[string]any{
					"deleted_at":      nil,
					"deleted_by":      uint(0),
					"disabled":        false,
					"disabled_at":     nil,
					"disabled_by":     uint(0),
					"bound_uuid":      "",
					"device_group_id": nil,
					"owner_user_id":   nil,
					"strategy_id":     nil,
					"last_seen_at":    nil,
				}).Error; err != nil {
				return fmt.Errorf("devseed: reset session device: %w", err)
			}
		}

		var sessionIDs []uint
		if err := scoped.Model(&model.Session{}).Where("device_id = ?", device.ID).
			Pluck("id", &sessionIDs).Error; err != nil {
			return fmt.Errorf("devseed: list session fixture rows: %w", err)
		}
		if len(sessionIDs) > 0 {
			if err := scoped.Where("session_id IN ?", sessionIDs).Delete(&model.SessionEvent{}).Error; err != nil {
				return fmt.Errorf("devseed: clear session events: %w", err)
			}
			if err := scoped.Where("id IN ?", sessionIDs).Delete(&model.Session{}).Error; err != nil {
				return fmt.Errorf("devseed: clear session fixture rows: %w", err)
			}
		}
		if err := scoped.Model(&model.DeviceDisconnect{}).
			Where("device_id = ? AND status = ?", device.ID, model.DisconnectStatusPending).
			Update("status", model.DisconnectStatusExpired).Error; err != nil {
			return fmt.Errorf("devseed: expire session disconnects: %w", err)
		}

		now := time.Now().UTC()
		session := model.Session{
			OrganizationID: orgID,
			DeviceID:       device.ID,
			RustdeskID:     SeedSessionDeviceID,
			Origin:         model.SessionOriginPanel,
			Status:         model.SessionStatusOpen,
			StartedAt:      now,
			LastActivityAt: &now,
		}
		if err := scoped.Create(&session).Error; err != nil {
			return fmt.Errorf("devseed: insert session fixture: %w", err)
		}
		return nil
	})
}

// SeedInvitationEmail is the disposable pending invitation the e2e suite
// lists and revokes. It never leaves the CI/dev database.
const SeedInvitationEmail = "e2e-invite@example.com"

// seedInvitation keeps one pending invitation for e2e. The plaintext token is
// never generated or stored: only a hash of discarded random bytes exists, so
// the fixture is unusable outside the UI and cannot leak through the dev mailer.
func seedInvitation(db *gorm.DB, orgID uint) error {
	return db.Transaction(func(tx *gorm.DB) error {
		if err := store.ScopedByOrg(tx, orgID).
			Where("email = ?", SeedInvitationEmail).
			Delete(&model.Invitation{}).Error; err != nil {
			return fmt.Errorf("devseed: clear sample invitation: %w", err)
		}
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return fmt.Errorf("devseed: invitation token: %w", err)
		}
		inv := model.Invitation{
			OrganizationID: orgID,
			Email:          SeedInvitationEmail,
			Role:           model.RoleMember,
			TokenHash:      fmt.Sprintf("%x", sha256.Sum256(raw)),
			ExpiresAt:      time.Now().UTC().Add(24 * time.Hour),
		}
		if err := store.ScopedByOrg(tx, orgID).Create(&inv).Error; err != nil {
			return fmt.Errorf("devseed: insert sample invitation: %w", err)
		}
		return nil
	})
}

// seedLogEvents gives e2e/read-only log pages a deterministic set of parsed
// hbbs/hbbr events. The marker lives in detail_json under a reserved key, so
// reruns replace only their own rows and never touch collected evidence.
func seedLogEvents(db *gorm.DB, orgID uint) error {
	return db.Transaction(func(tx *gorm.DB) error {
		if err := store.ScopedByOrg(tx, orgID).
			Where("detail_json LIKE ?", `%"devseed":"e2e"%`).
			Delete(&model.LogEvent{}).Error; err != nil {
			return fmt.Errorf("devseed: clear sample log events: %w", err)
		}
		now := time.Now().UTC()
		mk := func(minutes int, source, level, kind, raw string) model.LogEvent {
			return model.LogEvent{
				OrganizationID: orgID,
				Source:         source,
				Level:          level,
				Kind:           kind,
				DetailJSON:     fmt.Sprintf(`{"devseed":"e2e","raw":%q}`, raw),
				OccurredAt:     now.Add(-time.Duration(minutes) * time.Minute),
			}
		}
		events := []model.LogEvent{
			mk(4, model.LogSourceHbbs, model.LogLevelInfo, model.LogKindConn, "INFO connection from 10.0.0.5"),
			mk(3, model.LogSourceHbbr, model.LogLevelWarn, model.LogKindFile, "WARN file transfer path=/tmp/report.csv"),
			mk(2, model.LogSourceHbbs, model.LogLevelError, model.LogKindError, "ERROR relay unreachable"),
			mk(1, model.LogSourceHbbr, model.LogLevelInfo, model.LogKindDisconnected, "INFO connection closed"),
		}
		if err := store.ScopedByOrg(tx, orgID).Create(&events).Error; err != nil {
			return fmt.Errorf("devseed: insert sample log events: %w", err)
		}
		return nil
	})
}

func ensureOrg(db *gorm.DB, name string) (model.Organization, error) {
	var org model.Organization
	err := db.Where("name = ?", name).First(&org).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		org = model.Organization{Name: name}
		if err := db.Create(&org).Error; err != nil {
			return model.Organization{}, fmt.Errorf("devseed: create organization: %w", err)
		}
		return org, nil
	}
	if err != nil {
		return model.Organization{}, fmt.Errorf("devseed: load organization: %w", err)
	}
	return org, nil
}

func ensureUser(db *gorm.DB, email, password string) (model.User, error) {
	var user model.User
	err := db.Where("LOWER(email) = ?", email).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		hash, herr := auth.HashPassword(password)
		if herr != nil {
			return model.User{}, fmt.Errorf("devseed: hash password: %w", herr)
		}
		user = model.User{Email: email, PasswordHash: hash, EmailVerified: true}
		if err := db.Create(&user).Error; err != nil {
			return model.User{}, fmt.Errorf("devseed: create user: %w", err)
		}
		return user, nil
	}
	if err != nil {
		return model.User{}, fmt.Errorf("devseed: load user: %w", err)
	}
	return user, nil
}

func ensureMembership(db *gorm.DB, orgID, userID uint, kind string) error {
	var role model.Role
	// The tenant plugin would inject organization_id = 0 without this scope.
	if err := store.WithoutTenantScope(db).
		Where("organization_id = ? AND kind = ?", orgID, kind).First(&role).Error; err != nil {
		return fmt.Errorf("devseed: load %s role: %w", kind, err)
	}
	var existing model.Membership
	err := store.WithoutTenantScope(db).
		Where("organization_id = ? AND user_id = ?", orgID, userID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		if err := db.Create(&model.Membership{
			OrganizationID: orgID, UserID: userID, RoleID: role.ID,
		}).Error; err != nil {
			return fmt.Errorf("devseed: create %s membership: %w", kind, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("devseed: load %s membership: %w", kind, err)
	}
	return nil
}
