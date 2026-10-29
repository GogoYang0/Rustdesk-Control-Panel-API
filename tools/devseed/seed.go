package main

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/access"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/authz"
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
		opts.OpsEmail == "" || opts.OpsPassword == "" {
		return Result{}, errors.New("devseed: all names, emails and passwords are required")
	}
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
	return Result{OrgID: org.ID, AdminEmail: admin.Email, OpsEmail: ops.Email}, nil
}

// seedLogEvents gives e2e/read-only log pages a deterministic set of parsed
// hbbs/hbbr events. The marker lives in detail_json; reruns replace only their
// own rows and never touch real collected evidence.
func seedLogEvents(db *gorm.DB, orgID uint) error {
	if err := store.ScopedByOrg(db, orgID).
		Where("detail_json LIKE ?", `%"seed":"e2e"%`).
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
			DetailJSON:     fmt.Sprintf(`{"seed":"e2e","raw":%q}`, raw),
			OccurredAt:     now.Add(-time.Duration(minutes) * time.Minute),
		}
	}
	events := []model.LogEvent{
		mk(4, model.LogSourceHbbs, model.LogLevelInfo, model.LogKindConn, "INFO connection from 10.0.0.5"),
		mk(3, model.LogSourceHbbr, model.LogLevelWarn, model.LogKindFile, "WARN file transfer path=/tmp/report.csv"),
		mk(2, model.LogSourceHbbs, model.LogLevelError, model.LogKindError, "ERROR relay unreachable"),
		mk(1, model.LogSourceHbbr, model.LogLevelInfo, model.LogKindDisconnected, "INFO connection closed"),
	}
	if err := store.ScopedByOrg(db, orgID).Create(&events).Error; err != nil {
		return fmt.Errorf("devseed: insert sample log events: %w", err)
	}
	return nil
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
