package compatapi

import (
	"context"
	"time"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// RevokeOrgSessions revokes every active compat session of one user in one
// organization and returns how many rows it revoked. Call it when the user
// loses access to the organization — membership removal, role downgrade, or
// any future path that ends a membership (#39): a compat token lives up to
// 720 hours, so a membership change must kill the sessions it issued, not
// wait for expiry. The credential-free heartbeat and sysinfo resolve sessions
// through the same table, so they die with it.
//
// The operation is cross-tenant by design: the caller acts on behalf of the
// organization whose membership changed, and the rows carry both org and
// user id, so the scope is exact. It is idempotent — already-revoked rows
// no longer match, and expired rows are left alone (Active() refuses them
// anyway, and the returned count stays the honest "sessions that died
// here" number).
func RevokeAllOrgSessions(ctx context.Context, db *gorm.DB, orgID uint, now time.Time) (int64, error) {
	if orgID == 0 {
		return 0, nil
	}
	res := store.WithoutTenantScope(db.WithContext(ctx)).
		Model(&model.CompatSession{}).
		Where("organization_id = ? AND revoked_at IS NULL AND expires_at > ?", orgID, now).
		Update("revoked_at", now)
	if res.Error != nil {
		return 0, res.Error
	}
	return res.RowsAffected, nil
}

func RevokeOrgSessions(ctx context.Context, db *gorm.DB, orgID, userID uint, now time.Time) (int64, error) {
	if orgID == 0 || userID == 0 {
		return 0, nil
	}
	res := store.WithoutTenantScope(db.WithContext(ctx)).
		Model(&model.CompatSession{}).
		Where("organization_id = ? AND user_id = ? AND revoked_at IS NULL AND expires_at > ?",
			orgID, userID, now).
		Update("revoked_at", now)
	if res.Error != nil {
		return 0, res.Error
	}
	return res.RowsAffected, nil
}
