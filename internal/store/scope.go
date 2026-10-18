// Tenant scoping helpers: every business query must go through ScopedByOrg.
package store

import (
	"fmt"
	"sync"

	"gorm.io/gorm"
)

// businessModels lists every tenant-scoped model. New business models must be
// registered here so that isolation tests and reviewers can verify coverage.
var (
	businessModels   []any
	businessModelsMu sync.RWMutex
)

// RegisterScopedModel registers a model that carries organization_id.
func RegisterScopedModel(model any) {
	businessModelsMu.Lock()
	defer businessModelsMu.Unlock()
	businessModels = append(businessModels, model)
}

// ScopedModels returns the registered tenant-scoped models.
func ScopedModels() []any {
	businessModelsMu.RLock()
	defer businessModelsMu.RUnlock()
	out := make([]any, len(businessModels))
	copy(out, businessModels)
	return out
}

// ScopedByOrg is the only sanctioned way to query tenant data: every business
// query must go through it, never through a hand-written WHERE clause.
func ScopedByOrg(db *gorm.DB, orgID uint) *gorm.DB {
	return db.Where("organization_id = ?", orgID)
}

// RequireOrgID fails fast when an org-scoped call has no organization.
func RequireOrgID(orgID uint) error {
	if orgID == 0 {
		return fmt.Errorf("organization id is required for tenant-scoped access")
	}
	return nil
}
