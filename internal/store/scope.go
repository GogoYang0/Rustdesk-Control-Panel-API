// Tenant scoping helpers: every business query must carry an org context.
package store

import (
	"context"
	"fmt"
	"sync"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// OrgContextKey is the context key carrying the tenant id.
type orgCtxKey struct{}

var orgContextKey = orgCtxKey{}

// businessModels lists every tenant-scoped model. New business models must be
// registered here so that isolation tests and reviewers can verify coverage.
var (
	businessModels   []any
	businessModelsMu sync.RWMutex
	scopedTables     = map[string]bool{}
)

// RegisterScopedModel registers a model that carries organization_id.
// Only registered tables get the tenant condition injected.
func RegisterScopedModel(m any) {
	businessModelsMu.Lock()
	defer businessModelsMu.Unlock()
	businessModels = append(businessModels, m)

	table := ""
	if tn, ok := m.(interface{ TableName() string }); ok {
		table = tn.TableName()
	} else if s, err := schema.Parse(m, &sync.Map{}, schema.NamingStrategy{}); err == nil {
		table = s.Table
	}
	if table != "" {
		scopedTables[table] = true
	}

}

// ScopedModels returns the registered tenant-scoped models.
func ScopedModels() []any {
	businessModelsMu.RLock()
	defer businessModelsMu.RUnlock()
	out := make([]any, len(businessModels))
	copy(out, businessModels)
	return out
}

func tableIsScoped(table string) bool {
	businessModelsMu.RLock()
	defer businessModelsMu.RUnlock()
	return scopedTables[table]
}

// ScopedByOrg attaches the tenant context to the query. The condition itself is
// injected by the tenant plugin as an outer AND group, so chained .Or(...)
// clauses cannot escape it (a plain WHERE would).
//
// A zero orgID fails closed: the injected condition matches no rows.
//
// Raw() and Exec() carry no schema, so the tenant plugin cannot scope them:/n// raw SQL must never be used for tenant data.
func ScopedByOrg(db *gorm.DB, orgID uint) *gorm.DB {
	parent := context.Background()
	if db.Statement != nil && db.Statement.Context != nil {
		parent = db.Statement.Context
	}
	return db.WithContext(context.WithValue(parent, orgContextKey, orgID))
}

// crossTenantKeyT marks a query as an intentional cross-tenant lookup.
type crossTenantKeyT struct{}

var crossTenantKey = crossTenantKeyT{}

// WithoutTenantScope disables tenant filtering for a single query chain.
//
// It exists only for operations that are inherently cross-org: resolving the
// current user's memberships, accepting an invitation token, startup scans of
// per-organization infrastructure (deployed server groups), and system
// maintenance such as the log retention sweep. Every use must be obvious at
// the call site and read-only or system-scoped; request-driven tenant data
// must never use it.
func WithoutTenantScope(db *gorm.DB) *gorm.DB {
	parent := context.Background()
	if db.Statement != nil && db.Statement.Context != nil {
		parent = db.Statement.Context
	}
	return db.WithContext(context.WithValue(parent, crossTenantKey, true))
}

// isCrossTenant reports whether the statement opted out of tenant filtering.
func isCrossTenant(stmt *gorm.Statement) bool {
	if stmt.Context == nil {
		return false
	}
	v, _ := stmt.Context.Value(crossTenantKey).(bool)
	return v
}

// RequireOrgID fails fast when an org-scoped call has no organization.
func RequireOrgID(orgID uint) error {
	if orgID == 0 {
		return fmt.Errorf("organization id is required for tenant-scoped access")
	}
	return nil
}
