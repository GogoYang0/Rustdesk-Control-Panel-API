package store

import (
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// registerTenantPlugin adds the organization condition to every query against a
// registered scoped table. Two guarantees:
//
//  1. Queries without a tenant context are rejected (fail closed), so a missing
//     org id can never widen a result set.
//  2. A top-level OR written by the caller cannot escape the tenant boundary:
//     GORM flattens chained WHERE/OR clauses, so such a statement is replaced by
//     a fail-closed condition instead of guessing at grouping. Callers that need
//     an internal disjunction must pass a nested group (clause.Group) themselves.
func registerTenantPlugin(db *gorm.DB) error {
	inject := func(tx *gorm.DB) {
		if tx.Statement == nil || tx.Statement.Schema == nil {
			return
		}
		if !tableIsScoped(tx.Statement.Schema.Table) {
			return
		}
		if tx.Statement.Context == nil {
			return
		}
		rawOrg := tx.Statement.Context.Value(orgContextKey)
		if rawOrg == nil {
			return
		}
		orgID, _ := rawOrg.(uint)

		var exprs []clause.Expression
		if w, ok := tx.Statement.Clauses["WHERE"].Expression.(clause.Where); ok {
			exprs = append(exprs, w.Exprs...)
		}

		var tenantExpr clause.Expression
		switch {
		case orgID == 0:
			// No tenant context: match nothing, ignore caller conditions entirely.
			tenantExpr = clause.Expr{SQL: "1 = 0"}
			exprs = nil
		case hasTopLevelOr(exprs):
			// Cannot be grouped safely; fail closed rather than leak rows.
			tenantExpr = clause.Expr{SQL: "1 = 0"}
			exprs = nil
		default:
			tenantExpr = clause.Expr{SQL: "organization_id = ?", Vars: []any{orgID}}
		}

		exprs = append(exprs, tenantExpr)
		tx.Statement.Clauses["WHERE"] = clause.Clause{
			Name:       "WHERE",
			Expression: clause.Where{Exprs: []clause.Expression{clause.AndConditions{Exprs: exprs}}},
		}
	}

	if err := db.Callback().Query().Before("gorm:query").Register("panel:tenant_scope", inject); err != nil {
		return err
	}
	if err := db.Callback().Update().Before("gorm:update").Register("panel:tenant_scope", inject); err != nil {
		return err
	}
	if err := db.Callback().Delete().Before("gorm:delete").Register("panel:tenant_scope", inject); err != nil {
		return err
	}
	return nil
}

// hasTopLevelOr reports whether the caller's conditions contain a disjunction
// that GORM would flatten into the shared WHERE clause.
func hasTopLevelOr(exprs []clause.Expression) bool {
	for _, e := range exprs {
		switch v := e.(type) {
		case clause.OrConditions:
			return true
		case clause.AndConditions:
			if hasTopLevelOr(v.Exprs) {
				return true
			}
		}
	}
	return false
}
