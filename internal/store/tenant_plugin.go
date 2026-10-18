package store

import (
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// registerTenantPlugin adds the organization condition to every query against a
// registered scoped table. It is attached to the Query, Row, Update and Delete
// callback chains, so Find and Scan both go through it.
//
// Guarantees:
//  1. No tenant context on a scoped table fails closed (WHERE 1 = 0), so a
//     forgotten ScopedByOrg call cannot read every tenant's rows.
//  2. A top-level OR written by the caller cannot escape the tenant boundary:
//     GORM flattens chained WHERE/OR clauses and offers no grouping primitive,
//     so such a statement fails closed instead of guessing at syntax.
func registerTenantPlugin(db *gorm.DB) error {
	inject := func(tx *gorm.DB) {
		if tx.Statement == nil || tx.Statement.Schema == nil {
			return
		}
		if !tableIsScoped(tx.Statement.Schema.Table) {
			return
		}

		var orgID uint
		hasCtx := false
		if tx.Statement.Context != nil {
			if raw := tx.Statement.Context.Value(orgContextKey); raw != nil {
				orgID, _ = raw.(uint)
				hasCtx = true
			}
		}

		var exprs []clause.Expression
		if w, ok := tx.Statement.Clauses["WHERE"].Expression.(clause.Where); ok {
			exprs = append(exprs, w.Exprs...)
		}

		var tenantExpr clause.Expression
		switch {
		case !hasCtx || orgID == 0:
			// Missing tenant context: match nothing, ignore caller conditions.
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

	chains := []struct {
		register func(name string, fn func(*gorm.DB)) error
	}{
		{db.Callback().Query().Before("gorm:query").Register},
		{db.Callback().Row().Before("gorm:row").Register},
		{db.Callback().Update().Before("gorm:update").Register},
		{db.Callback().Delete().Before("gorm:delete").Register},
	}
	for _, c := range chains {
		if err := c.register("panel:tenant_scope", inject); err != nil {
			return err
		}
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
