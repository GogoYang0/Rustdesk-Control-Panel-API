package store

import (
	"strings"

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
//  2. Caller conditions are rendered inside an explicit parenthesis group and
//     the tenant condition is ANDed outside of it. Chained .Or(...) calls and
//     raw SQL fragments containing OR therefore cannot widen the result set.
func registerTenantPlugin(db *gorm.DB) error {
	inject := func(tx *gorm.DB) {
		if tx.Statement == nil {
			return
		}
		// Resolve the queried table: an explicit .Table(...) wins over the model
		// schema, and aliases ("memberships AS m") must map back to the real name.
		table := resolveTable(tx.Statement)
		if table == "" || !tableIsScoped(table) {
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

		var caller []clause.Expression
		if w, ok := tx.Statement.Clauses["WHERE"].Expression.(clause.Where); ok {
			caller = append(caller, w.Exprs...)
		}

		var exprs []clause.Expression
		if !hasCtx || orgID == 0 {
			// Missing tenant context: match nothing, ignore caller conditions.
			exprs = []clause.Expression{clause.Expr{SQL: "1 = 0"}}
		} else {
			if len(caller) > 0 {
				exprs = append(exprs, parenGroup{exprs: caller})
			}
			exprs = append(exprs, clause.Expr{SQL: "organization_id = ?", Vars: []any{orgID}})
		}

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

// parenGroup renders the wrapped expressions inside one pair of parentheses.
// GORM has no grouping clause type, but a custom clause.Expression may render
// whatever it likes, and reusing clause.Where.Build keeps GORM's OR handling
// (single OrConditions joins with OR) intact.
type parenGroup struct {
	exprs []clause.Expression
}

// Build implements clause.Expression.
func (g parenGroup) Build(builder clause.Builder) {
	_ = builder.WriteByte('(')
	clause.Where{Exprs: g.exprs}.Build(builder)
	_ = builder.WriteByte(')')
}

// resolveTable returns the underlying table name of the current statement.
// Precedence: explicit table expression, explicit table name, model schema.
func resolveTable(stmt *gorm.Statement) string {
	if stmt.TableExpr != nil {
		if name := normalizeTableName(stmt.TableExpr.SQL); name != "" {
			return name
		}
	}
	if name := normalizeTableName(stmt.Table); name != "" {
		return name
	}
	if stmt.Schema != nil {
		return stmt.Schema.Table
	}
	return ""
}

// normalizeTableName strips aliases and quoting from a table reference.
func normalizeTableName(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "(") {
		return ""
	}
	upper := strings.ToUpper(s)
	if i := strings.Index(upper, " AS "); i > 0 {
		s = s[:i]
	} else if i := strings.IndexAny(s, " \t\n"); i > 0 {
		s = s[:i]
	}
	s = strings.Trim(s, "\"`[]")
	if i := strings.LastIndex(s, "."); i >= 0 {
		s = s[i+1:]
	}
	return strings.Trim(s, "\"`[]")
}
