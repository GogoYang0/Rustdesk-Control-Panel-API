package store

import (
	"errors"
	"fmt"
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
		if isCrossTenant(tx.Statement) {
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

		// Resolve the queried table: an explicit .Table(...) wins over the model
		// schema, and aliases ("memberships AS m") must map back to the real name.
		table, resolved := resolveTable(tx.Statement)
		if !resolved {
			// A derived table cannot be scoped. Reject it unconditionally: a
			// missing tenant context must not turn into a full-table read.
			_ = tx.AddError(errDerivedTableNotScopable)
			return
		}
		// A JOIN that touches a scoped table cannot be scoped reliably (aliases,
		// ON clauses); reject instead of guessing.
		for _, j := range tx.Statement.Joins {
			// GORM keeps the raw clause in Name for string joins and in
			// Expression for structured ones; Conds may hold extra fragments.
			parts := []string{j.Name, expressionSQL(j.Expression)}
			for _, c := range j.Conds {
				if str, ok := c.(string); ok {
					parts = append(parts, str)
				}
			}
			sql := strings.Join(parts, " ")
			if strings.TrimSpace(sql) == "" {
				continue
			}
			lower := strings.ToLower(sql)
			for _, scoped := range scopedTableNames() {
				if containsWord(lower, strings.ToLower(scoped)) {
					_ = tx.AddError(fmt.Errorf("tenant scope: join on scoped table %q is not supported", scoped))
					return
				}
			}
		}
		if table == "" || !tableIsScoped(table) {
			return
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
		// The write guard runs first: rejecting the statement before the
		// scope injection means nothing downstream can act on a payload that
		// reassigns the tenant column.
		{db.Callback().Update().Before("gorm:update").Register},
		{db.Callback().Delete().Before("gorm:delete").Register},
	}
	if err := db.Callback().Update().Before("gorm:update").
		Register("panel:tenant_write_guard", guardTenantColumnWrite); err != nil {
		return err
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
func resolveTable(stmt *gorm.Statement) (string, bool) {
	if stmt.TableExpr != nil {
		raw := stmt.TableExpr.SQL
		if strings.HasPrefix(strings.TrimSpace(raw), "(") {
			return "", false
		}
		if name := normalizeTableName(raw); name != "" {
			return name, true
		}
	}
	if name := normalizeTableName(stmt.Table); name != "" {
		return name, true
	}
	if stmt.Schema != nil {
		return stmt.Schema.Table, true
	}
	return "", true
}

// errDerivedTableNotScopable rejects statements whose table cannot be resolved.
var errDerivedTableNotScopable = errors.New("tenant scope: derived table expressions are not supported on scoped tables")

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

func expressionSQL(expr clause.Expression) string {
	switch v := expr.(type) {
	case clause.Expr:
		return v.SQL
	case clause.Join:
		return expressionSQL(v.Expression)
	}
	return ""
}

func scopedTableNames() []string {
	businessModelsMu.RLock()
	defer businessModelsMu.RUnlock()
	names := make([]string, 0, len(scopedTables))
	for name := range scopedTables {
		names = append(names, name)
	}
	return names
}

// containsWord reports whether word appears in s delimited by non-identifier
// characters, so "memberships" does not match "memberships_audit".
func containsWord(s, word string) bool {
	for i := 0; ; i++ {
		idx := strings.Index(s[i:], word)
		if idx < 0 {
			return false
		}
		start := i + idx
		end := start + len(word)
		beforeOK := start == 0 || !isIdentChar(s[start-1])
		afterOK := end == len(s) || !isIdentChar(s[end])
		if beforeOK && afterOK {
			return true
		}
		i = start + 1
		if i >= len(s) {
			return false
		}
	}
}

func isIdentChar(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}
