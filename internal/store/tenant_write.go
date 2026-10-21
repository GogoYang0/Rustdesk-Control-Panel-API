package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrTenantColumnWrite reports an update that tried to change the tenant column.
//
// The tenant plugin scopes the WHERE clause, which stops a request from reading
// or writing another organization's rows. It says nothing about *assigning* the
// tenant column: Update("organization_id", other) keeps the WHERE inside the
// caller's organization and hands the row to a different one (issue #42).
var ErrTenantColumnWrite = errors.New("tenant scope: update must not change organization_id")

// tenantColumn is the column every scoped table carries.
const tenantColumn = "organization_id"

type tenantTransferKeyT struct{}

var tenantTransferKey = tenantTransferKeyT{}

// AllowTenantTransfer marks a single statement as a deliberate tenant move.
//
// It is the only way through the write guard, so every transfer is visible at
// the call site and in review. Nothing in the request path should need it: a row
// belongs to the organization that created it, and "moving" it is a data repair,
// not a feature.
func AllowTenantTransfer(db *gorm.DB) *gorm.DB {
	parent := context.Background()
	if db.Statement != nil && db.Statement.Context != nil {
		parent = db.Statement.Context
	}
	return db.WithContext(context.WithValue(parent, tenantTransferKey, true))
}

func isTenantTransfer(stmt *gorm.Statement) bool {
	if stmt == nil || stmt.Context == nil {
		return false
	}
	v, _ := stmt.Context.Value(tenantTransferKey).(bool)
	return v
}

// guardTenantColumnWrite rejects an UPDATE that assigns the tenant column.
//
// It deliberately does NOT honour WithoutTenantScope: opting out of the WHERE
// filter for maintenance reads is not permission to move rows between tenants.
// Only AllowTenantTransfer is.
func guardTenantColumnWrite(tx *gorm.DB) {
	if tx.Statement == nil {
		return
	}
	table, resolved := resolveTable(tx.Statement)
	if !resolved || !tableIsScoped(table) {
		return
	}
	if isTenantTransfer(tx.Statement) {
		return
	}
	column, ok := assignsTenantColumn(tx.Statement)
	if !ok {
		return
	}
	_ = tx.AddError(fmt.Errorf("%w (table %s, column %s)", ErrTenantColumnWrite, table, column))
}

// assignsTenantColumn reports whether the update payload includes the tenant
// column, and the column name as it appeared.
//
// The SET clause is not built yet when this runs (gorm:update does that), so the
// payload is inspected from Dest, plus an already-built SET clause if some
// earlier callback produced one.
func assignsTenantColumn(stmt *gorm.Statement) (string, bool) {
	if c, ok := stmt.Clauses["SET"]; ok {
		if column, found := setClauseTenantColumn(c.Expression); found {
			return column, true
		}
	}

	if dest, ok := stmt.Dest.(map[string]any); ok {
		for key := range dest {
			if isTenantColumnKey(stmt, key) {
				return key, true
			}
		}
		return "", false
	}
	if stmt.Dest == nil || stmt.Schema == nil {
		return "", false
	}

	// Struct payload (Updates with a struct, or Save): only selected fields are
	// written, and a zero value is skipped by GORM, so an unset OrganizationID
	// must not trip the guard.
	field, ok := stmt.Schema.FieldsByDBName[tenantColumn]
	if !ok || field.FieldType.Kind() == reflect.Struct {
		return "", false
	}
	if !selected(stmt, field.Name) {
		return "", false
	}
	value := reflect.ValueOf(stmt.Dest)
	for value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return "", false
		}
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return "", false
	}
	fieldValue := value.FieldByName(field.Name)
	if !fieldValue.IsValid() || fieldValue.IsZero() {
		return "", false
	}
	return tenantColumn, true
}

// setClauseTenantColumn looks for the tenant column in a prebuilt SET clause.
func setClauseTenantColumn(expr clause.Expression) (string, bool) {
	if set, ok := expr.(clause.Set); ok {
		for _, a := range set {
			if normalizeColumn(a.Column.Name) == tenantColumn {
				return a.Column.Name, true
			}
		}
	}
	return "", false
}

// isTenantColumnKey resolves a map key against the schema when possible, and
// falls back to a normalised name comparison (raw column names are allowed).
func isTenantColumnKey(stmt *gorm.Statement, key string) bool {
	if stmt.Schema != nil {
		if field := stmt.Schema.LookUpField(key); field != nil {
			return field.DBName == tenantColumn
		}
	}
	return normalizeColumn(key) == tenantColumn
}

// selected reports whether a struct field will be written. With no explicit
// Select everything non-zero is written; with Select only the listed columns are.
func selected(stmt *gorm.Statement, fieldName string) bool {
	if len(stmt.Selects) == 0 {
		return true
	}
	for _, sel := range stmt.Selects {
		if sel == "*" {
			return true
		}
		if stmt.Schema != nil {
			if field := stmt.Schema.LookUpField(sel); field != nil {
				if field.Name == fieldName {
					return true
				}
				continue
			}
		}
		if normalizeColumn(sel) == tenantColumn {
			return true
		}
	}
	return false
}

// normalizeColumn strips quoting, table prefixes and case from a column name.
func normalizeColumn(raw string) string {
	s := strings.TrimSpace(raw)
	if i := strings.LastIndex(s, "."); i >= 0 {
		s = s[i+1:]
	}
	s = strings.Trim(s, "\"`[]")
	return strings.ToLower(s)
}
