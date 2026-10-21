package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"

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

// ErrTransferAuditMissing reports a tenant transfer attempted without a
// registered recorder.
var ErrTransferAuditMissing = errors.New("tenant scope: no transfer recorder registered, refusing an unaudited tenant move")

// tenantColumn is the column every scoped table carries.
const tenantColumn = "organization_id"

type tenantTransferKeyT struct{}

var tenantTransferKey = tenantTransferKeyT{}

// TransferAudit is the audit context of a deliberate tenant transfer. The store
// cannot write the entry itself (audit imports store, so the reverse would be a
// cycle), so the caller states who moved what and why, and the registered
// recorder writes it inside the same transaction.
type TransferAudit struct {
	// OrganizationID is the organization the rows are leaving.
	OrganizationID uint
	// ActorUserID is the human or service responsible. Zero means "system".
	ActorUserID uint
	// Reason describes the repair. Required: an unexplained tenant move is the
	// thing this guard exists to prevent.
	Reason string
}

func (a TransferAudit) validate() error {
	if a.OrganizationID == 0 {
		return errors.New("tenant scope: transfer audit requires the source organization")
	}
	if strings.TrimSpace(a.Reason) == "" {
		return errors.New("tenant scope: transfer audit requires a reason")
	}
	return nil
}

// TransferRecorder writes the audit entry for a transfer inside its transaction.
type TransferRecorder func(tx *gorm.DB, aud TransferAudit) error

var (
	transferRecorderMu sync.RWMutex
	transferRecorder   TransferRecorder
)

// RegisterTransferRecorder installs the audit writer used by
// AllowTenantTransfer. cmd/server wires it to the audit package; tests use a
// fake. There is deliberately no default: an unaudited transfer is refused.
func RegisterTransferRecorder(r TransferRecorder) {
	transferRecorderMu.Lock()
	defer transferRecorderMu.Unlock()
	transferRecorder = r
}

func currentTransferRecorder() TransferRecorder {
	transferRecorderMu.RLock()
	defer transferRecorderMu.RUnlock()
	return transferRecorder
}

// AllowTenantTransfer runs fn with permission to reassign the tenant column, then
// records why it happened.
//
// The permission exists only for the duration of fn, so it cannot be stored and
// reused. It is not an authority boundary — anyone who can call this could also
// call it twice — it is a review-and-audit boundary: every transfer names its
// source organization, its actor and a reason, and produces an audit row in the
// same transaction.
//
// A transfer with no registered recorder, no organization or no reason fails
// before fn runs. Nothing in the request path should need this: a row belongs to
// the organization that created it, and "moving" it is a data repair, not a
// feature.
func AllowTenantTransfer(db *gorm.DB, aud TransferAudit, fn func(tx *gorm.DB) error) error {
	if err := aud.validate(); err != nil {
		return err
	}
	recorder := currentTransferRecorder()
	if recorder == nil {
		return ErrTransferAuditMissing
	}
	parent := context.Background()
	if db.Statement != nil && db.Statement.Context != nil {
		parent = db.Statement.Context
	}
	tx := db.WithContext(context.WithValue(parent, tenantTransferKey, true))
	// The move and its audit row must commit or fail together. Without this
	// transaction the update autocommits, a recorder error leaves the row moved
	// but unaudited, and the caller only sees an error for a change that already
	// happened.
	return tx.Transaction(func(inner *gorm.DB) error {
		if err := fn(inner); err != nil {
			return err
		}
		return recorder(inner, aud)
	})
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

// guardUpsertTenantColumn rejects an INSERT ... ON CONFLICT DO UPDATE that
// reassigns the tenant column.
//
// A batch Save of a slice compiles to exactly that: GORM turns it into an upsert
// through the create chain, so the update guard never sees it and a "save these
// rows" call could move them between tenants.
func guardUpsertTenantColumn(tx *gorm.DB) {
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
	conflict, ok := tx.Statement.Clauses["ON CONFLICT"]
	if !ok {
		return
	}
	onConflict, ok := conflict.Expression.(clause.OnConflict)
	if !ok {
		return
	}
	// UpdateAll is the shape Save produces: GORM expands it to every column while
	// building the SQL, so the assignment list is still empty here.
	if onConflict.UpdateAll {
		_ = tx.AddError(fmt.Errorf("%w (table %s, column %s in upsert)", ErrTenantColumnWrite, table, tenantColumn))
		return
	}
	if _, found := setClauseTenantColumn(onConflict.DoUpdates); found {
		_ = tx.AddError(fmt.Errorf("%w (table %s, column %s in upsert)", ErrTenantColumnWrite, table, tenantColumn))
		return
	}
	// Columns is the conflict TARGET (the key that decides whether a row already
	// exists), not the assignment list: a business key containing organization_id
	// is normal and must stay allowed. Only the DO UPDATE payload matters.
}

// assignsTenantColumn reports whether the statement's update payload includes
// the tenant column, and the column name as it appeared.
//
// The SET clause is not built yet when this runs (gorm:update does that), so the
// payload is inspected from Dest, mirroring GORM's own reflection: any depth of
// pointer, then struct, slice or map.
func assignsTenantColumn(stmt *gorm.Statement) (string, bool) {
	if c, ok := stmt.Clauses["SET"]; ok {
		if column, found := setClauseTenantColumn(c.Expression); found {
			return column, true
		}
	}
	return payloadTenantColumn(stmt, reflect.ValueOf(stmt.Dest))
}

// payloadTenantColumn walks an update payload looking for the tenant column.
func payloadTenantColumn(stmt *gorm.Statement, value reflect.Value) (string, bool) {
	// Bound the dereference walk: GORM itself does not recurse forever, and an
	// unbounded loop on a malformed payload would hang the callback.
	for i := 0; i < 8 && value.IsValid() && value.Kind() == reflect.Pointer; i++ {
		if value.IsNil() {
			return "", false
		}
		value = value.Elem()
	}
	if !value.IsValid() {
		return "", false
	}

	switch value.Kind() {
	case reflect.Map:
		// Map updates carry column names as keys. Omit still means "not written".
		if omitted(stmt, tenantColumn) {
			return "", false
		}
		iter := value.MapRange()
		for iter.Next() {
			key := iter.Key()
			if key.Kind() != reflect.String {
				continue
			}
			if isTenantColumnKey(stmt, key.String()) {
				return key.String(), true
			}
		}
		return "", false
	case reflect.Slice, reflect.Array:
		// Save(&[]T{...}) is a legal batch update; every element has to be checked.
		for i := 0; i < value.Len(); i++ {
			if column, found := payloadTenantColumn(stmt, value.Index(i)); found {
				return column, true
			}
		}
		return "", false
	case reflect.Struct:
		return structTenantColumn(stmt, value)
	default:
		return "", false
	}
}

// structTenantColumn reports whether a struct payload writes the tenant column.
func structTenantColumn(stmt *gorm.Statement, value reflect.Value) (string, bool) {
	if stmt.Schema == nil {
		return "", false
	}
	field, ok := stmt.Schema.FieldsByDBName[tenantColumn]
	if !ok || field.FieldType.Kind() == reflect.Struct {
		return "", false
	}
	if omitted(stmt, field.Name) {
		return "", false
	}
	if !selected(stmt, field.Name) {
		return "", false
	}
	fieldValue := value.FieldByName(field.Name)
	if !fieldValue.IsValid() {
		return "", false
	}
	// Without an explicit Select GORM skips zero values, so an unset
	// OrganizationID is simply not part of the write. With Select("*") or
	// Select("organization_id") the column IS written, and a zero value would
	// hide the row from every tenant — that must be rejected.
	if fieldValue.IsZero() && !explicitSelect(stmt) {
		return "", false
	}
	return tenantColumn, true
}

// explicitSelect reports whether the caller asked for the tenant column by name
// (or asked for all columns), as opposed to relying on GORM's "all non-zero
// fields" default.
func explicitSelect(stmt *gorm.Statement) bool {
	for _, sel := range stmt.Selects {
		if sel == "*" || normalizeColumn(sel) == tenantColumn {
			return true
		}
		if stmt.Schema != nil {
			if field := stmt.Schema.LookUpField(sel); field != nil && field.DBName == tenantColumn {
				return true
			}
		}
	}
	return false
}

// omitted reports whether the field is excluded from the write.
func omitted(stmt *gorm.Statement, fieldName string) bool {
	for _, omit := range stmt.Omits {
		if normalizeColumn(omit) == tenantColumn {
			return true
		}
		if stmt.Schema != nil {
			if field := stmt.Schema.LookUpField(omit); field != nil && field.Name == fieldName {
				return true
			}
		}
	}
	return false
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
