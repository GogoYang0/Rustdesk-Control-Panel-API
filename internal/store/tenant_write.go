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
	"gorm.io/gorm/schema"
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
// The permission is bound to aud.OrganizationID: statements inside fn must be
// scoped with ScopedByOrg(tx, aud.OrganizationID), and WithoutTenantScope is not
// accepted. A transfer that names one organization while writing another is
// rejected, because an audit entry pointing at the wrong source is worse than a
// missing one.
//
// The statements inside fn must be updates, not upserts: ON CONFLICT matching
// cannot be tenant-scoped (MySQL matches any unique key), so an upsert could
// reach another organization's row even with a correct audit.
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
	// The context carries the source organization, not a bare "transfer
	// allowed" flag: the guard can then refuse a statement aimed at a different
	// organization, which is what keeps the audit entry's source honest.
	tx := db.WithContext(context.WithValue(parent, tenantTransferKey, aud.OrganizationID))
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

// isTenantTransfer reports whether the statement is covered by the transfer
// authorisation in force.
//
// Being inside fn is not enough: the statement must also be scoped to exactly
// the organization the audit names. Otherwise AllowTenantTransfer(aud{OrgB})
// could move org A's rows and record the move against org B — an audit entry
// that is not merely missing but wrong, which is worse, because it looks
// authoritative.
//
// WithoutTenantScope is deliberately excluded: widening one repair into an
// unscoped sweep is not a transfer, and the permission must not be usable that
// way.
func isTenantTransfer(stmt *gorm.Statement) bool {
	_, ok := authorisedTransferOrg(stmt)
	return ok
}

// authorisedTransferOrg returns the organization a transfer authorises, when the
// statement is covered by it.
func authorisedTransferOrg(stmt *gorm.Statement) (uint, bool) {
	if stmt == nil || stmt.Context == nil {
		return 0, false
	}
	transferOrg, ok := stmt.Context.Value(tenantTransferKey).(uint)
	if !ok || transferOrg == 0 {
		return 0, false
	}
	if isCrossTenant(stmt) {
		return 0, false
	}
	scopedOrg, ok := stmt.Context.Value(orgContextKey).(uint)
	if !ok || scopedOrg != transferOrg {
		return 0, false
	}
	return transferOrg, true
}

// upsertWriteError explains why an upsert may not assign the tenant column.
//
// This is refused even inside an authorised transfer: conflict matching happens
// before any WHERE exists, so the row the INSERT collides with is decided by
// unique keys alone. A globally unique key (a ticket digest, a primary key) can
// therefore land on another organization's row, and MySQL cannot narrow it —
// ON DUPLICATE KEY UPDATE fires on any unique key, ignoring the conflict target
// GORM emits. The portable rule is to use UPDATE, where the tenant condition
// exists, and that is what the message tells the caller.
func upsertWriteError(stmt *gorm.Statement, table string) error {
	const hint = "conflict matching ignores the tenant condition, and MySQL matches any unique key, so the conflict target cannot make this safe; use an UPDATE inside ScopedByOrg"
	if _, ok := authorisedTransferOrg(stmt); ok {
		return fmt.Errorf("%w (table %s, column %s in upsert; a tenant transfer must be an UPDATE: %s)", ErrTenantColumnWrite, table, tenantColumn, hint)
	}
	return fmt.Errorf("%w (table %s, column %s in upsert: %s)", ErrTenantColumnWrite, table, tenantColumn, hint)
}

// tenantWriteError explains a rejected write. The mismatch case is worth naming
// explicitly: it is the one where the caller did almost everything right.
func tenantWriteError(stmt *gorm.Statement, table, where string) error {
	if stmt != nil && stmt.Context != nil {
		if transferOrg, ok := stmt.Context.Value(tenantTransferKey).(uint); ok && transferOrg != 0 {
			scopedOrg, _ := stmt.Context.Value(orgContextKey).(uint)
			if isCrossTenant(stmt) {
				return fmt.Errorf("%w (table %s, %s; transfer authorised for organization %d but the statement is not scoped to it)", ErrTenantColumnWrite, table, where, transferOrg)
			}
			return fmt.Errorf("%w (table %s, %s; transfer authorised for organization %d but the statement is scoped to %d)", ErrTenantColumnWrite, table, where, transferOrg, scopedOrg)
		}
	}
	return fmt.Errorf("%w (table %s, %s)", ErrTenantColumnWrite, table, where)
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
	_ = tx.AddError(tenantWriteError(tx.Statement, table, "column "+column))
}

// guardUpsertTenantColumn rejects an INSERT ... ON CONFLICT DO UPDATE that
// reassigns the tenant column.
//
// A batch Save of a slice compiles to exactly that: GORM turns it into an upsert
// through the create chain, so the update guard never sees it and a "save these
// rows" call could move them between tenants.
//
// It rejects even inside an authorised tenant transfer. A transfer is a repair
// of existing rows, and an upsert is not a safe spelling for it: the conflict is
// resolved by unique keys before any tenant condition applies.
func guardUpsertTenantColumn(tx *gorm.DB) {
	if tx.Statement == nil {
		return
	}
	table, resolved := resolveTable(tx.Statement)
	if !resolved || !tableIsScoped(table) {
		return
	}
	// No transfer exemption here, deliberately: see upsertWriteError.
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
		_ = tx.AddError(upsertWriteError(tx.Statement, table))
		return
	}
	if _, found := setClauseTenantColumn(onConflict.DoUpdates); found {
		_ = tx.AddError(upsertWriteError(tx.Statement, table))
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
	if stmt.Schema == nil || stmt.DB == nil || !value.IsValid() || value.Kind() != reflect.Struct {
		return "", false
	}
	// GORM re-parses Dest when Model and Dest are heterogeneous, so the guard
	// must inspect the payload's own schema: resolving the field from the
	// Model schema and reading it from the Dest value by the Model's field
	// name silently misses DTOs whose org column lives under a different
	// field name — FieldByName returns an invalid value and the write would
	// sail through (CWE-863). schema.Parse is cached by GORM, so the
	// per-call cost is a map lookup.
	payloadSchema, err := schema.Parse(value.Interface(), &sync.Map{}, stmt.NamingStrategy)
	if err != nil {
		// Unparseable payload: fail closed — refuse the write instead of
		// waving it through uninspected.
		return tenantColumn, true
	}
	field, ok := payloadSchema.FieldsByDBName[tenantColumn]
	if !ok || field.FieldType.Kind() == reflect.Struct {
		return "", false
	}
	if omitted(stmt, field.Name) {
		return "", false
	}
	if !selectedTenantColumn(stmt) {
		return "", false
	}
	fieldValue := field.ReflectValueOf(stmt.Context, value)
	if !fieldValue.IsValid() {
		return "", false
	}
	// A payload that merely echoes the scoped organization id back (a loaded
	// row saved through ScopedByOrg) is not a transfer: it sends the row to
	// the tenant it already belongs to. WithoutTenantScope carries no org id
	// and keeps refusing every tenant-column write.
	if scopedOrg, ok := stmt.Context.Value(orgContextKey).(uint); ok && scopedOrg != 0 && !isCrossTenant(stmt) {
		if fieldValue.CanUint() && uint(fieldValue.Uint()) == scopedOrg {
			return "", false
		}
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

// selectedTenantColumn reports whether the statement's explicit Select (if
// any) includes the tenant column. The comparison is by database column name:
// with a heterogeneous Dest the payload field can carry the org column under
// a different Go name (Org -> organization_id), and matching the payload's
// field name against the Model's would skip the check — Select("OrganizationID")
// must select the tenant column no matter what either schema calls its field.
func selectedTenantColumn(stmt *gorm.Statement) bool {
	if len(stmt.Selects) == 0 {
		return true
	}
	for _, sel := range stmt.Selects {
		if sel == "*" {
			return true
		}
		if stmt.Schema != nil {
			if field := stmt.Schema.LookUpField(sel); field != nil {
				if field.DBName == tenantColumn {
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
