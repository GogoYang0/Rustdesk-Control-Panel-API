package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// When the handler records its domain audit entry inside the entity
// transaction, the middleware must skip its fallback record: one auditable
// request yields exactly one audit row (#19).
func TestMiddleware_SkipsWhenDomainRecorded(t *testing.T) {
	h := newHarnessWith(t, func(d *api.Deps) {
		d.Auditor = audit.NewGormAuditor(d.DB)
	})
	h.seedUser(t, "aud-owner@example.com", "password123")
	token := h.login(t, "aud-owner@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "aud-org"}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))
	scoped := store.ScopedByOrg(h.db.DB, uint(orgResp.Data.Id))

	var middlewareRows, domainRows int64
	require.NoError(t, scoped.Model(&model.AuditLog{}).
		Where("action = ?", "POST /api/v1/orgs").
		Count(&middlewareRows).Error)
	require.NoError(t, scoped.Model(&model.AuditLog{}).
		Where("action = ?", "organization.create").
		Count(&domainRows).Error)
	require.Zero(t, middlewareRows, "the middleware must skip its fallback when the domain recorded")
	require.EqualValues(t, 1, domainRows, "the domain record must be the only audit row")

	// The domain row carries the created organization as target.
	var row model.AuditLog
	require.NoError(t, scoped.Where("action = ?", "organization.create").First(&row).Error)
	require.Equal(t, "organization", row.TargetType)
}

// Without a TxRecorder (the default harness wires audit.Nop) the middleware
// fallback still records, so behaviour is unchanged for non-transactional
// auditors.
func TestMiddleware_FallbackWithoutTxRecorder(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "fallback-owner@example.com", "password123")
	token := h.login(t, "fallback-owner@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "fb-org"}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	// The Nop auditor discards entries, so nothing lands in the table; the
	// assertion is that the request flow itself is unaffected.
	var rows int64
	require.NoError(t, h.db.DB.Model(&model.AuditLog{}).Count(&rows).Error)
	require.Zero(t, rows)
}
