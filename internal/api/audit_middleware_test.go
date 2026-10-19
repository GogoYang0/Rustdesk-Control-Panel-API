package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// spyAuditor counts middleware fallback Record calls; the inner auditor
// keeps the real persistence behaviour.
type spyAuditor struct {
	inner   audit.Auditor
	records int
}

func (s *spyAuditor) Record(ctx context.Context, e audit.Entry) error {
	s.records++
	return s.inner.Record(ctx, e)
}

// spyTxAuditor also implements audit.TxRecorder (delegating to a real
// GormAuditor), so the domain-recorded path of the handlers runs.
type spyTxAuditor struct {
	spyAuditor
	tx audit.TxRecorder
}

func (s *spyTxAuditor) RecordTx(tx *gorm.DB, e audit.Entry) error {
	return s.tx.RecordTx(tx, e)
}

// When the handler records its domain audit entry inside the entity
// transaction, the middleware must skip its fallback record: one auditable
// request yields exactly one audit row and no fallback call (#19).
func TestMiddleware_SkipsWhenDomainRecorded(t *testing.T) {
	spy := &spyTxAuditor{}
	h := newHarnessWith(t, func(d *api.Deps) {
		ga := audit.NewGormAuditor(d.DB)
		spy.inner = ga
		spy.tx = ga
		d.Auditor = spy
	})
	h.seedUser(t, "aud-owner@example.com", "password123")
	token := h.login(t, "aud-owner@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"email": "aud-owner@example.com", "password": "password123",
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	// The login request already produced one fallback call (its entry is
	// org-less and therefore not persisted); measure the delta from here.
	recordsAfterLogin := spy.records

	w = h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "aud-org"}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))
	scoped := store.ScopedByOrg(h.db.DB, uint(orgResp.Data.Id))

	// The middleware never invoked its fallback record for this request.
	require.Equal(t, recordsAfterLogin, spy.records,
		"the middleware must skip its fallback when the domain recorded")

	var domainRows int64
	require.NoError(t, scoped.Model(&model.AuditLog{}).
		Where("action = ?", "organization.create").
		Count(&domainRows).Error)
	require.EqualValues(t, 1, domainRows, "the domain record must be the only audit row")

	// The domain row carries the created organization as target.
	var row model.AuditLog
	require.NoError(t, scoped.Where("action = ?", "organization.create").First(&row).Error)
	require.Equal(t, "organization", row.TargetType)
}

// Without a TxRecorder the middleware fallback still runs: the spy proves
// Record was called exactly once for the auditable request.
func TestMiddleware_FallbackWithoutTxRecorder(t *testing.T) {
	spy := &spyAuditor{inner: audit.Nop{}}
	h := newHarnessWith(t, func(d *api.Deps) {
		d.Auditor = spy
	})
	h.seedUser(t, "fallback-owner@example.com", "password123")
	token := h.login(t, "fallback-owner@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"email": "fallback-owner@example.com", "password": "password123",
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	recordsAfterLogin := spy.records

	w = h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "fb-org"}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	require.Equal(t, recordsAfterLogin+1, spy.records,
		"the middleware fallback must record exactly once for the auditable request")
}
