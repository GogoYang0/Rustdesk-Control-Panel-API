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
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/session"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

// spyAuditor counts middleware fallback Record calls; the inner auditor
// keeps the real persistence behaviour.
type spyAuditor struct {
	inner   audit.Auditor
	records int
	entries []audit.Entry
}

func (s *spyAuditor) Record(ctx context.Context, e audit.Entry) error {
	s.records++
	s.entries = append(s.entries, e)
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
// Record was called exactly once for the auditable request. Tenant creation
// now refuses to commit without a transactional auditor, so a read is used as
// the vehicle — the middleware records every request that reaches it.
func TestMiddleware_FallbackWithoutTxRecorder(t *testing.T) {
	spy := &spyAuditor{inner: audit.Nop{}}
	h := newHarnessWith(t, func(d *api.Deps) {
		d.Auditor = spy
		// A non-TxRecorder auditor plus no explicit Tickets is refused by the
		// dependency boundary; this test exercises the middleware fallback, so
		// it wires a real transactional recorder into the session service and
		// keeps the spy on the middleware path only.
		d.Tickets = session.NewService(d.DB, audit.NewGormAuditor(d.DB), nil)
	})
	h.seedUser(t, "fallback-owner@example.com", "password123")
	token := h.login(t, "fallback-owner@example.com", "password123")

	w := h.do(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"email": "fallback-owner@example.com", "password": "password123",
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	recordsAfterLogin := spy.records

	w = h.do(t, http.MethodGet, "/api/v1/orgs", nil, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	require.Equal(t, recordsAfterLogin+1, spy.records,
		"the middleware fallback must record exactly once for the auditable request")
}

// A compat mutation sets its own context keys ("compat.*") and never the
// management keys: without reading them the fallback attributes every client
// address-book change to organization zero, which the persistent auditor
// silently drops. The fallback must carry the compat actor and organization.
func TestMiddleware_AttributesCompatMutations(t *testing.T) {
	// Tenant creation requires a transactional auditor (fail closed), so the
	// spy implements TxRecorder too; the compat write is still audited through
	// the middleware fallback, which is what this test measures.
	spy := &spyTxAuditor{}
	h := newHarnessWith(t, func(d *api.Deps) {
		ga := audit.NewGormAuditor(d.DB)
		spy.inner = ga
		spy.tx = ga
		d.Auditor = spy
		d.Tickets = session.NewService(d.DB, ga, nil)
	})
	h.seedUser(t, "compat-audit@example.com", "password123")

	// Management side: create the organization and make the user a member.
	adminToken := h.login(t, "compat-audit@example.com", "password123")
	w := h.do(t, http.MethodPost, "/api/v1/orgs", map[string]string{"name": "compat-audit-org"}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var orgResp struct {
		Data struct {
			Id int64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &orgResp))

	// Compat side: the native client logs in and pushes a personal book change.
	w = h.do(t, http.MethodPost, "/api/login", map[string]string{
		"username": "compat-audit@example.com", "password": "password123",
		"id": "123456789", "uuid": "compat-audit-uuid",
	}, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var compatLogin struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &compatLogin))
	require.NotEmpty(t, compatLogin.AccessToken)

	w = h.do(t, http.MethodPost, "/api/ab/personal", map[string]any{
		"data": `{"tags":["ops"],"peers":[{"id":"111111","alias":"alpha"}],"tag_colors":"{}"}`,
		"hash": "",
	}, compatLogin.AccessToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var compatEntry *audit.Entry
	for i := range spy.entries {
		// The management org-creation request is audited correctly; the entry
		// under test is the one the compat write produces.
		if spy.entries[i].Action == "POST /api/ab/personal" {
			compatEntry = &spy.entries[i]
		}
	}
	require.NotNil(t, compatEntry, "the compat mutation must produce an audit entry")
	require.Equal(t, uint(orgResp.Data.Id), compatEntry.OrganizationID,
		"the compat organization must be carried into the audit entry")
	require.NotZero(t, compatEntry.ActorUserID, "the compat actor must be attributed")
}
