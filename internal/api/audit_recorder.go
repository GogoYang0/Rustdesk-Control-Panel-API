package api

import (
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
)

// discardRecorder records nothing.
//
// It exists for the one case the ticket service cannot handle silently: an
// injected auditor that is not transactional (audit.Nop, a wrapper, a fake).
// NewService refuses to run without a recorder, so the composition root has to
// supply something — and this is that something, chosen loudly by
// NewAdminAPI rather than by default inside the service. Production passes the
// GORM auditor, which is transactional.
type discardRecorder struct{}

func (discardRecorder) RecordTx(*gorm.DB, audit.Entry) error { return nil }
