package store

import (
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

// registerDefaultScopedModels registers every tenant-scoped model at store
// startup. Without this, tableIsScoped would report false in production and the
// tenant plugin would silently skip the organization condition.
func registerDefaultScopedModels() {
	RegisterScopedModel(&model.Membership{})
}
