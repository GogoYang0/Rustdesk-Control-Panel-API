package api

import (
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/limit"
)

// loginGuard aliases the shared rate limiter so existing call sites keep
// working; the compat layer (internal/compatapi) uses the same limiter.
type loginGuard = limit.LoginGuard

func newLoginGuard() *loginGuard { return limit.NewLoginGuard() }
