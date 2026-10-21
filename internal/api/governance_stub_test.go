package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// governanceRoutes is the surface contract v0.4.0 adds. Keeping it in one place
// lets the wiring tests below prove every path is registered and authenticated.
var governanceRoutes = []struct {
	method string
	path   string
	// ginPath is the pattern gin registers for this path (parameters instead
	// of concrete ids).
	ginPath string
}{
	{http.MethodGet, "/api/v1/orgs/1/sessions", "/api/v1/orgs/:orgId/sessions"},
	{http.MethodGet, "/api/v1/orgs/1/sessions/1", "/api/v1/orgs/:orgId/sessions/:sessionId"},
	{http.MethodGet, "/api/v1/orgs/1/policies", "/api/v1/orgs/:orgId/policies"},
	{http.MethodPost, "/api/v1/orgs/1/policies", "/api/v1/orgs/:orgId/policies"},
	{http.MethodPut, "/api/v1/orgs/1/policies/1", "/api/v1/orgs/:orgId/policies/:policyId"},
	{http.MethodDelete, "/api/v1/orgs/1/policies/1", "/api/v1/orgs/:orgId/policies/:policyId"},
	{http.MethodGet, "/api/v1/orgs/1/approvals", "/api/v1/orgs/:orgId/approvals"},
	{http.MethodPost, "/api/v1/orgs/1/approvals", "/api/v1/orgs/:orgId/approvals"},
	{http.MethodPost, "/api/v1/orgs/1/approvals/1/decision", "/api/v1/orgs/:orgId/approvals/:approvalId/decision"},
	{http.MethodPost, "/api/v1/orgs/1/tickets", "/api/v1/orgs/:orgId/tickets"},
	{http.MethodGet, "/api/v1/orgs/1/alerts", "/api/v1/orgs/:orgId/alerts"},
}

// TestGovernanceRoutesRegistered proves the generated handlers are mounted: a
// missing route would answer 404 from gin instead of reaching the handlers.
func TestGovernanceRoutesRegistered(t *testing.T) {
	h := newHarness(t)

	registered := make(map[string]bool, len(h.router.Routes()))
	for _, r := range h.router.Routes() {
		registered[r.Method+" "+r.Path] = true
	}

	for _, route := range governanceRoutes {
		want := route.method + " " + route.ginPath
		require.True(t, registered[want], "%s is not mounted", want)
	}
}

// TestGovernanceRoutesRequireAuth proves the new endpoints sit behind the
// management JWT middleware. They must never be added to publicPaths: session
// records, policies and approvals are organization data.
func TestGovernanceRoutesRequireAuth(t *testing.T) {
	h := newHarness(t)

	for _, route := range governanceRoutes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			w := h.do(t, route.method, route.path, map[string]any{}, "")
			require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
		})
	}
}

// TestGovernanceRoutesAreStubsUntilImplemented pins the interim state: every
// endpoint answers 501 rather than pretending to work. Each owning task (T4-T7)
// replaces its handlers and must drop the corresponding case here.
func TestGovernanceRoutesAreStubsUntilImplemented(t *testing.T) {
	h := newHarness(t)
	h.seedUser(t, "gov-stub@example.com", "StubPass!123")
	token := h.login(t, "gov-stub@example.com", "StubPass!123")

	for _, route := range governanceRoutes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			w := h.do(t, route.method, route.path, map[string]any{}, token)
			require.Equal(t, http.StatusNotImplemented, w.Code, w.Body.String())
			require.True(t, strings.Contains(w.Body.String(), "not implemented"),
				"the stub must say so: %s", w.Body.String())
		})
	}
}
