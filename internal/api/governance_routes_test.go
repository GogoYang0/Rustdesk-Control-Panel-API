package api_test

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// governanceRoutes is the surface contract v0.4.0 adds. Paths carry an {org}
// placeholder so tests can point them at the organization they actually
// created; ginPath is the pattern gin registers.
var governanceRoutes = []struct {
	method  string
	path    string
	ginPath string
}{
	{http.MethodGet, "/api/v1/orgs/{org}/sessions", "/api/v1/orgs/:orgId/sessions"},
	{http.MethodGet, "/api/v1/orgs/{org}/sessions/1", "/api/v1/orgs/:orgId/sessions/:sessionId"},
	{http.MethodGet, "/api/v1/orgs/{org}/policies", "/api/v1/orgs/:orgId/policies"},
	{http.MethodPost, "/api/v1/orgs/{org}/policies", "/api/v1/orgs/:orgId/policies"},
	{http.MethodPut, "/api/v1/orgs/{org}/policies/1", "/api/v1/orgs/:orgId/policies/:policyId"},
	{http.MethodDelete, "/api/v1/orgs/{org}/policies/1", "/api/v1/orgs/:orgId/policies/:policyId"},
	{http.MethodGet, "/api/v1/orgs/{org}/approvals", "/api/v1/orgs/:orgId/approvals"},
	{http.MethodGet, "/api/v1/orgs/{org}/approvals/1", "/api/v1/orgs/:orgId/approvals/:approvalId"},
	{http.MethodPost, "/api/v1/orgs/{org}/approvals", "/api/v1/orgs/:orgId/approvals"},
	{http.MethodPost, "/api/v1/orgs/{org}/approvals/1/decision", "/api/v1/orgs/:orgId/approvals/:approvalId/decision"},
	{http.MethodPost, "/api/v1/orgs/{org}/tickets", "/api/v1/orgs/:orgId/tickets"},
	{http.MethodGet, "/api/v1/orgs/{org}/tickets/1", "/api/v1/orgs/:orgId/tickets/:ticketId"},
	{http.MethodPost, "/api/v1/orgs/{org}/tickets/1/redeem", "/api/v1/orgs/:orgId/tickets/:ticketId/redeem"},
	{http.MethodGet, "/api/v1/orgs/{org}/alerts", "/api/v1/orgs/:orgId/alerts"},
}

// withOrg substitutes the {org} placeholder.
func withOrg(template string, orgID int64) string {
	return strings.Replace(template, "{org}", strconv.FormatInt(orgID, 10), 1)
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
			w := h.do(t, route.method, withOrg(route.path, 1), map[string]any{}, "")
			require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
		})
	}
}

// TestGovernanceRoutesRejectNonMembers pins the tenant boundary. The outsider
// owns their own organization, so the 403 on the other organization proves the
// check is per-organization rather than a blanket deny — and it is the
// regression net for "forgot the permission check".
func TestGovernanceRoutesRejectNonMembers(t *testing.T) {
	h := newHarness(t)
	_, orgA := seedOrgOwner(t, h, "gov-a@example.com")
	outsiderToken, orgB := seedOrgOwner(t, h, "gov-b@example.com")
	require.NotEqual(t, orgA, orgB, "the two seeded organizations must differ")

	for _, route := range governanceRoutes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			w := h.do(t, route.method, withOrg(route.path, orgA), map[string]any{}, outsiderToken)
			require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
		})
	}

	// The same caller must reach their own organization: the 403 above is about
	// membership, not about the route. Every governance endpoint has a real
	// handler since v0.4.0, so a legitimate owner must not be rejected. Only the
	// 403 is asserted here — the handlers legitimately answer 404 for the
	// non-existent resource ids these placeholders use (e.g. GET .../tickets/1),
	// and route mounting has its own net in TestGovernanceRoutesRegistered.
	for _, route := range governanceRoutes {
		t.Run("own org "+route.method+" "+route.path, func(t *testing.T) {
			w := h.do(t, route.method, withOrg(route.path, orgB), map[string]any{}, outsiderToken)
			require.NotEqual(t, http.StatusForbidden, w.Code, w.Body.String())
		})
	}
}
