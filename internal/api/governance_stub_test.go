package api_test

import (
	"encoding/json"
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

// stubRoutes are the governance endpoints still answered by a placeholder.
// Tickets moved to their real handlers in T4, so they keep the shared
// registration/auth/tenant assertions but drop the 501 ones.
func stubRoutes() []struct {
	method  string
	path    string
	ginPath string
} {
	out := make([]struct {
		method  string
		path    string
		ginPath string
	}, 0, len(governanceRoutes))
	for _, route := range governanceRoutes {
		if strings.Contains(route.path, "/tickets") {
			continue
		}
		out = append(out, route)
	}
	return out
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

// TestGovernanceRoutesRejectNonMembers pins the tenant boundary the placeholders
// already enforce. The outsider owns their own organization, so the 403 on the
// other organization proves the check is per-organization rather than a blanket
// deny — and it is the regression net for "forgot the permission check" when
// the real handlers land.
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

	// The same caller reaches their own organization (501 = the placeholder),
	// which proves the rejection above is about membership, not about the route.
	// Ticket routes are implemented now, so they are excluded here; their own
	// suite covers the positive path.
	for _, route := range stubRoutes() {
		t.Run("own org "+route.method+" "+route.path, func(t *testing.T) {
			w := h.do(t, route.method, withOrg(route.path, orgB), map[string]any{}, outsiderToken)
			require.Equal(t, http.StatusNotImplemented, w.Code, w.Body.String())
		})
	}
}

// TestGovernanceRoutesAreStubsUntilImplemented pins the interim state: every
// endpoint answers 501 with the standard envelope rather than pretending to
// work. Each owning task (T4-T7) replaces its handlers and must drop the
// corresponding case here.
func TestGovernanceRoutesAreStubsUntilImplemented(t *testing.T) {
	h := newHarness(t)
	token, orgID := seedOrgOwner(t, h, "gov-stub@example.com")

	for _, route := range stubRoutes() {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			w := h.do(t, route.method, withOrg(route.path, orgID), map[string]any{}, token)
			require.Equal(t, http.StatusNotImplemented, w.Code, w.Body.String())
			require.Contains(t, w.Header().Get("Content-Type"), "application/json")

			var body struct {
				Code    string          `json:"code"`
				Message string          `json:"message"`
				Data    json.RawMessage `json:"data"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			require.Equal(t, "internal", body.Code)
			require.Contains(t, body.Message, "not implemented yet:")
			// The address-book envelope omits data on error; the placeholder
			// must not invent one.
			require.True(t, len(body.Data) == 0 || string(body.Data) == "null",
				"stub response must not carry a data payload, got %s", string(body.Data))
		})
	}
}
