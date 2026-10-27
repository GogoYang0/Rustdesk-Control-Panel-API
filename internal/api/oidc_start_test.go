package api_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/auth/oidctest"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/oidc"
)

const testCallbackURL = "https://panel.example.com/api/v1/auth/oidc/callback"

func newOIDCService(issuer string) *oidc.Service {
	return oidc.NewService(nil, oidc.Config{
		ProviderName: "Test IdP",
		Issuer:       issuer,
		ClientID:     "panel-client",
		ClientSecret: "s3cret-value",
		Scopes:       []string{"openid", "profile", "email"},
		ClockSkew:    time.Minute,
		StateTTL:     10 * time.Minute,
		CallbackURL:  testCallbackURL,
		Now:          time.Now,
	}, zap.NewNop())
}

func oidcStartHarness(t *testing.T, issuer string) (*harness, *oidc.Service) {
	t.Helper()

	var svc *oidc.Service
	h := newHarnessWith(t, func(d *api.Deps) {
		svc = oidc.NewService(d.DB, oidc.Config{
			ProviderName: "Test IdP",
			Issuer:       issuer,
			ClientID:     "panel-client",
			ClientSecret: "s3cret-value",
			Scopes:       []string{"openid", "profile", "email"},
			ClockSkew:    time.Minute,
			StateTTL:     10 * time.Minute,
			CallbackURL:  testCallbackURL,
			Now:          time.Now,
		}, zap.NewNop())
		d.OIDC = svc
	})
	return h, svc
}

func TestOIDCStart_HappyPath(t *testing.T) {
	fake := oidctest.New(t, "panel-client")
	h, _ := oidcStartHarness(t, fake.Issuer)

	w := h.do(t, http.MethodPost, "/api/v1/auth/oidc/start", map[string]string{
		"redirect_path": "/devices",
	}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var start struct {
		AuthorizationURL string `json:"authorization_url"`
		State            string `json:"state"`
	}
	decodeData(t, w, &start)
	if start.State == "" || start.AuthorizationURL == "" {
		t.Fatalf("incomplete response: %+v", start)
	}

	parsed, err := url.Parse(start.AuthorizationURL)
	if err != nil {
		t.Fatalf("parse authorization_url: %v", err)
	}
	q := parsed.Query()
	for key, want := range map[string]string{
		"response_type":         "code",
		"client_id":             "panel-client",
		"redirect_uri":          testCallbackURL,
		"state":                 start.State,
		"code_challenge_method": "S256",
	} {
		if got := q.Get(key); got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
	if q.Get("nonce") == "" {
		t.Fatal("authorization_url has no nonce; replay protection would be silently off")
	}
	if !strings.Contains(q.Get("scope"), "openid") || !strings.Contains(q.Get("scope"), "email") {
		t.Fatalf("scope = %q", q.Get("scope"))
	}

	var flow model.ExternalLoginFlow
	if err := h.db.DB.Where("state = ?", start.State).First(&flow).Error; err != nil {
		t.Fatalf("flow row: %v", err)
	}
	if flow.RedirectPath != "/devices" {
		t.Fatalf("redirect_path = %q", flow.RedirectPath)
	}
	if flow.Provider != model.IdentityProviderOIDC {
		t.Fatalf("provider = %q", flow.Provider)
	}
	if !flow.ExpiresAt.After(time.Now()) || flow.ConsumedAt != nil {
		t.Fatalf("flow is not in a usable state: %+v", flow)
	}
	if flow.PKCEVerifier == "" {
		t.Fatal("flow has no PKCE verifier; the exchange would fail")
	}
}

func TestOIDCStart_RejectsOpenRedirect(t *testing.T) {
	fake := oidctest.New(t, "panel-client")
	h, _ := oidcStartHarness(t, fake.Issuer)

	cases := []string{
		"//evil.com",
		"https://evil.com",
		`/\evil.com`,
		"/%2F%2Fevil.com",
		"/a/../../b",
		"javascript:alert(1)",
		"/a\nb",
		"/" + strings.Repeat("x", 300),
	}
	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			w := h.do(t, http.MethodPost, "/api/v1/auth/oidc/start", map[string]string{
				"redirect_path": path,
			}, "")
			if w.Code != http.StatusBadRequest {
				t.Fatalf("redirect_path %q accepted with status %d", path, w.Code)
			}
		})
	}

	var flows int64
	if err := h.db.DB.Model(&model.ExternalLoginFlow{}).Count(&flows).Error; err != nil {
		t.Fatalf("count flows: %v", err)
	}
	if flows != 0 {
		t.Fatalf("rejected requests created %d flow rows", flows)
	}
}

func TestOIDCStart_DisabledReturns503(t *testing.T) {
	h := newHarness(t)
	w := h.do(t, http.MethodPost, "/api/v1/auth/oidc/start", map[string]string{}, "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when oidc is not configured", w.Code)
	}
}

func TestOIDCStart_ProviderDownReturns503(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	issuer := dead.URL
	dead.Close()

	h, _ := oidcStartHarness(t, issuer)
	w := h.do(t, http.MethodPost, "/api/v1/auth/oidc/start", map[string]string{}, "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when discovery fails: %s", w.Code, w.Body.String())
	}
}

func TestAuthProviders_OIDCEnabled(t *testing.T) {
	fake := oidctest.New(t, "panel-client")
	h, _ := oidcStartHarness(t, fake.Issuer)

	w := h.do(t, http.MethodGet, "/api/v1/auth/providers", nil, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var view struct {
		Oidc struct {
			Enabled bool   `json:"enabled"`
			Name    string `json:"name"`
		} `json:"oidc"`
		Ldap struct {
			Enabled bool `json:"enabled"`
		} `json:"ldap"`
	}
	decodeData(t, w, &view)
	if !view.Oidc.Enabled {
		t.Fatal("oidc.enabled = false for a configured provider")
	}
	if view.Oidc.Name != "Test IdP" {
		t.Fatalf("oidc.name = %q", view.Oidc.Name)
	}
	if view.Ldap.Enabled {
		t.Fatal("ldap.enabled = true without an LDAP implementation")
	}
}
