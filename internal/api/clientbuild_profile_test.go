package api_test

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/api"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/clientbuild"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func clientBuildTestConfig(t *testing.T) clientbuild.Config {
	t.Helper()
	return clientbuild.Config{
		Enabled:         true,
		PublicBaseURL:   "https://panel.example.com",
		RelayHost:       "relay.example.com",
		AssetDir:        t.TempDir(),
		RustdeskVersion: "1.5.0",
		GitHub: clientbuild.GitHubConfig{
			APIBaseURL: "https://api.github.com", Repo: "acme/build",
			Workflow: "build-client.yml", Ref: "main", Token: "pat",
			ArtifactHosts: []string{"github.com"},
		},
		BundleTTL:             24 * time.Hour,
		BundleKey:             "0123456789abcdef0123456789abcdef",
		PollInterval:          30 * time.Second,
		PendingTimeout:        12 * time.Hour,
		DispatchTimeout:       10 * time.Minute,
		BuildTimeout:          3 * time.Hour,
		IngestTimeout:         time.Hour,
		ArtifactRetention:     720 * time.Hour,
		DeleteRemoteArtifacts: true,
		MaxProfilesPerOrg:     10,
		MaxConcurrentPerOrg:   2,
		MaxActiveBuilds:       4,
		MaxArtifactBytes:      2 << 30,
		Platforms:             append([]string{}, clientbuild.SupportedPlatforms...),
	}
}

func newClientBuildHarness(t *testing.T) (
	h *harness, orgID int64, ownerToken, adminToken, memberToken string, svc *clientbuild.Service,
) {
	t.Helper()
	return newClientBuildHarnessWith(t, nil)
}

func newClientBuildHarnessWith(t *testing.T, mutate func(*clientbuild.Config)) (
	h *harness, orgID int64, ownerToken, adminToken, memberToken string, svc *clientbuild.Service,
) {
	t.Helper()
	h, orgID, _, _, _, ownerToken, adminToken, memberToken = m4OrgWith(t, func(d *api.Deps) {
		recorder, ok := d.Auditor.(audit.TxRecorder)
		require.True(t, ok)
		cfg := clientBuildTestConfig(t)
		if mutate != nil {
			mutate(&cfg)
		}
		s, err := clientbuild.NewService(d.DB, recorder, d.Auditor, cfg, nil, zap.NewNop(), nil)
		require.NoError(t, err)
		svc = s
		d.ClientBuilds = s
	})
	require.NoError(t, h.db.DB.Create(&model.ServerGroup{
		OrganizationID: uint(orgID), HbbsPort: 21115, HbbrPort: 21118,
		PubKey: "dGVzdC1rZXktMDEyMzQ1Njc4OWFiY2RlZmdoaWo=", State: model.ServerGroupDeployed,
	}).Error)
	return h, orgID, ownerToken, adminToken, memberToken, svc
}

func makeTestPNG(t *testing.T, size int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	for x := 0; x < size; x++ {
		for y := 0; y < size; y++ {
			img.Set(x, y, color.RGBA{R: uint8(x), G: uint8(y), B: 200, A: 255})
		}
	}
	var buf bytes.Buffer
	require.NoError(t, png.Encode(&buf, img))
	return buf.Bytes()
}

func TestClientBuildProfile_CRUDAndPermissions(t *testing.T) {
	h, orgID, _, adminToken, memberToken, _ := newClientBuildHarness(t)
	base := "/api/v1/orgs/" + itoa(orgID) + "/client-build-profiles"

	w := h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/client-build/capabilities", nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var caps gen.ClientBuildCapabilities
	decodeData(t, w, &caps)
	require.True(t, caps.Enabled)
	require.Equal(t, gen.ClientBuildCapabilitiesProvisioningState("deployed"), caps.ProvisioningState)
	require.NotNil(t, caps.Defaults)
	require.Equal(t, "relay.example.com:21116", caps.Defaults.Server)

	w = h.do(t, http.MethodPost, base, map[string]string{"name": "  Acme  ", "app_name": "Acme Ops"}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var profile gen.ClientBuildProfile
	decodeData(t, w, &profile)
	require.Equal(t, "Acme", profile.Name)
	require.Equal(t, "Acme Ops", profile.AppName)
	require.False(t, profile.HasLogo)

	w = h.do(t, http.MethodPost, base, map[string]string{"name": "Member", "app_name": "Member"}, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	w = h.do(t, http.MethodPost, base, map[string]string{"name": "ACME", "app_name": "Acme"}, adminToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())

	w = h.do(t, http.MethodGet, base, nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var page gen.ClientBuildProfilePage
	decodeData(t, w, &page)
	require.Len(t, page.Items, 1)

	item := base + "/" + itoa(profile.Id)
	w = h.do(t, http.MethodGet, item, nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodPatch, item, map[string]string{"app_name": "Acme Next"}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	decodeData(t, w, &profile)
	require.Equal(t, "Acme Next", profile.AppName)

	w = h.do(t, http.MethodDelete, item, nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodGet, item, nil, memberToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	var actions []string
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("organization_id = ? AND action LIKE ?", orgID, "client_build.%").
		Pluck("action", &actions).Error)
	require.Contains(t, actions, "client_build.profile.create")
	require.Contains(t, actions, "client_build.profile.update")
	require.Contains(t, actions, "client_build.profile.delete")
	var httpRows int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("action LIKE ?", "PATCH /api/v1/orgs/:orgId/client-build-profiles/%").
		Count(&httpRows).Error)
	require.Zero(t, httpRows)

	// A failed PATCH is audited by the HTTP fallback, not by the domain
	// transaction; this only checks the status mapping.
	w = h.do(t, http.MethodPatch, item, map[string]string{}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
}

func TestClientBuildProfile_AppNameCrossOrg(t *testing.T) {
	h, orgID, _, adminToken, _, _ := newClientBuildHarness(t)
	base := "/api/v1/orgs/" + itoa(orgID) + "/client-build-profiles"

	w := h.do(t, http.MethodPost, base, map[string]string{"name": "Bad", "app_name": "RustDesk"}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	w = h.do(t, http.MethodPost, base, map[string]string{"name": "Acme", "app_name": "Acme"}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var profile gen.ClientBuildProfile
	decodeData(t, w, &profile)

	otherOrg := createOrg(t, h, adminToken, "other-org")
	w = h.do(t, http.MethodGet,
		"/api/v1/orgs/"+itoa(otherOrg)+"/client-build-profiles/"+itoa(profile.Id), nil, adminToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
}

func TestClientBuildProfile_MissingService(t *testing.T) {
	h, orgID, _, _, _, ownerToken, _, _ := m4Org(t)
	w := h.do(t, http.MethodGet,
		"/api/v1/orgs/"+itoa(orgID)+"/client-build/capabilities", nil, ownerToken)
	require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
}

func TestClientBuildProfile_LogoLifecycle(t *testing.T) {
	h, orgID, _, adminToken, memberToken, _ := newClientBuildHarness(t)
	base := "/api/v1/orgs/" + itoa(orgID) + "/client-build-profiles"
	w := h.do(t, http.MethodPost, base, map[string]string{"name": "Acme", "app_name": "Acme"}, adminToken)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var profile gen.ClientBuildProfile
	decodeData(t, w, &profile)
	logoURL := base + "/" + itoa(profile.Id) + "/logo"

	pngBytes := makeTestPNG(t, 256)
	w = h.do(t, http.MethodPut, logoURL,
		map[string]string{"png_base64": base64.StdEncoding.EncodeToString(pngBytes)}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	decodeData(t, w, &profile)
	require.True(t, profile.HasLogo)
	require.Equal(t, 256, profile.LogoWidth)

	w = h.do(t, http.MethodGet, logoURL, nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, "image/png", w.Header().Get("Content-Type"))
	etag := w.Header().Get("ETag")
	require.NotEmpty(t, etag)

	req := httptest.NewRequest(http.MethodGet, logoURL, nil)
	req.Header.Set("Authorization", "Bearer "+memberToken)
	req.Header.Set("If-None-Match", etag)
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusNotModified, rec.Code)

	w = h.do(t, http.MethodPut, logoURL, map[string]string{"png_base64": "not-base64"}, adminToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	w = h.do(t, http.MethodDelete, logoURL, nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodGet, logoURL, nil, memberToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	var actions []string
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("organization_id = ? AND action LIKE ?", orgID, "client_build.logo.%").
		Pluck("action", &actions).Error)
	require.Contains(t, actions, "client_build.logo.set")
	require.Contains(t, actions, "client_build.logo.delete")
}
