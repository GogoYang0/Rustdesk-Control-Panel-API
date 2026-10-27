package api_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func TestClientBuild_BundlePublicEndpoint(t *testing.T) {
	h, orgID, _, adminToken, _, svc := newClientBuildHarness(t)
	profile := createProfileHTTP(t, h, orgID, adminToken, "Acme")
	build := createBuildHTTP(t, h, orgID, adminToken, profile.Id, []string{"linux-x64"})

	rawURL, err := svc.BundleURL(uint(build.Id))
	require.NoError(t, err)
	parsed, err := url.Parse(rawURL)
	require.NoError(t, err)
	token := parsed.Query().Get("token")
	require.NotEmpty(t, token)
	publicPath := "/api/v1/client-builds/" + itoa(build.Id) + "/bundle?token=" + url.QueryEscape(token)

	w := h.do(t, http.MethodGet, publicPath, nil, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, "application/gzip", w.Header().Get("Content-Type"))

	gz, err := gzip.NewReader(bytes.NewReader(w.Body.Bytes()))
	require.NoError(t, err)
	tr := tar.NewReader(gz)
	var manifest gen.ClientBuildManifest
	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		if hdr.Name != "manifest.json" {
			continue
		}
		require.NoError(t, json.NewDecoder(tr).Decode(&manifest))
		found = true
	}
	require.True(t, found)
	require.EqualValues(t, build.Id, manifest.BuildId)
	require.Equal(t, "https://panel.example.com", manifest.ApiServer)
	require.Equal(t, "relay.example.com:21116", manifest.Server)

	w = h.do(t, http.MethodGet, "/api/v1/client-builds/"+itoa(build.Id)+"/bundle", nil, "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	w = h.do(t, http.MethodGet, publicPath+"x", nil, "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())

	other := createBuildHTTP(t, h, orgID, adminToken, profile.Id, []string{"linux-x64"})
	w = h.do(t, http.MethodGet,
		"/api/v1/client-builds/"+itoa(other.Id)+"/bundle?token="+url.QueryEscape(token), nil, "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())

	require.NoError(t, os.Remove(filepath.Join(svc.Config().AssetDir, "bundles", fmt.Sprintf("%d.tar.gz", build.Id))))
	w = h.do(t, http.MethodGet, publicPath, nil, "")
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	var served, httpRows int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("organization_id = ? AND action = ?", orgID, "client_build.bundle.served").
		Count(&served).Error)
	require.EqualValues(t, 1, served)
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("action LIKE ?", "GET /api/v1/client-builds/:buildId/bundle").
		Count(&httpRows).Error)
	require.Zero(t, httpRows)
}
