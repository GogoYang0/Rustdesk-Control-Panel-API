package api_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/clientbuild"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func createProfileHTTP(t *testing.T, h *harness, orgID int64, token, name string) gen.ClientBuildProfile {
	t.Helper()
	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/client-build-profiles",
		map[string]string{"name": name, "app_name": name}, token)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var profile gen.ClientBuildProfile
	decodeData(t, w, &profile)
	return profile
}

func createBuildHTTP(t *testing.T, h *harness, orgID int64, token string, profileID int64, platforms []string) gen.ClientBuildDetail {
	t.Helper()
	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/client-builds",
		map[string]any{"profile_id": profileID, "platforms": platforms}, token)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	var detail gen.ClientBuildDetail
	decodeData(t, w, &detail)
	return detail
}

func TestClientBuild_BuildHTTP(t *testing.T) {
	h, orgID, _, adminToken, memberToken, _ := newClientBuildHarness(t)
	profile := createProfileHTTP(t, h, orgID, adminToken, "Acme")
	build := createBuildHTTP(t, h, orgID, adminToken, profile.Id, []string{"linux-x64", "windows-x64"})
	require.Equal(t, gen.ClientBuildDetailStatus("pending"), build.Status)
	require.Equal(t, "https://panel.example.com", build.Manifest.ApiServer)
	require.Equal(t, "relay.example.com:21116", build.Manifest.Server)
	require.Equal(t, []gen.ClientBuildDetailPlatforms{"windows-x64", "linux-x64"}, build.Platforms)

	w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/client-builds",
		map[string]any{"profile_id": profile.Id, "platforms": []string{"linux-x64"}}, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/client-builds", nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/client-builds/"+itoa(build.Id), nil, memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	otherOrg := createOrg(t, h, adminToken, "other-build-http")
	w = h.do(t, http.MethodGet,
		"/api/v1/orgs/"+itoa(otherOrg)+"/client-builds/"+itoa(build.Id), nil, adminToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	// The build keeps its manifest snapshot after the profile changes.
	w = h.do(t, http.MethodPatch, "/api/v1/orgs/"+itoa(orgID)+"/client-build-profiles/"+itoa(profile.Id),
		map[string]string{"app_name": "Acme Next"}, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var after gen.ClientBuildDetail
	w = h.do(t, http.MethodGet, "/api/v1/orgs/"+itoa(orgID)+"/client-builds/"+itoa(build.Id), nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	decodeData(t, w, &after)
	require.Equal(t, "Acme", after.Manifest.AppName)

	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/client-builds/"+itoa(build.Id)+"/cancel", nil, adminToken)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	var cancelled gen.ClientBuildDetail
	decodeData(t, w, &cancelled)
	require.Equal(t, gen.ClientBuildDetailStatus("cancelled"), cancelled.Status)
	w = h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/client-builds/"+itoa(build.Id)+"/cancel", nil, adminToken)
	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
}

func TestClientBuild_DisabledAndNotReady(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		h, orgID, _, adminToken, _, _ := newClientBuildHarnessWith(t, func(c *clientbuild.Config) {
			c.Enabled = false
		})
		profile := createProfileHTTP(t, h, orgID, adminToken, "Acme")
		w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/client-builds",
			map[string]any{"profile_id": profile.Id, "platforms": []string{"linux-x64"}}, adminToken)
		require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
	})
	t.Run("server not deployed", func(t *testing.T) {
		h, orgID, _, adminToken, _, _ := newClientBuildHarness(t)
		profile := createProfileHTTP(t, h, orgID, adminToken, "Acme")
		require.NoError(t, store.ScopedByOrg(h.db.DB, uint(orgID)).Model(&model.ServerGroup{}).
			Where("organization_id = ?", orgID).Update("state", model.ServerGroupFailed).Error)
		w := h.do(t, http.MethodPost, "/api/v1/orgs/"+itoa(orgID)+"/client-builds",
			map[string]any{"profile_id": profile.Id, "platforms": []string{"linux-x64"}}, adminToken)
		require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	})
}

func TestClientBuild_ArtifactDownload(t *testing.T) {
	h, orgID, _, adminToken, memberToken, svc := newClientBuildHarness(t)
	profile := createProfileHTTP(t, h, orgID, adminToken, "Acme")
	build := createBuildHTTP(t, h, orgID, adminToken, profile.Id, []string{"linux-x64"})

	fileName := fmt.Sprintf("panel-client-%d-linux-x64.AppImage", build.Id)
	body := []byte("artifact-bytes")
	sum := sha256.Sum256(body)
	rel := filepath.ToSlash(filepath.Join("artifacts", fmt.Sprint(orgID), fmt.Sprint(build.Id), fileName))
	abs := filepath.Join(svc.Config().AssetDir, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(abs), 0o700))
	require.NoError(t, os.WriteFile(abs, body, 0o600))
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.ClientBuild{}).
		Where("id = ?", build.Id).Updates(map[string]any{
		"status": model.ClientBuildStatusSucceeded, "artifact_count": 1, "finished_at": time.Now(),
	}).Error)
	artifact := model.ClientBuildArtifact{
		OrganizationID: uint(orgID), BuildID: uint(build.Id), Platform: "linux-x64",
		FileName: fileName, SizeBytes: int64(len(body)), SHA256: hex.EncodeToString(sum[:]),
		StoragePath: rel, CreatedAt: time.Now(),
	}
	require.NoError(t, store.ScopedByOrg(h.db.DB, uint(orgID)).Create(&artifact).Error)

	path := "/api/v1/orgs/" + itoa(orgID) + "/client-builds/" + itoa(build.Id) +
		"/artifacts/" + itoa(int64(artifact.ID))
	w := h.do(t, http.MethodGet, path, nil, adminToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, body, w.Body.Bytes())
	require.Contains(t, w.Header().Get("Content-Disposition"), fileName)

	w = h.do(t, http.MethodGet, path, nil, memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	otherOrg := createOrg(t, h, adminToken, "other-artifact")
	w = h.do(t, http.MethodGet,
		"/api/v1/orgs/"+itoa(otherOrg)+"/client-builds/"+itoa(build.Id)+"/artifacts/"+itoa(int64(artifact.ID)),
		nil, adminToken)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())

	var count int64
	require.NoError(t, store.WithoutTenantScope(h.db.DB).Model(&model.AuditLog{}).
		Where("organization_id = ? AND action = ?", orgID, "client_build.artifact.download").
		Count(&count).Error)
	require.EqualValues(t, 1, count)
}
