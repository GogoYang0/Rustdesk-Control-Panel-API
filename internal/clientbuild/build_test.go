package clientbuild

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func (f *fixture) createBuild(t *testing.T, profileID uint, platforms []string) *BuildDetail {
	t.Helper()
	d, err := f.svc.CreateBuild(context.Background(), f.org.ID, f.user.ID, profileID, platforms)
	require.NoError(t, err)
	return d
}

func TestBuild_CreateAndSnapshot(t *testing.T) {
	f := newFixture(t)
	p := f.createProfile(t, "Acme", "Acme")
	d := f.createBuild(t, p.ID, []string{"linux-x64", "windows-x64"})
	require.Equal(t, model.ClientBuildStatusPending, d.Build.Status)
	require.Equal(t, fmt.Sprintf("relay.example.com:%d", f.sg.HbbsPort+1), d.Manifest.Server)
	require.Equal(t, "https://panel.example.com", d.Manifest.APIServer)
	require.Equal(t, []string{"windows-x64", "linux-x64"}, d.Manifest.Platforms)
	require.Equal(t, f.user.ID, d.Build.CreatedBy)
	require.True(t, f.svc.storage.BundleExists(d.Build.ID))
	require.Contains(t, f.recorder.actions(), "client_build.start")

	f.now = f.now.Add(time.Hour)
	_, err := f.svc.UpdateProfile(context.Background(), f.org.ID, f.user.ID, p.ID,
		ProfileUpdate{AppName: strPtr("Acme Next")})
	require.NoError(t, err)
	f.setLogo(t, p.ID, 256)
	got, err := f.svc.GetBuild(context.Background(), f.org.ID, d.Build.ID)
	require.NoError(t, err)
	require.Equal(t, "Acme", got.Manifest.AppName)
	require.Nil(t, got.Manifest.Logo)
	require.Empty(t, got.Artifacts)
}

func TestBuild_Errors(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		f := newFixture(t)
		p := f.createProfile(t, "Acme", "Acme")
		f.svc.cfg.Enabled = false
		_, err := f.svc.CreateBuild(context.Background(), f.org.ID, f.user.ID, p.ID, []string{"linux-x64"})
		require.ErrorIs(t, err, ErrDisabled)
	})
	t.Run("profile cross org", func(t *testing.T) {
		f := newFixture(t)
		p, err := f.svc.CreateProfile(context.Background(), f.otherOrg.ID, f.user.ID,
			ProfileInput{Name: "Other", AppName: "Other"})
		require.NoError(t, err)
		_, err = f.svc.CreateBuild(context.Background(), f.org.ID, f.user.ID, p.ID, []string{"linux-x64"})
		require.ErrorIs(t, err, ErrNotFound)
	})
	t.Run("platforms", func(t *testing.T) {
		f := newFixture(t)
		p := f.createProfile(t, "Acme", "Acme")
		_, err := f.svc.CreateBuild(context.Background(), f.org.ID, f.user.ID, p.ID, nil)
		require.ErrorIs(t, err, ErrInvalidInput)
		_, err = f.svc.CreateBuild(context.Background(), f.org.ID, f.user.ID, p.ID, []string{"ios"})
		require.ErrorIs(t, err, ErrInvalidInput)
	})
	t.Run("platform narrowed by config", func(t *testing.T) {
		f := newFixture(t)
		f.svc.cfg.Platforms = []string{PlatformLinuxX64}
		p := f.createProfile(t, "Acme", "Acme")
		_, err := f.svc.CreateBuild(context.Background(), f.org.ID, f.user.ID, p.ID, []string{PlatformWindowsX64})
		require.ErrorIs(t, err, ErrInvalidInput)
	})
	t.Run("server missing", func(t *testing.T) {
		f := newFixture(t)
		p, err := f.svc.CreateProfile(context.Background(), f.otherOrg.ID, f.user.ID,
			ProfileInput{Name: "Other", AppName: "Other"})
		require.NoError(t, err)
		_, err = f.svc.CreateBuild(context.Background(), f.otherOrg.ID, f.user.ID, p.ID, []string{"linux-x64"})
		require.ErrorIs(t, err, ErrServerNotReady)
	})
	t.Run("quota", func(t *testing.T) {
		f := newFixture(t)
		p := f.createProfile(t, "Acme", "Acme")
		f.createBuild(t, p.ID, []string{"linux-x64"})
		f.createBuild(t, p.ID, []string{"linux-x64"})
		_, err := f.svc.CreateBuild(context.Background(), f.org.ID, f.user.ID, p.ID, []string{"linux-x64"})
		require.ErrorIs(t, err, ErrQuotaExceeded)
	})
	t.Run("logo file missing", func(t *testing.T) {
		f := newFixture(t)
		p := f.createProfile(t, "Acme", "Acme")
		rel := f.setLogo(t, p.ID, 256)
		require.NoError(t, os.Remove(filepath.Join(f.cfg.AssetDir, filepath.FromSlash(rel))))
		_, err := f.svc.CreateBuild(context.Background(), f.org.ID, f.user.ID, p.ID, []string{"linux-x64"})
		require.ErrorIs(t, err, ErrConflict)
	})
}

func TestBuild_ListGetAndFilters(t *testing.T) {
	f := newFixture(t)
	f.svc.cfg.MaxConcurrentPerOrg = 10
	p1 := f.createProfile(t, "One", "One")
	p2 := f.createProfile(t, "Two", "Two")
	b1 := f.createBuild(t, p1.ID, []string{"linux-x64"})
	f.createBuild(t, p1.ID, []string{"linux-x64"})
	b3 := f.createBuild(t, p2.ID, []string{"linux-x64"})
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).Model(&model.ClientBuild{}).
		Where("id = ?", b1.Build.ID).Update("status", model.ClientBuildStatusSucceeded).Error)

	page, err := f.svc.ListBuilds(context.Background(), f.org.ID, BuildFilter{Page: 1, PageSize: 2})
	require.NoError(t, err)
	require.EqualValues(t, 3, page.Total)
	require.Len(t, page.Items, 2)
	page, err = f.svc.ListBuilds(context.Background(), f.org.ID, BuildFilter{Page: 2, PageSize: 2})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)

	succeeded, err := f.svc.ListBuilds(context.Background(), f.org.ID, BuildFilter{Status: model.ClientBuildStatusSucceeded})
	require.NoError(t, err)
	require.EqualValues(t, 1, succeeded.Total)
	byProfile, err := f.svc.ListBuilds(context.Background(), f.org.ID, BuildFilter{ProfileID: &p1.ID})
	require.NoError(t, err)
	require.EqualValues(t, 2, byProfile.Total)

	got, err := f.svc.GetBuild(context.Background(), f.org.ID, b3.Build.ID)
	require.NoError(t, err)
	require.Equal(t, p2.Name, got.Manifest.AppName)
	require.Empty(t, got.Artifacts)

	_, err = f.svc.ListBuilds(context.Background(), f.org.ID, BuildFilter{Status: "bogus"})
	require.ErrorIs(t, err, ErrInvalidInput)
}

func TestBuild_BundleURLAndServe(t *testing.T) {
	f := newFixture(t)
	p := f.createProfile(t, "Acme", "Acme")
	d := f.createBuild(t, p.ID, []string{"linux-x64"})

	raw, err := f.svc.BundleURL(d.Build.ID)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(raw,
		"https://panel.example.com/api/v1/client-builds/"+strconv.FormatUint(uint64(d.Build.ID), 10)+"/bundle?token="))
	u, err := url.Parse(raw)
	require.NoError(t, err)
	token := u.Query().Get("token")
	require.NotEmpty(t, token)

	file, err := f.svc.ServeBundle(context.Background(), d.Build.ID, token)
	require.NoError(t, err)
	_, err = io.ReadAll(file)
	file.Close()
	require.NoError(t, err)
	require.Contains(t, f.recorder.actions(), "client_build.bundle.served")

	_, err = f.svc.ServeBundle(context.Background(), d.Build.ID+1, token)
	require.ErrorIs(t, err, ErrTokenInvalid)

	f.recorder.fail = errors.New("audit unavailable")
	file, err = f.svc.ServeBundle(context.Background(), d.Build.ID, token)
	require.ErrorIs(t, err, ErrUnaudited)
	require.Nil(t, file)
	f.recorder.fail = nil

	require.NoError(t, f.svc.storage.RemoveBundle(d.Build.ID))
	_, err = f.svc.ServeBundle(context.Background(), d.Build.ID, token)
	require.ErrorIs(t, err, ErrArtifactUnavailable)

	_, err = f.svc.BundleURL(9999)
	require.ErrorIs(t, err, ErrArtifactUnavailable)
}

func TestBuild_Cancel(t *testing.T) {
	t.Run("pending", func(t *testing.T) {
		f := newFixture(t)
		p := f.createProfile(t, "Acme", "Acme")
		d := f.createBuild(t, p.ID, []string{"linux-x64"})
		got, err := f.svc.CancelBuild(context.Background(), f.org.ID, f.user.ID, d.Build.ID)
		require.NoError(t, err)
		require.Equal(t, model.ClientBuildStatusCancelled, got.Build.Status)
		require.NotNil(t, got.Build.FinishedAt)
		require.Contains(t, f.recorder.actions(), "client_build.cancel")
		require.Contains(t, f.recorder.actions(), "client_build.cancelled")
	})

	t.Run("dispatching without marker", func(t *testing.T) {
		f := newFixture(t)
		p := f.createProfile(t, "Acme", "Acme")
		d := f.createBuild(t, p.ID, []string{"linux-x64"})
		require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).Model(&model.ClientBuild{}).
			Where("id = ?", d.Build.ID).Update("status", model.ClientBuildStatusDispatching).Error)
		f.github.dispatchFn = func(context.Context, DispatchInput) (DispatchResult, error) {
			t.Error("cancel must not dispatch")
			return DispatchResult{}, nil
		}
		got, err := f.svc.CancelBuild(context.Background(), f.org.ID, f.user.ID, d.Build.ID)
		require.NoError(t, err)
		require.Equal(t, model.ClientBuildStatusCancelled, got.Build.Status)
	})

	t.Run("dispatching with marker", func(t *testing.T) {
		f := newFixture(t)
		p := f.createProfile(t, "Acme", "Acme")
		d := f.createBuild(t, p.ID, []string{"linux-x64"})
		now := time.Now().UTC()
		require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).Model(&model.ClientBuild{}).
			Where("id = ?", d.Build.ID).Updates(map[string]any{
			"status": model.ClientBuildStatusDispatching, "dispatch_attempted_at": now, "github_run_id": 4242,
		}).Error)
		cancelCalled := false
		f.github.cancelRunFn = func(_ context.Context, id int64) error {
			require.EqualValues(t, 4242, id)
			cancelCalled = true
			return nil
		}
		got, err := f.svc.CancelBuild(context.Background(), f.org.ID, f.user.ID, d.Build.ID)
		require.NoError(t, err)
		require.Equal(t, model.ClientBuildStatusDispatching, got.Build.Status)
		require.NotNil(t, got.Build.CancelRequestedAt)
		require.True(t, cancelCalled)
	})

	t.Run("terminal", func(t *testing.T) {
		f := newFixture(t)
		p := f.createProfile(t, "Acme", "Acme")
		d := f.createBuild(t, p.ID, []string{"linux-x64"})
		require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).Model(&model.ClientBuild{}).
			Where("id = ?", d.Build.ID).Update("status", model.ClientBuildStatusSucceeded).Error)
		_, err := f.svc.CancelBuild(context.Background(), f.org.ID, f.user.ID, d.Build.ID)
		require.ErrorIs(t, err, ErrConflict)
	})
}

func TestBuild_CancelIngestingRejected(t *testing.T) {
	f := newFixture(t)
	p := f.createProfile(t, "Acme", "Acme")
	d := f.createBuild(t, p.ID, []string{"linux-x64"})
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).Model(&model.ClientBuild{}).
		Where("id = ?", d.Build.ID).Update("status", model.ClientBuildStatusIngesting).Error)
	_, err := f.svc.CancelBuild(context.Background(), f.org.ID, f.user.ID, d.Build.ID)
	require.ErrorIs(t, err, ErrConflict)
}
