package clientbuild

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

func (f *fixture) ingestLinux(t *testing.T, d *BuildDetail) *BuildDetail {
	t.Helper()
	zipName := "panel-client-" + itoa(d.Build.ID) + "-linux-x64"
	f.fakeArtifacts(d.Build.ID, map[string][]byte{
		zipName: makeZip(t, zipEntry{Name: zipName + ".AppImage", Body: []byte("x")}),
	})
	require.NoError(t, f.ingest(t, d))
	got, err := f.svc.GetBuild(context.Background(), f.org.ID, d.Build.ID)
	require.NoError(t, err)
	return got
}

func TestSweep_PurgesExpiredArtifacts(t *testing.T) {
	f := newFixture(t)
	p := f.createProfile(t, "Acme", "Acme")
	expired := f.ingestLinux(t, f.createBuild(t, p.ID, []string{"linux-x64"}))
	artifactID := expired.Artifacts[0].ID
	artifactPath := filepath.Join(f.cfg.AssetDir, filepath.FromSlash(expired.Artifacts[0].StoragePath))
	require.FileExists(t, artifactPath)
	f.setBuild(t, expired.Build.ID, map[string]any{"finished_at": f.now.Add(-721 * time.Hour)})

	recent := f.ingestLinux(t, f.createBuild(t, p.ID, []string{"linux-x64"}))
	f.setBuild(t, recent.Build.ID, map[string]any{"finished_at": f.now.Add(-time.Hour)})

	n, err := f.svc.Sweep(context.Background())
	require.NoError(t, err)
	require.Positive(t, n)

	got, err := f.svc.GetBuild(context.Background(), f.org.ID, expired.Build.ID)
	require.NoError(t, err)
	require.NotNil(t, got.Build.ArtifactsPurgedAt)
	require.Empty(t, got.Artifacts)
	require.NoFileExists(t, artifactPath)
	_, err = f.svc.OpenArtifact(context.Background(), f.org.ID, expired.Build.ID, artifactID, f.user.ID)
	require.ErrorIs(t, err, ErrArtifactUnavailable)

	recentGot, err := f.svc.GetBuild(context.Background(), f.org.ID, recent.Build.ID)
	require.NoError(t, err)
	require.Nil(t, recentGot.Build.ArtifactsPurgedAt)
	require.Len(t, recentGot.Artifacts, 1)

	// The second pass is idempotent for the already-purged build.
	n, err = f.svc.Sweep(context.Background())
	require.NoError(t, err)
	require.Zero(t, n)
}

func TestSweep_RemovesOldBundles(t *testing.T) {
	f := newFixture(t)
	f.svc.cfg.MaxConcurrentPerOrg = 3
	p := f.createProfile(t, "Acme", "Acme")
	oldFinished := f.createBuild(t, p.ID, []string{"linux-x64"})
	oldCreated := f.createBuild(t, p.ID, []string{"linux-x64"})
	fresh := f.createBuild(t, p.ID, []string{"linux-x64"})

	f.setBuild(t, oldFinished.Build.ID, map[string]any{
		"status": model.ClientBuildStatusSucceeded, "finished_at": f.now.Add(-25 * time.Hour),
	})
	f.setBuild(t, oldCreated.Build.ID, map[string]any{"created_at": f.now.Add(-49 * time.Hour)})

	n, err := f.svc.Sweep(context.Background())
	require.NoError(t, err)
	require.Positive(t, n)
	require.False(t, f.svc.storage.BundleExists(oldFinished.Build.ID))
	require.False(t, f.svc.storage.BundleExists(oldCreated.Build.ID))
	require.True(t, f.svc.storage.BundleExists(fresh.Build.ID))
}

func TestSweep_CleansStagingAndOrphanArtifacts(t *testing.T) {
	f := newFixture(t)
	oldStage, err := f.svc.storage.NewStaging(1)
	require.NoError(t, err)
	require.NoError(t, os.Chtimes(oldStage, f.now.Add(-3*time.Hour), f.now.Add(-3*time.Hour)))
	newStage, err := f.svc.storage.NewStaging(2)
	require.NoError(t, err)
	require.NoError(t, os.Chtimes(newStage, f.now, f.now))

	orphan, err := f.svc.storage.ArtifactDir(f.org.ID, 9999)
	require.NoError(t, err)
	require.NoError(t, os.Chtimes(orphan, f.now.Add(-25*time.Hour), f.now.Add(-25*time.Hour)))

	_, err = f.svc.Sweep(context.Background())
	require.NoError(t, err)
	_, err = os.Stat(oldStage)
	require.True(t, os.IsNotExist(err))
	require.DirExists(t, newStage)
	_, err = os.Stat(orphan)
	require.True(t, os.IsNotExist(err))
}
