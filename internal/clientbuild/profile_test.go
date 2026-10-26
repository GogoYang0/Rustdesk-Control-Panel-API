package clientbuild

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
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

func TestProfile_CreateAndAudit(t *testing.T) {
	f := newFixture(t)
	p := f.createProfile(t, "  Acme  ", "Acme Ops")
	require.Equal(t, "Acme", p.Name)
	require.Equal(t, "acme", p.NameKey)
	require.Equal(t, "Acme Ops", p.AppName)
	require.Equal(t, f.org.ID, p.OrganizationID)
	require.Equal(t, f.user.ID, p.CreatedBy)
	require.Contains(t, f.recorder.actions(), "client_build.profile.create")
	entry := f.recorder.entries[len(f.recorder.entries)-1]
	require.Equal(t, f.org.ID, entry.OrganizationID)
	require.Equal(t, f.user.ID, entry.ActorUserID)
	require.Equal(t, "client_build_profile", entry.TargetType)
}

func TestProfile_DuplicateNameAcrossOrgs(t *testing.T) {
	f := newFixture(t)
	f.createProfile(t, "Acme", "Acme")
	_, err := f.svc.CreateProfile(context.Background(), f.org.ID, f.user.ID,
		ProfileInput{Name: "ACME", AppName: "Acme"})
	require.ErrorIs(t, err, ErrDuplicateName)

	other, err := f.svc.CreateProfile(context.Background(), f.otherOrg.ID, f.user.ID,
		ProfileInput{Name: "Acme", AppName: "Globex"})
	require.NoError(t, err)
	require.Equal(t, f.otherOrg.ID, other.OrganizationID)
}

func TestProfile_AppNameValidation(t *testing.T) {
	f := newFixture(t)
	for _, app := range []string{"RustDesk", "a/b", `a\b`, "."} {
		_, err := f.svc.CreateProfile(context.Background(), f.org.ID, f.user.ID,
			ProfileInput{Name: "Ops", AppName: app})
		require.ErrorIs(t, err, ErrInvalidInput, "app name %q", app)
	}
}

func TestProfile_Quota(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < 10; i++ {
		f.createProfile(t, "profile-"+strings.Repeat("x", i), "Acme")
	}
	_, err := f.svc.CreateProfile(context.Background(), f.org.ID, f.user.ID,
		ProfileInput{Name: "one-too-many", AppName: "Acme"})
	require.ErrorIs(t, err, ErrQuotaExceeded)
}

func TestProfile_Update(t *testing.T) {
	f := newFixture(t)
	p := f.createProfile(t, "Acme", "Acme")
	f.now = f.now.Add(time.Hour)
	updated, err := f.svc.UpdateProfile(context.Background(), f.org.ID, f.user.ID, p.ID,
		ProfileUpdate{AppName: strPtr("Acme Next")})
	require.NoError(t, err)
	require.Equal(t, "Acme Next", updated.AppName)
	require.True(t, updated.UpdatedAt.After(p.UpdatedAt) || updated.UpdatedAt.Equal(f.now))
	require.Contains(t, f.recorder.actions(), "client_build.profile.update")

	other := f.createProfile(t, "Other", "Other")
	_, err = f.svc.UpdateProfile(context.Background(), f.org.ID, f.user.ID, other.ID,
		ProfileUpdate{Name: strPtr("Acme")})
	require.ErrorIs(t, err, ErrDuplicateName)
}

func TestProfile_DeleteChecksActiveBuildsAndRemovesLogo(t *testing.T) {
	f := newFixture(t)
	p := f.createProfile(t, "Acme", "Acme")
	logo := f.setLogo(t, p.ID, 256)
	build := model.ClientBuild{
		OrganizationID: f.org.ID, ProfileID: p.ID, ProfileName: p.Name, AppName: p.AppName,
		UpstreamVersion: "1.5.0", ManifestJSON: "{}", PlatformsJSON: "[]",
		Status: model.ClientBuildStatusPending, CreatedBy: f.user.ID,
	}
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).Create(&build).Error)

	err := f.svc.DeleteProfile(context.Background(), f.org.ID, f.user.ID, p.ID)
	require.ErrorIs(t, err, ErrProfileInUse)

	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).Model(&build).Update("status", model.ClientBuildStatusSucceeded).Error)
	require.NoError(t, f.svc.DeleteProfile(context.Background(), f.org.ID, f.user.ID, p.ID))
	require.Contains(t, f.recorder.actions(), "client_build.profile.delete")
	_, err = os.Stat(filepath.Join(f.cfg.AssetDir, filepath.FromSlash(logo)))
	require.True(t, os.IsNotExist(err))

	_, err = f.svc.GetProfile(context.Background(), f.otherOrg.ID, p.ID)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestProfile_LogoLifecycle(t *testing.T) {
	f := newFixture(t)
	p := f.createProfile(t, "Acme", "Acme")
	oldRel := f.setLogo(t, p.ID, 256)

	updated, err := f.svc.GetProfile(context.Background(), f.org.ID, p.ID)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(updated.LogoPath,
		"logos/"+strconv.FormatUint(uint64(f.org.ID), 10)+"/"+strconv.FormatUint(uint64(p.ID), 10)+"-"))
	require.Len(t, updated.LogoSHA256, 64)
	require.Equal(t, 256, updated.LogoWidth)
	require.Equal(t, 256, updated.LogoHeight)

	opened, err := f.svc.OpenProfileLogo(context.Background(), f.org.ID, p.ID)
	require.NoError(t, err)
	data, err := io.ReadAll(opened.File)
	opened.File.Close()
	require.NoError(t, err)
	sum := sha256.Sum256(data)
	require.Equal(t, hex.EncodeToString(sum[:]), updated.LogoSHA256)

	newRel := f.setLogo(t, p.ID, 512)
	require.NotEqual(t, oldRel, newRel)
	_, err = os.Stat(filepath.Join(f.cfg.AssetDir, filepath.FromSlash(oldRel)))
	require.True(t, os.IsNotExist(err))

	require.NoError(t, f.svc.DeleteProfileLogo(context.Background(), f.org.ID, f.user.ID, p.ID))
	require.Contains(t, f.recorder.actions(), "client_build.logo.delete")
	_, err = f.svc.OpenProfileLogo(context.Background(), f.org.ID, p.ID)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestProfile_Unaudited(t *testing.T) {
	f := newFixture(t)
	f.svc.recorder = nil
	_, err := f.svc.CreateProfile(context.Background(), f.org.ID, f.user.ID,
		ProfileInput{Name: "Acme", AppName: "Acme"})
	require.ErrorIs(t, err, ErrUnaudited)
}

func (f *fixture) setLogo(t *testing.T, profileID uint, size int) string {
	t.Helper()
	p, err := f.svc.SetProfileLogo(context.Background(), f.org.ID, f.user.ID, profileID, makePNG(t, size, size))
	require.NoError(t, err)
	require.Contains(t, f.recorder.actions(), "client_build.logo.set")
	return p.LogoPath
}

func strPtr(v string) *string { return &v }
