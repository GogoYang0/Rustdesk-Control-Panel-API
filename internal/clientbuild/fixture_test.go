package clientbuild

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/config"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

var fixtureSeq atomic.Int64

type fakeRecorder struct {
	entries []audit.Entry
	fail    error
}

func (f *fakeRecorder) RecordTx(_ *gorm.DB, e audit.Entry) error {
	if f.fail != nil {
		return f.fail
	}
	f.entries = append(f.entries, e)
	return nil
}

func (f *fakeRecorder) Record(_ context.Context, e audit.Entry) error {
	return f.RecordTx(nil, e)
}

func (f *fakeRecorder) actions() []string {
	out := make([]string, 0, len(f.entries))
	for _, e := range f.entries {
		out = append(out, e.Action)
	}
	return out
}

type fakeGitHub struct {
	dispatchFn      func(context.Context, DispatchInput) (DispatchResult, error)
	getRunFn        func(context.Context, int64) (Run, error)
	listRunsFn      func(context.Context, time.Time) ([]Run, error)
	cancelRunFn     func(context.Context, int64) error
	listArtifactsFn func(context.Context, int64) ([]RemoteArtifact, error)
	downloadFn      func(context.Context, int64, string, int64) (int64, error)
	deleteFn        func(context.Context, int64) error
}

func (f *fakeGitHub) Dispatch(ctx context.Context, in DispatchInput) (DispatchResult, error) {
	if f.dispatchFn == nil {
		return DispatchResult{}, nil
	}
	return f.dispatchFn(ctx, in)
}

func (f *fakeGitHub) GetRun(ctx context.Context, id int64) (Run, error) {
	if f.getRunFn == nil {
		return Run{}, nil
	}
	return f.getRunFn(ctx, id)
}

func (f *fakeGitHub) ListRuns(ctx context.Context, since time.Time) ([]Run, error) {
	if f.listRunsFn == nil {
		return nil, nil
	}
	return f.listRunsFn(ctx, since)
}

func (f *fakeGitHub) CancelRun(ctx context.Context, id int64) error {
	if f.cancelRunFn == nil {
		return nil
	}
	return f.cancelRunFn(ctx, id)
}

func (f *fakeGitHub) ListArtifacts(ctx context.Context, id int64) ([]RemoteArtifact, error) {
	if f.listArtifactsFn == nil {
		return nil, nil
	}
	return f.listArtifactsFn(ctx, id)
}

func (f *fakeGitHub) DownloadArtifact(ctx context.Context, id int64, dest string, max int64) (int64, error) {
	if f.downloadFn == nil {
		return 0, nil
	}
	return f.downloadFn(ctx, id, dest, max)
}

func (f *fakeGitHub) DeleteArtifact(ctx context.Context, id int64) error {
	if f.deleteFn == nil {
		return nil
	}
	return f.deleteFn(ctx, id)
}

type fixture struct {
	db       *gorm.DB
	svc      *Service
	cfg      Config
	recorder *fakeRecorder
	github   *fakeGitHub
	org      model.Organization
	otherOrg model.Organization
	user     model.User
	sg       model.ServerGroup
	now      time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	n := fixtureSeq.Add(1)
	st, err := store.Open(config.DatabaseConfig{
		Driver: "sqlite",
		DSN:    fmt.Sprintf("file:clientbuild_%d?mode=memory&cache=shared", n),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	require.NoError(t, st.DB.AutoMigrate(
		&model.Organization{}, &model.User{}, &model.ServerGroup{},
		&model.ClientBuildProfile{}, &model.ClientBuild{}, &model.ClientBuildArtifact{},
	))

	f := &fixture{
		db:       st.DB,
		recorder: &fakeRecorder{},
		github:   &fakeGitHub{},
		now:      time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC),
	}
	f.org = model.Organization{Name: fmt.Sprintf("cb-org-%d", n)}
	f.otherOrg = model.Organization{Name: fmt.Sprintf("cb-other-%d", n)}
	require.NoError(t, f.db.Create(&f.org).Error)
	require.NoError(t, f.db.Create(&f.otherOrg).Error)
	f.user = model.User{
		Email: fmt.Sprintf("cb-user-%d@example.com", n), PasswordHash: "x", EmailVerified: true,
	}
	require.NoError(t, f.db.Create(&f.user).Error)
	f.sg = model.ServerGroup{
		OrganizationID: f.org.ID, HbbsPort: 21116, HbbrPort: 21119,
		PubKey: "dGVzdC1rZXktMDEyMzQ1Njc4OWFiY2RlZmdoaWo=",
		State:  model.ServerGroupDeployed,
	}
	require.NoError(t, f.db.Create(&f.sg).Error)

	f.cfg = validConfig()
	f.cfg.AssetDir = t.TempDir()
	svc, err := NewService(st.DB, f.recorder, f.recorder, f.cfg, f.github, zap.NewNop(),
		func() time.Time { return f.now })
	require.NoError(t, err)
	f.svc = svc
	return f
}

func (f *fixture) createProfile(t *testing.T, name, appName string) *model.ClientBuildProfile {
	t.Helper()
	p, err := f.svc.CreateProfile(context.Background(), f.org.ID, f.user.ID,
		ProfileInput{Name: name, AppName: appName})
	require.NoError(t, err)
	return p
}
