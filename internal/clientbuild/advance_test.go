package clientbuild

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

func (f *fixture) buildRow(t *testing.T, id uint) model.ClientBuild {
	t.Helper()
	var row model.ClientBuild
	require.NoError(t, store.WithoutTenantScope(f.db).First(&row, id).Error)
	return row
}

func (f *fixture) setBuild(t *testing.T, id uint, updates map[string]any) {
	t.Helper()
	require.NoError(t, store.WithoutTenantScope(f.db).Model(&model.ClientBuild{}).
		Where("id = ?", id).Updates(updates).Error)
}

func (f *fixture) advance(t *testing.T) {
	t.Helper()
	_, err := f.svc.Advance(context.Background())
	require.NoError(t, err)
}

func TestAdvance_DispatchesPending(t *testing.T) {
	f := newFixture(t)
	p := f.createProfile(t, "Acme", "Acme")
	d := f.createBuild(t, p.ID, []string{"linux-x64"})
	calls := 0
	f.github.dispatchFn = func(context.Context, DispatchInput) (DispatchResult, error) {
		calls++
		return DispatchResult{RunID: 4242, URL: "https://github.com/r/4242"}, nil
	}
	f.github.getRunFn = func(_ context.Context, id int64) (Run, error) {
		return Run{ID: id, Status: "queued", URL: "https://github.com/r/4242"}, nil
	}
	f.advance(t)
	row := f.buildRow(t, d.Build.ID)
	require.Equal(t, model.ClientBuildStatusDispatched, row.Status)
	require.NotNil(t, row.GitHubRunID)
	require.EqualValues(t, 4242, *row.GitHubRunID)
	require.Equal(t, 1, calls)
}

func TestAdvance_AmbiguousDispatchNoRetryThenTimeout(t *testing.T) {
	f := newFixture(t)
	p := f.createProfile(t, "Acme", "Acme")
	d := f.createBuild(t, p.ID, []string{"linux-x64"})
	calls := 0
	f.github.dispatchFn = func(context.Context, DispatchInput) (DispatchResult, error) {
		calls++
		return DispatchResult{}, errors.New("network down")
	}
	f.advance(t)
	row := f.buildRow(t, d.Build.ID)
	require.Equal(t, model.ClientBuildStatusDispatching, row.Status)
	require.NotNil(t, row.DispatchAttemptedAt)

	f.github.dispatchFn = func(context.Context, DispatchInput) (DispatchResult, error) {
		t.Error("a build with a dispatch marker must never be dispatched again")
		return DispatchResult{}, nil
	}
	f.advance(t)
	require.Equal(t, 1, calls)

	f.now = f.now.Add(11 * time.Minute)
	f.advance(t)
	require.Equal(t, model.ClientBuildStatusFailed, f.buildRow(t, d.Build.ID).Status)
}

func TestAdvance_PendingTimeoutBeforeDispatch(t *testing.T) {
	f := newFixture(t)
	p := f.createProfile(t, "Acme", "Acme")
	d := f.createBuild(t, p.ID, []string{"linux-x64"})
	f.setBuild(t, d.Build.ID, map[string]any{"created_at": f.now.Add(-13 * time.Hour)})
	f.github.dispatchFn = func(context.Context, DispatchInput) (DispatchResult, error) {
		t.Error("an expired pending build must not be dispatched")
		return DispatchResult{}, nil
	}
	f.advance(t)
	row := f.buildRow(t, d.Build.ID)
	require.Equal(t, model.ClientBuildStatusFailed, row.Status)
	require.Contains(t, row.ErrorMessage, "queue timeout")
}

func TestAdvance_NoRunIDWaitsForRecovery(t *testing.T) {
	f := newFixture(t)
	p := f.createProfile(t, "Acme", "Acme")
	d := f.createBuild(t, p.ID, []string{"linux-x64"})
	f.github.dispatchFn = func(context.Context, DispatchInput) (DispatchResult, error) {
		return DispatchResult{}, nil
	}
	f.advance(t)
	row := f.buildRow(t, d.Build.ID)
	require.Equal(t, model.ClientBuildStatusDispatching, row.Status)
	require.NotNil(t, row.DispatchAttemptedAt)
	f.advance(t)
	require.Equal(t, model.ClientBuildStatusDispatching, f.buildRow(t, d.Build.ID).Status)
}

func TestAdvance_RecoversRunByName(t *testing.T) {
	f := newFixture(t)
	p := f.createProfile(t, "Acme", "Acme")
	d := f.createBuild(t, p.ID, []string{"linux-x64"})
	f.github.dispatchFn = func(context.Context, DispatchInput) (DispatchResult, error) {
		return DispatchResult{}, errors.New("result unknown")
	}
	f.advance(t)
	title := "panel-client-" + itoa(d.Build.ID)
	f.github.listRunsFn = func(context.Context, time.Time) ([]Run, error) {
		return []Run{{ID: 4242, Status: "in_progress", DisplayTitle: title, CreatedAt: f.now}}, nil
	}
	f.github.getRunFn = func(context.Context, int64) (Run, error) {
		return Run{ID: 4242, Status: "in_progress", DisplayTitle: title}, nil
	}
	f.advance(t)
	row := f.buildRow(t, d.Build.ID)
	require.Equal(t, model.ClientBuildStatusRunning, row.Status)
	require.EqualValues(t, 4242, *row.GitHubRunID)
}

func TestAdvance_ActiveCapExcludesPending(t *testing.T) {
	f := newFixture(t)
	f.svc.cfg.MaxConcurrentPerOrg = 5
	p := f.createProfile(t, "Acme", "Acme")
	for i := 0; i < 5; i++ {
		f.createBuild(t, p.ID, []string{"linux-x64"})
	}
	nextRun := int64(100)
	f.github.dispatchFn = func(context.Context, DispatchInput) (DispatchResult, error) {
		nextRun++
		return DispatchResult{RunID: nextRun}, nil
	}
	f.github.getRunFn = func(_ context.Context, id int64) (Run, error) {
		return Run{ID: id, Status: "queued"}, nil
	}
	f.advance(t)

	page, err := f.svc.ListBuilds(context.Background(), f.org.ID, BuildFilter{PageSize: 10})
	require.NoError(t, err)
	dispatched := 0
	pending := 0
	for _, row := range page.Items {
		switch row.Status {
		case model.ClientBuildStatusDispatched:
			dispatched++
		case model.ClientBuildStatusPending:
			pending++
		}
	}
	require.Equal(t, 4, dispatched)
	require.Equal(t, 1, pending)

	// Free one slot; the fifth pending build is dispatched on the next pass.
	for _, row := range page.Items {
		if row.Status == model.ClientBuildStatusDispatched {
			f.setBuild(t, row.ID, map[string]any{"status": model.ClientBuildStatusFailed})
			break
		}
	}
	f.advance(t)
	page, err = f.svc.ListBuilds(context.Background(), f.org.ID, BuildFilter{PageSize: 10})
	require.NoError(t, err)
	dispatched = 0
	for _, row := range page.Items {
		if row.Status == model.ClientBuildStatusDispatched {
			dispatched++
		}
	}
	require.Equal(t, 4, dispatched)
}

func TestAdvance_CancelPendingAndClaimedWithoutMarker(t *testing.T) {
	t.Run("pending", func(t *testing.T) {
		f := newFixture(t)
		p := f.createProfile(t, "Acme", "Acme")
		d := f.createBuild(t, p.ID, []string{"linux-x64"})
		_, err := f.svc.CancelBuild(context.Background(), f.org.ID, f.user.ID, d.Build.ID)
		require.NoError(t, err)
		f.github.dispatchFn = func(context.Context, DispatchInput) (DispatchResult, error) {
			t.Error("a cancelled pending build must not dispatch")
			return DispatchResult{}, nil
		}
		f.advance(t)
		require.Equal(t, model.ClientBuildStatusCancelled, f.buildRow(t, d.Build.ID).Status)
	})
	t.Run("claimed but not sent", func(t *testing.T) {
		f := newFixture(t)
		p := f.createProfile(t, "Acme", "Acme")
		d := f.createBuild(t, p.ID, []string{"linux-x64"})
		now := f.now
		f.setBuild(t, d.Build.ID, map[string]any{
			"status": model.ClientBuildStatusDispatching, "dispatched_at": now, "cancel_requested_at": now,
		})
		f.github.dispatchFn = func(context.Context, DispatchInput) (DispatchResult, error) {
			t.Error("a cancelled claimed build must not dispatch")
			return DispatchResult{}, nil
		}
		f.advance(t)
		require.Equal(t, model.ClientBuildStatusCancelled, f.buildRow(t, d.Build.ID).Status)
	})
}

func TestAdvance_CancelDispatchingWithRun(t *testing.T) {
	f := newFixture(t)
	p := f.createProfile(t, "Acme", "Acme")
	d := f.createBuild(t, p.ID, []string{"linux-x64"})
	now := f.now
	f.setBuild(t, d.Build.ID, map[string]any{
		"status": model.ClientBuildStatusDispatching, "dispatch_attempted_at": now,
		"github_run_id": 4242, "cancel_requested_at": now,
	})
	cancelCalled := false
	f.github.cancelRunFn = func(_ context.Context, id int64) error {
		require.EqualValues(t, 4242, id)
		cancelCalled = true
		return nil
	}
	f.github.getRunFn = func(context.Context, int64) (Run, error) {
		return Run{ID: 4242, Status: "completed", Conclusion: "cancelled"}, nil
	}
	f.advance(t)
	require.True(t, cancelCalled)
	require.Equal(t, model.ClientBuildStatusCancelled, f.buildRow(t, d.Build.ID).Status)
}

func TestAdvance_SuccessAndCancelledAfterSuccess(t *testing.T) {
	success := func(t *testing.T) *fixture {
		f := newFixture(t)
		p := f.createProfile(t, "Acme", "Acme")
		d := f.createBuild(t, p.ID, []string{"linux-x64"})
		f.github.dispatchFn = func(context.Context, DispatchInput) (DispatchResult, error) {
			return DispatchResult{RunID: 4242}, nil
		}
		f.github.getRunFn = func(context.Context, int64) (Run, error) {
			return Run{ID: 4242, Status: "completed", Conclusion: "success"}, nil
		}
		zipName := "panel-client-" + itoa(d.Build.ID) + "-linux-x64"
		f.fakeArtifacts(d.Build.ID, map[string][]byte{
			zipName: makeZip(t, zipEntry{Name: zipName + ".AppImage", Body: []byte("x")}),
		})
		return f
	}

	t.Run("success", func(t *testing.T) {
		f := success(t)
		f.advance(t)
		var row model.ClientBuild
		require.NoError(t, store.WithoutTenantScope(f.db).Order("id DESC").First(&row).Error)
		require.Equal(t, model.ClientBuildStatusSucceeded, row.Status)
		require.Equal(t, 1, row.ArtifactCount)
	})

	t.Run("cancelled", func(t *testing.T) {
		f := success(t)
		f.advance(t)
		var row model.ClientBuild
		require.NoError(t, store.WithoutTenantScope(f.db).Order("id DESC").First(&row).Error)
		// Reset to a running build with a cancel request to exercise the
		// success-but-cancelled branch.
		f.setBuild(t, row.ID, map[string]any{
			"status": model.ClientBuildStatusRunning, "cancel_requested_at": f.now,
			"artifact_count": 0, "finished_at": nil,
		})
		require.NoError(t, store.WithoutTenantScope(f.db).
			Where("build_id = ?", row.ID).Delete(&model.ClientBuildArtifact{}).Error)
		f.advance(t)
		row = f.buildRow(t, row.ID)
		require.Equal(t, model.ClientBuildStatusCancelled, row.Status)
	})
}

func TestAdvance_RunFailure(t *testing.T) {
	f := newFixture(t)
	p := f.createProfile(t, "Acme", "Acme")
	d := f.createBuild(t, p.ID, []string{"linux-x64"})
	f.github.dispatchFn = func(context.Context, DispatchInput) (DispatchResult, error) {
		return DispatchResult{RunID: 4242}, nil
	}
	f.github.getRunFn = func(context.Context, int64) (Run, error) {
		return Run{ID: 4242, Status: "completed", Conclusion: "failure"}, nil
	}
	f.advance(t)
	require.Equal(t, model.ClientBuildStatusFailed, f.buildRow(t, d.Build.ID).Status)
}

func TestAdvance_IngestTimeoutCanceledDownload(t *testing.T) {
	f := newFixture(t)
	f.svc.cfg.IngestTimeout = 50 * time.Millisecond
	p := f.createProfile(t, "Acme", "Acme")
	d := f.createBuild(t, p.ID, []string{"linux-x64"})
	f.github.dispatchFn = func(context.Context, DispatchInput) (DispatchResult, error) {
		return DispatchResult{RunID: 4242}, nil
	}
	f.github.getRunFn = func(context.Context, int64) (Run, error) {
		return Run{ID: 4242, Status: "completed", Conclusion: "success"}, nil
	}
	zipName := "panel-client-" + itoa(d.Build.ID) + "-linux-x64"
	f.fakeArtifacts(d.Build.ID, map[string][]byte{
		zipName: makeZip(t, zipEntry{Name: zipName + ".AppImage", Body: []byte("x")}),
	})
	f.github.downloadFn = func(ctx context.Context, _ int64, _ string, _ int64) (int64, error) {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	_, err := f.svc.Advance(context.Background())
	require.Error(t, err)
	row := f.buildRow(t, d.Build.ID)
	require.Equal(t, model.ClientBuildStatusFailed, row.Status)
	require.Contains(t, row.ErrorMessage, "artifact download failed")
}

func TestAdvance_BuildTimeout(t *testing.T) {
	f := newFixture(t)
	p := f.createProfile(t, "Acme", "Acme")
	d := f.createBuild(t, p.ID, []string{"linux-x64"})
	f.github.dispatchFn = func(context.Context, DispatchInput) (DispatchResult, error) {
		return DispatchResult{RunID: 4242}, nil
	}
	f.github.getRunFn = func(context.Context, int64) (Run, error) {
		return Run{ID: 4242, Status: "in_progress"}, nil
	}
	f.advance(t)
	f.setBuild(t, d.Build.ID, map[string]any{"dispatched_at": f.now.Add(-4 * time.Hour)})
	cancelCalled := false
	f.github.cancelRunFn = func(context.Context, int64) error { cancelCalled = true; return nil }
	f.advance(t)
	require.True(t, cancelCalled)
	row := f.buildRow(t, d.Build.ID)
	require.Equal(t, model.ClientBuildStatusFailed, row.Status)
	require.Contains(t, row.ErrorMessage, "build timeout")
}

func TestAdvance_IngestTimeout(t *testing.T) {
	f := newFixture(t)
	p := f.createProfile(t, "Acme", "Acme")
	d := f.createBuild(t, p.ID, []string{"linux-x64"})
	f.setBuild(t, d.Build.ID, map[string]any{
		"status": model.ClientBuildStatusIngesting, "ingesting_at": f.now.Add(-2 * time.Hour),
	})
	f.advance(t)
	row := f.buildRow(t, d.Build.ID)
	require.Equal(t, model.ClientBuildStatusFailed, row.Status)
	require.Contains(t, row.ErrorMessage, "ingest timeout")
}

func TestAdvance_TerminalUnchanged(t *testing.T) {
	f := newFixture(t)
	p := f.createProfile(t, "Acme", "Acme")
	d := f.createBuild(t, p.ID, []string{"linux-x64"})
	f.setBuild(t, d.Build.ID, map[string]any{"status": model.ClientBuildStatusSucceeded})
	before := len(f.recorder.entries)
	f.advance(t)
	require.Equal(t, model.ClientBuildStatusSucceeded, f.buildRow(t, d.Build.ID).Status)
	require.Len(t, f.recorder.entries, before)
}

func TestAdvance_NilGitHubFailsClosed(t *testing.T) {
	f := newFixture(t)
	f.svc.github = nil
	_, err := f.svc.Advance(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "github client")
}

func TestAdvance_MatchRunIgnoresNonMatchingTitles(t *testing.T) {
	run := matchRun([]Run{{ID: 1, DisplayTitle: "panel-client-9", CreatedAt: time.Now()}}, 7)
	require.Nil(t, run)
}

func TestAdvance_DispatchInputFailureDoesNotStopThePass(t *testing.T) {
	f := newFixture(t)
	p := f.createProfile(t, "Acme", "Acme")
	bad := f.createBuild(t, p.ID, []string{"linux-x64"})
	good := f.createBuild(t, p.ID, []string{"linux-x64"})
	require.NoError(t, store.WithoutTenantScope(f.db).Model(&model.ClientBuild{}).
		Where("id = ?", bad.Build.ID).Update("platforms_json", "{not-json").Error)
	f.github.dispatchFn = func(context.Context, DispatchInput) (DispatchResult, error) {
		return DispatchResult{RunID: 4242, URL: "https://github.com/r/4242"}, nil
	}
	f.github.getRunFn = func(_ context.Context, id int64) (Run, error) {
		return Run{ID: id, Status: "queued"}, nil
	}

	f.advance(t)

	require.Equal(t, model.ClientBuildStatusFailed, f.buildRow(t, bad.Build.ID).Status)
	require.Equal(t, model.ClientBuildStatusDispatched, f.buildRow(t, good.Build.ID).Status)
}
