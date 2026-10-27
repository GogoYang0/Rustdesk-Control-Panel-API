package clientbuild

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newGitHubForTest(t *testing.T, baseURL string) *githubClient {
	t.Helper()
	c := NewGitHubClient(GitHubConfig{
		APIBaseURL: baseURL, Repo: "acme/build", Workflow: "build-client.yml",
		Ref: "main", Token: "pat", ArtifactHosts: []string{"github.com"},
	}, zap.NewNop()).(*githubClient)
	c.sleep = func(time.Duration) {}
	return c
}

func TestGitHub_Dispatch(t *testing.T) {
	var gotPath, gotAuth, gotVersion, gotUA string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotVersion = r.Header.Get("X-GitHub-Api-Version")
		gotUA = r.Header.Get("User-Agent")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode dispatch body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"workflow_run":{"id":4242,` +
			`"html_url":"https://github.com/acme/build/actions/runs/4242","display_title":"panel-client-7"}}`))
	}))
	defer srv.Close()

	c := newGitHubForTest(t, srv.URL)
	res, err := c.Dispatch(context.Background(), DispatchInput{
		BuildID: 7, BundleURL: "https://panel.example.com/bundle?token=x",
		Platforms: []string{"linux-x64", "windows-x64"}, RustdeskVersion: "1.5.0",
	})
	require.NoError(t, err)
	require.EqualValues(t, 4242, res.RunID)
	require.Equal(t, "https://github.com/acme/build/actions/runs/4242", res.URL)
	require.Equal(t, "/repos/acme/build/actions/workflows/build-client.yml/dispatches", gotPath)
	require.Equal(t, "Bearer pat", gotAuth)
	require.Equal(t, "2022-11-28", gotVersion)
	require.Equal(t, "rustdesk-control-panel", gotUA)
	require.Equal(t, "main", gotBody["ref"])
	// GitHub only reports the run back when this flag is set; without it the
	// endpoint answers 204 and every dispatch degrades to run-name matching.
	require.Equal(t, true, gotBody["return_run_details"])
	inputs := gotBody["inputs"].(map[string]any)
	require.Equal(t, "7", inputs["build_id"])
	require.Equal(t, "linux-x64,windows-x64", inputs["platforms"])
	require.Equal(t, "1.5.0", inputs["rustdesk_version"])
}

func TestGitHub_DispatchNoContentLeavesRunUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	res, err := newGitHubForTest(t, srv.URL).Dispatch(context.Background(), DispatchInput{BuildID: 7})
	require.NoError(t, err)
	require.Zero(t, res.RunID)
	require.Empty(t, res.URL)
}

func TestGitHub_DispatchDoesNotRetry(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom token=pat"))
	}))
	defer srv.Close()

	c := newGitHubForTest(t, srv.URL)
	_, err := c.Dispatch(context.Background(), DispatchInput{BuildID: 7, Platforms: []string{"linux-x64"}})
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, http.StatusInternalServerError, apiErr.Status)
	require.Equal(t, 1, calls)
	require.NotContains(t, err.Error(), "pat")
}

func TestGitHub_DispatchUnauthorized(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	_, err := newGitHubForTest(t, srv.URL).Dispatch(context.Background(), DispatchInput{BuildID: 7})
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, http.StatusUnauthorized, apiErr.Status)
	require.Equal(t, 1, calls)
}

func TestGitHub_GetRunRetriesTransient(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"id":4242,"status":"completed","conclusion":"success"}`))
	}))
	defer srv.Close()
	run, err := newGitHubForTest(t, srv.URL).GetRun(context.Background(), 4242)
	require.NoError(t, err)
	require.Equal(t, "success", run.Conclusion)
	require.Equal(t, 2, calls)
}

func TestGitHub_GetRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/build/actions/runs/4242" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"id":4242,"status":"in_progress","conclusion":"","html_url":"https://github.com/r/4242","display_title":"panel-client-7","created_at":"2026-10-27T12:00:00Z"}`))
	}))
	defer srv.Close()
	run, err := newGitHubForTest(t, srv.URL).GetRun(context.Background(), 4242)
	require.NoError(t, err)
	require.EqualValues(t, 4242, run.ID)
	require.Equal(t, "in_progress", run.Status)
	require.Equal(t, "panel-client-7", run.DisplayTitle)
	require.Equal(t, time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC), run.CreatedAt)
}

func TestGitHub_ListRunsPaginatesAndFilters(t *testing.T) {
	pages := []int{}
	since := time.Date(2026, 10, 27, 11, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("event"); got != "workflow_dispatch" {
			t.Errorf("event = %q", got)
		}
		if got := r.URL.Query().Get("created"); got != ">="+since.Format(time.RFC3339) {
			t.Errorf("created = %q", got)
		}
		if got := r.URL.Query().Get("per_page"); got != "100" {
			t.Errorf("per_page = %q", got)
		}
		page := r.URL.Query().Get("page")
		pages = append(pages, len(pages)+1)
		if page != fmt.Sprint(len(pages)) {
			t.Errorf("page = %q, want %d", page, len(pages))
		}
		items := make([]string, 0, 100)
		if len(pages) <= 2 {
			for i := 0; i < 100; i++ {
				items = append(items, fmt.Sprintf(`{"id":%d,"status":"completed","display_title":"panel-client-%d"}`, len(pages)*1000+i, len(pages)))
			}
		}
		_, _ = w.Write([]byte(`{"workflow_runs":[` + strings.Join(items, ",") + `]}`))
	}))
	defer srv.Close()
	runs, err := newGitHubForTest(t, srv.URL).ListRuns(context.Background(), since)
	require.NoError(t, err)
	require.Len(t, runs, 200)
	require.Len(t, pages, 3, "a full page is followed until a short/empty page, capped at 3")
}

func TestGitHub_CancelRunAndArtifacts(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		switch {
		case strings.HasSuffix(r.URL.Path, "/cancel"):
			w.WriteHeader(http.StatusAccepted)
		case strings.HasSuffix(r.URL.Path, "/artifacts"):
			_, _ = w.Write([]byte(`{"artifacts":[{"id":9,"name":"panel-client-1-linux-x64","size_in_bytes":123}]}`))
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := newGitHubForTest(t, srv.URL)
	require.NoError(t, c.CancelRun(context.Background(), 4242))
	arts, err := c.ListArtifacts(context.Background(), 4242)
	require.NoError(t, err)
	require.Equal(t, []RemoteArtifact{{ID: 9, Name: "panel-client-1-linux-x64", SizeBytes: 123}}, arts)
	require.NoError(t, c.DeleteArtifact(context.Background(), 9))
	require.Equal(t, []string{
		"POST /repos/acme/build/actions/runs/4242/cancel",
		"GET /repos/acme/build/actions/runs/4242/artifacts",
		"DELETE /repos/acme/build/actions/artifacts/9",
	}, paths)
}

func TestGitHub_CancelRunNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	err := newGitHubForTest(t, srv.URL).CancelRun(context.Background(), 4242)
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, http.StatusNotFound, apiErr.Status)
}

func TestGitHub_DownloadArtifactRedirect(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://github.com/a.zip", http.StatusFound)
	}))
	defer srv.Close()
	c := newGitHubForTest(t, srv.URL)
	var gotLocation string
	c.fetch = func(_ context.Context, location, dest string, max int64) (int64, error) {
		gotLocation = location
		return int64(len("redirected")), nil
	}
	n, err := c.DownloadArtifact(context.Background(), 9, filepath.Join(dir, "a.zip"), 100)
	require.NoError(t, err)
	require.EqualValues(t, len("redirected"), n)
	require.Equal(t, "https://github.com/a.zip", gotLocation)
}

func TestGitHub_DownloadArtifactDirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("direct-bytes"))
	}))
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "direct.zip")
	n, err := newGitHubForTest(t, srv.URL).DownloadArtifact(context.Background(), 9, dest, 100)
	require.NoError(t, err)
	require.EqualValues(t, len("direct-bytes"), n)
	raw, err := os.ReadFile(dest)
	require.NoError(t, err)
	require.Equal(t, "direct-bytes", string(raw))
}

func TestGitHub_DownloadArtifactRejectsUnlistedRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example.com/a.zip", http.StatusFound)
	}))
	defer srv.Close()
	c := newGitHubForTest(t, srv.URL)
	_, err := c.DownloadArtifact(context.Background(), 9, filepath.Join(t.TempDir(), "a.zip"), 100)
	require.Error(t, err)
}
