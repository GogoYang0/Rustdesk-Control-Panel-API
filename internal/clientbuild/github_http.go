package clientbuild

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("github API status %d", e.Status)
	}
	return fmt.Sprintf("github API status %d: %s", e.Status, e.Message)
}

type githubClient struct {
	cfg    GitHubConfig
	api    *http.Client
	fetch  func(ctx context.Context, location, dest string, maxBytes int64) (int64, error)
	logger *zap.Logger
	sleep  func(time.Duration)
}

func NewGitHubClient(cfg GitHubConfig, logger *zap.Logger) GitHubClient {
	if logger == nil {
		logger = zap.NewNop()
	}
	cfg.APIBaseURL = strings.TrimRight(strings.TrimSpace(cfg.APIBaseURL), "/")
	c := &githubClient{
		cfg:    cfg,
		api:    &http.Client{Timeout: 30 * time.Second},
		logger: logger,
		sleep:  time.Sleep,
	}
	c.fetch = newArtifactFetcher(cfg.ArtifactHosts).fetch
	return c
}

func (c *githubClient) Dispatch(ctx context.Context, in DispatchInput) (DispatchResult, error) {
	body := map[string]any{
		"ref": c.cfg.Ref,
		// Without this GitHub answers 204 and the run has to be recovered by
		// matching run-name later, which is slower and can pick the wrong run.
		"return_run_details": true,
		"inputs": map[string]string{
			"build_id":         strconv.FormatUint(uint64(in.BuildID), 10),
			"bundle_url":       in.BundleURL,
			"platforms":        strings.Join(in.Platforms, ","),
			"rustdesk_version": in.RustdeskVersion,
		},
	}
	var out struct {
		WorkflowRun struct {
			ID      int64  `json:"id"`
			HTMLURL string `json:"html_url"`
		} `json:"workflow_run"`
	}
	err := c.doJSON(ctx, http.MethodPost,
		fmt.Sprintf("/repos/%s/actions/workflows/%s/dispatches", c.cfg.Repo, c.cfg.Workflow),
		nil, body, &out, false)
	if err != nil {
		return DispatchResult{}, err
	}
	return DispatchResult{RunID: out.WorkflowRun.ID, URL: out.WorkflowRun.HTMLURL}, nil
}

func (c *githubClient) GetRun(ctx context.Context, runID int64) (Run, error) {
	var out runPayload
	err := c.doJSON(ctx, http.MethodGet,
		fmt.Sprintf("/repos/%s/actions/runs/%d", c.cfg.Repo, runID), nil, nil, &out, true)
	if err != nil {
		return Run{}, err
	}
	return out.run(), nil
}

func (c *githubClient) ListRuns(ctx context.Context, since time.Time) ([]Run, error) {
	var runs []Run
	for page := 1; page <= 3; page++ {
		q := url.Values{}
		q.Set("event", "workflow_dispatch")
		q.Set("created", ">="+since.UTC().Format(time.RFC3339))
		q.Set("per_page", "100")
		q.Set("page", strconv.Itoa(page))
		var out struct {
			WorkflowRuns []runPayload `json:"workflow_runs"`
		}
		err := c.doJSON(ctx, http.MethodGet,
			fmt.Sprintf("/repos/%s/actions/runs", c.cfg.Repo), q, nil, &out, true)
		if err != nil {
			return nil, err
		}
		for _, payload := range out.WorkflowRuns {
			runs = append(runs, payload.run())
		}
		if len(out.WorkflowRuns) < 100 {
			break
		}
	}
	return runs, nil
}

func (c *githubClient) CancelRun(ctx context.Context, runID int64) error {
	return c.doJSON(ctx, http.MethodPost,
		fmt.Sprintf("/repos/%s/actions/runs/%d/cancel", c.cfg.Repo, runID),
		nil, nil, nil, false)
}

func (c *githubClient) ListArtifacts(ctx context.Context, runID int64) ([]RemoteArtifact, error) {
	var out struct {
		Artifacts []struct {
			ID        int64  `json:"id"`
			Name      string `json:"name"`
			SizeBytes int64  `json:"size_in_bytes"`
		} `json:"artifacts"`
	}
	q := url.Values{}
	q.Set("per_page", "100")
	err := c.doJSON(ctx, http.MethodGet,
		fmt.Sprintf("/repos/%s/actions/runs/%d/artifacts", c.cfg.Repo, runID), q, nil, &out, true)
	if err != nil {
		return nil, err
	}
	artifacts := make([]RemoteArtifact, 0, len(out.Artifacts))
	for _, item := range out.Artifacts {
		artifacts = append(artifacts, RemoteArtifact{ID: item.ID, Name: item.Name, SizeBytes: item.SizeBytes})
	}
	return artifacts, nil
}

func (c *githubClient) DeleteArtifact(ctx context.Context, artifactID int64) error {
	return c.doJSON(ctx, http.MethodDelete,
		fmt.Sprintf("/repos/%s/actions/artifacts/%d", c.cfg.Repo, artifactID),
		nil, nil, nil, false)
}

func (c *githubClient) DownloadArtifact(ctx context.Context, artifactID int64, destPath string, maxBytes int64) (int64, error) {
	if maxBytes <= 0 {
		return 0, fmt.Errorf("artifact download size limit is required")
	}
	req, err := c.request(ctx, http.MethodGet,
		fmt.Sprintf("/repos/%s/actions/artifacts/%d/zip", c.cfg.Repo, artifactID), nil, nil)
	if err != nil {
		return 0, err
	}
	client := *c.api
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("artifact download request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusOK:
		return writeLimited(resp.Body, destPath, maxBytes)
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		location := resp.Header.Get("Location")
		if location == "" {
			return 0, fmt.Errorf("artifact download redirect has no location")
		}
		if _, err := validateArtifactURL(location, c.cfg.ArtifactHosts); err != nil {
			return 0, err
		}
		if c.fetch == nil {
			return 0, fmt.Errorf("artifact redirect target is not configured")
		}
		return c.fetch(ctx, location, destPath, maxBytes)
	default:
		return 0, &APIError{Status: resp.StatusCode, Message: c.sanitizeBody(resp.Body)}
	}
}

type runPayload struct {
	ID           int64     `json:"id"`
	Status       string    `json:"status"`
	Conclusion   string    `json:"conclusion"`
	URL          string    `json:"html_url"`
	DisplayTitle string    `json:"display_title"`
	CreatedAt    time.Time `json:"created_at"`
}

func (p runPayload) run() Run {
	return Run(p)
}

func (c *githubClient) request(ctx context.Context, method, path string, query url.Values, body any) (*http.Request, error) {
	target := c.cfg.APIBaseURL + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = strings.NewReader(string(raw))
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "rustdesk-control-panel")
	if c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func (c *githubClient) doJSON(ctx context.Context, method, path string, query url.Values, body, out any, retry bool) error {
	attempts := 1
	if retry {
		attempts = 3
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			c.sleep(time.Duration(100<<uint(attempt-1)) * time.Millisecond)
		}
		err := c.doOnce(ctx, method, path, query, body, out)
		if err == nil {
			return nil
		}
		lastErr = err
		if !retry {
			return err
		}
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Status != http.StatusTooManyRequests && apiErr.Status < 500 {
			return err
		}
	}
	return lastErr
}

func (c *githubClient) doOnce(ctx context.Context, method, path string, query url.Values, body, out any) error {
	req, err := c.request(ctx, method, path, query, body)
	if err != nil {
		return err
	}
	resp, err := c.api.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{Status: resp.StatusCode, Message: c.sanitizeBody(resp.Body)}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func (c *githubClient) sanitizeBody(body io.Reader) string {
	raw, _ := io.ReadAll(io.LimitReader(body, 512))
	text := strings.TrimSpace(string(raw))
	if c.cfg.Token != "" {
		text = strings.ReplaceAll(text, c.cfg.Token, "[redacted]")
	}
	return text
}
