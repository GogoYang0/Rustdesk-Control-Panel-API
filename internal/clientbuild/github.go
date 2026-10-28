package clientbuild

import (
	"context"
	"time"
)

type GitHubClient interface {
	Dispatch(ctx context.Context, in DispatchInput) (DispatchResult, error)
	GetRun(ctx context.Context, runID int64) (Run, error)
	ListRuns(ctx context.Context, since time.Time) ([]Run, error)
	CancelRun(ctx context.Context, runID int64) error
	ListArtifacts(ctx context.Context, runID int64) ([]RemoteArtifact, error)
	DownloadArtifact(ctx context.Context, artifactID int64, destPath string, maxBytes int64) (int64, error)
	DeleteArtifact(ctx context.Context, artifactID int64) error
}

type DispatchInput struct {
	BuildID         uint
	BundleURL       string
	Platforms       []string
	RustdeskVersion string
}

type DispatchResult struct {
	RunID int64
	URL   string
}

type Run struct {
	ID           int64
	Status       string
	Conclusion   string
	URL          string
	DisplayTitle string
	CreatedAt    time.Time
}

type RemoteArtifact struct {
	ID        int64
	Name      string
	SizeBytes int64
}
