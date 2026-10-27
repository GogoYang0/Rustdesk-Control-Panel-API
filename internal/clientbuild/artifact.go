package clientbuild

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/audit"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

type ArtifactFile struct {
	Artifact model.ClientBuildArtifact
	File     *os.File
}

type stagedArtifact struct {
	platform string
	fileName string
	path     string
	size     int64
	sha256   string
	remoteID int64
}

var platformExtensions = map[string][]string{
	PlatformWindowsX64:   {".exe", ".zip"},
	PlatformLinuxX64:     {".AppImage"},
	PlatformMacOSARM64:   {".dmg"},
	PlatformMacOSX64:     {".dmg"},
	PlatformAndroidARM64: {".apk"},
}

func (s *Service) ingestRun(ctx context.Context, build *model.ClientBuild) error {
	if s.recorder == nil {
		return ErrUnaudited
	}
	if s.github == nil {
		return s.failIngest(ctx, build, "github client is not configured")
	}
	if build.GitHubRunID == nil {
		return s.failIngest(ctx, build, "github run id is missing")
	}
	platforms, err := ParsePlatforms(build.PlatformsJSON)
	if err != nil || len(platforms) == 0 {
		return s.failIngest(ctx, build, "stored platforms are unreadable")
	}
	remote, err := s.github.ListArtifacts(ctx, *build.GitHubRunID)
	if err != nil {
		return s.failIngest(ctx, build, "could not list artifacts")
	}
	expected := make(map[string]RemoteArtifact, len(platforms))
	for _, artifact := range remote {
		prefix := fmt.Sprintf("panel-client-%d-", build.ID)
		if !strings.HasPrefix(artifact.Name, prefix) {
			return s.failIngest(ctx, build, "unexpected artifact")
		}
		platform := strings.TrimPrefix(artifact.Name, prefix)
		if !containsPlatform(platforms, platform) {
			return s.failIngest(ctx, build, "unexpected artifact")
		}
		if _, duplicate := expected[platform]; duplicate {
			return s.failIngest(ctx, build, "duplicate platform artifact")
		}
		expected[platform] = artifact
	}
	if len(remote) != len(platforms) {
		return s.failIngest(ctx, build, "missing platform artifact")
	}
	for _, platform := range platforms {
		if _, ok := expected[platform]; !ok {
			return s.failIngest(ctx, build, "missing platform artifact")
		}
	}

	stage, err := s.storage.NewStaging(build.ID)
	if err != nil {
		return s.failIngest(ctx, build, "could not create staging directory")
	}
	defer func() { _ = os.RemoveAll(stage) }()

	var total int64
	seen := map[string]bool{}
	files := make([]stagedArtifact, 0, len(platforms))
	for _, platform := range platforms {
		remoteArtifact := expected[platform]
		zipPath := filepath.Join(stage, platform+".zip")
		n, err := s.github.DownloadArtifact(ctx, remoteArtifact.ID, zipPath, s.cfg.MaxArtifactBytes)
		if err != nil {
			return s.failIngest(ctx, build, "artifact download failed")
		}
		if n > s.cfg.MaxArtifactBytes {
			return s.failIngest(ctx, build, "artifact download exceeded the size limit")
		}
		platformFiles, err := s.extractArtifact(zipPath, stage, build.ID, platform, &total, seen)
		if err != nil {
			return s.failIngest(ctx, build, err.Error())
		}
		for i := range platformFiles {
			platformFiles[i].remoteID = remoteArtifact.ID
		}
		files = append(files, platformFiles...)
		if err := validatePlatformFiles(platform, platformFiles); err != nil {
			return s.failIngest(ctx, build, err.Error())
		}
	}
	if total > s.cfg.MaxArtifactBytes {
		return s.failIngest(ctx, build, "artifacts exceed the size limit")
	}

	finalDir, err := s.storage.ArtifactDir(build.OrganizationID, build.ID)
	if err != nil {
		return s.failIngest(ctx, build, "could not create artifact directory")
	}
	moved := make([]string, 0, len(files))
	cleanupFinal := func() {
		for _, name := range moved {
			_ = os.Remove(filepath.Join(finalDir, name))
		}
	}
	for _, file := range files {
		dest := filepath.Join(finalDir, file.fileName)
		if err := os.Rename(file.path, dest); err != nil {
			cleanupFinal()
			return s.failIngest(ctx, build, "could not store artifact")
		}
		moved = append(moved, file.fileName)
	}

	now := s.now()
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		scoped := store.ScopedByOrg(tx, build.OrganizationID)
		for _, file := range files {
			row := model.ClientBuildArtifact{
				OrganizationID: build.OrganizationID,
				BuildID:        build.ID,
				Platform:       file.platform,
				FileName:       file.fileName,
				SizeBytes:      file.size,
				SHA256:         file.sha256,
				StoragePath: path.Join("artifacts", strconv.FormatUint(uint64(build.OrganizationID), 10),
					strconv.FormatUint(uint64(build.ID), 10), file.fileName),
				RemoteArtifactID: file.remoteID,
				CreatedAt:        now,
			}
			if err := scoped.Create(&row).Error; err != nil {
				return err
			}
		}
		res := scoped.Model(&model.ClientBuild{}).
			Where("id = ? AND status = ?", build.ID, model.ClientBuildStatusIngesting).
			Updates(map[string]any{
				"status":         model.ClientBuildStatusSucceeded,
				"artifact_count": len(files),
				"finished_at":    now,
				"error_message":  "",
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrConflict
		}
		return s.recorder.RecordTx(tx, audit.Entry{
			OrganizationID: build.OrganizationID,
			Action:         "client_build.succeeded",
			TargetType:     "client_build",
			TargetID:       strconv.FormatUint(uint64(build.ID), 10),
			Detail: map[string]any{
				"artifacts": len(files),
				"run_id":    *build.GitHubRunID,
			},
		})
	})
	if err != nil {
		cleanupFinal()
		return s.failIngest(ctx, build, "could not store artifact records")
	}
	if s.cfg.DeleteRemoteArtifacts {
		for _, artifact := range remote {
			if err := s.github.DeleteArtifact(ctx, artifact.ID); err != nil {
				s.logger.Warn("delete remote build artifact failed",
					zap.Int64("artifact_id", artifact.ID))
			}
		}
	}
	return nil
}

func (s *Service) extractArtifact(
	zipPath, stage string, buildID uint, platform string, total *int64, seen map[string]bool,
) ([]stagedArtifact, error) {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, fmt.Errorf("zip structure is invalid")
	}
	defer func() { _ = reader.Close() }()
	prefix := fmt.Sprintf("panel-client-%d-%s", buildID, platform)
	allowed := platformExtensions[platform]
	maxEntries := len(allowed)
	expected := make(map[string]bool, len(allowed))
	for _, ext := range allowed {
		expected[prefix+ext] = true
	}
	var out []stagedArtifact
	for _, entry := range reader.File {
		rawName := entry.Name
		// Base() is the sanitizer at the file-write sink: every accepted
		// artifact name must be a single path component.
		name := filepath.Base(rawName)
		if entry.FileInfo().IsDir() || entry.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("zip contains a directory or symlink")
		}
		if name != rawName || name == "" || name == "." || name == ".." ||
			strings.ContainsAny(name, `/\`) || path.IsAbs(name) {
			return nil, fmt.Errorf("zip entry path is invalid")
		}
		if len(out) >= maxEntries {
			return nil, fmt.Errorf("artifact contains too many files")
		}
		if !expected[name] {
			return nil, fmt.Errorf("artifact file name is invalid")
		}
		if seen[name] {
			return nil, fmt.Errorf("artifact file name is duplicated")
		}
		if entry.UncompressedSize64 > uint64(s.cfg.MaxArtifactBytes) ||
			*total+int64(entry.UncompressedSize64) > s.cfg.MaxArtifactBytes {
			return nil, fmt.Errorf("artifacts exceed the size limit")
		}
		dest := filepath.Join(stage, name)
		in, err := entry.Open()
		if err != nil {
			return nil, fmt.Errorf("zip entry is unreadable")
		}
		outFile, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			_ = in.Close()
			return nil, fmt.Errorf("could not stage artifact")
		}
		hash := sha256.New()
		written, copyErr := io.Copy(io.MultiWriter(outFile, hash), io.LimitReader(in, s.cfg.MaxArtifactBytes+1))
		_ = in.Close()
		closeErr := outFile.Close()
		if copyErr != nil || closeErr != nil {
			_ = os.Remove(dest)
			return nil, fmt.Errorf("could not stage artifact")
		}
		*total += written
		if *total > s.cfg.MaxArtifactBytes {
			_ = os.Remove(dest)
			return nil, fmt.Errorf("artifacts exceed the size limit")
		}
		seen[name] = true
		out = append(out, stagedArtifact{
			platform: platform,
			fileName: name,
			path:     dest,
			size:     written,
			sha256:   hex.EncodeToString(hash.Sum(nil)),
		})
	}
	return out, nil
}

func validatePlatformFiles(platform string, files []stagedArtifact) error {
	exts := map[string]int{}
	for _, file := range files {
		exts[path.Ext(file.fileName)]++
	}
	if platform == PlatformWindowsX64 {
		if len(files) != 2 || exts[".exe"] != 1 || exts[".zip"] != 1 {
			return fmt.Errorf("windows artifact must contain exactly one exe and one zip")
		}
		return nil
	}
	if len(files) != 1 {
		return fmt.Errorf("platform artifact must contain exactly one file")
	}
	return nil
}

func (s *Service) failBuild(ctx context.Context, build *model.ClientBuild, reason string) error {
	if s.recorder == nil {
		return ErrUnaudited
	}
	if len(reason) > 1024 {
		reason = reason[:1024]
	}
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := store.ScopedByOrg(tx, build.OrganizationID).Model(&model.ClientBuild{}).
			Where("id = ? AND status NOT IN ?", build.ID, []string{
				model.ClientBuildStatusSucceeded, model.ClientBuildStatusFailed, model.ClientBuildStatusCancelled,
			}).Updates(map[string]any{
			"status":        model.ClientBuildStatusFailed,
			"error_message": reason,
			"finished_at":   s.now(),
		})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return nil
		}
		return s.recorder.RecordTx(tx, audit.Entry{
			OrganizationID: build.OrganizationID,
			Action:         "client_build.failed",
			TargetType:     "client_build",
			TargetID:       strconv.FormatUint(uint64(build.ID), 10),
			Detail:         map[string]any{"reason": reason},
		})
	})
	if err != nil {
		return fmt.Errorf("update failed build: %w", err)
	}
	return nil
}

func (s *Service) failIngest(ctx context.Context, build *model.ClientBuild, reason string) error {
	// The ingest context may be canceled by IngestTimeout; the failure status
	// must still be persisted with a fresh deadline.
	statusCtx := context.WithoutCancel(ctx)
	if err := s.failBuild(statusCtx, build, reason); err != nil {
		return err
	}
	return fmt.Errorf("ingest failed: %s", reason)
}

func (s *Service) markIngesting(ctx context.Context, buildID, orgID uint, now time.Time) (bool, error) {
	res := store.ScopedByOrg(s.db.WithContext(ctx), orgID).Model(&model.ClientBuild{}).
		Where("id = ? AND status IN ?", buildID, []string{
			model.ClientBuildStatusDispatching, model.ClientBuildStatusDispatched, model.ClientBuildStatusRunning,
		}).Updates(map[string]any{
		"status":       model.ClientBuildStatusIngesting,
		"ingesting_at": now,
	})
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

func (s *Service) OpenArtifact(ctx context.Context, orgID, buildID, artifactID, actorID uint) (*ArtifactFile, error) {
	var build model.ClientBuild
	err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).First(&build, buildID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if build.Status != model.ClientBuildStatusSucceeded || build.ArtifactsPurgedAt != nil {
		return nil, ErrArtifactUnavailable
	}
	var artifact model.ClientBuildArtifact
	err = store.ScopedByOrg(s.db.WithContext(ctx), orgID).
		Where("build_id = ? AND id = ?", buildID, artifactID).First(&artifact).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrArtifactUnavailable
	}
	if err != nil {
		return nil, err
	}
	f, err := s.storage.Open(artifact.StoragePath)
	if err != nil {
		return nil, ErrArtifactUnavailable
	}
	if s.auditor == nil {
		_ = f.Close()
		return nil, ErrUnaudited
	}
	if err := s.auditor.Record(ctx, audit.Entry{
		OrganizationID: orgID,
		ActorUserID:    actorID,
		Action:         "client_build.artifact.download",
		TargetType:     "client_build_artifact",
		TargetID:       strconv.FormatUint(uint64(artifact.ID), 10),
		Detail: map[string]any{
			"build_id":  buildID,
			"file_name": artifact.FileName,
		},
	}); err != nil {
		_ = f.Close()
		return nil, ErrUnaudited
	}
	return &ArtifactFile{Artifact: artifact, File: f}, nil
}

func containsPlatform(platforms []string, platform string) bool {
	for _, p := range platforms {
		if p == platform {
			return true
		}
	}
	return false
}
