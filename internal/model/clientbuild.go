package model

import "time"

const (
	ClientBuildStatusPending     = "pending"
	ClientBuildStatusDispatching = "dispatching"
	ClientBuildStatusDispatched  = "dispatched"
	ClientBuildStatusRunning     = "running"
	ClientBuildStatusIngesting   = "ingesting"
	ClientBuildStatusSucceeded   = "succeeded"
	ClientBuildStatusFailed      = "failed"
	ClientBuildStatusCancelled   = "cancelled"
)

const (
	ClientBuildPlatformWindowsX64   = "windows-x64"
	ClientBuildPlatformLinuxX64     = "linux-x64"
	ClientBuildPlatformMacOSARM64   = "macos-arm64"
	ClientBuildPlatformMacOSX64     = "macos-x64"
	ClientBuildPlatformAndroidARM64 = "android-arm64"
)

func ClientBuildTerminal(status string) bool {
	switch status {
	case ClientBuildStatusSucceeded, ClientBuildStatusFailed, ClientBuildStatusCancelled:
		return true
	default:
		return false
	}
}

type ClientBuildProfile struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	OrganizationID uint      `gorm:"uniqueIndex:idx_cb_profile_org_namekey,priority:1;not null" json:"organization_id"`
	Name           string    `gorm:"size:64;not null" json:"name"`
	NameKey        string    `gorm:"size:64;uniqueIndex:idx_cb_profile_org_namekey,priority:2;not null" json:"name_key"`
	AppName        string    `gorm:"size:32;not null" json:"app_name"`
	LogoPath       string    `gorm:"size:512;not null;default:''" json:"logo_path"`
	LogoSHA256     string    `gorm:"size:64;not null;default:''" json:"logo_sha256"`
	LogoWidth      int       `gorm:"not null;default:0" json:"logo_width"`
	LogoHeight     int       `gorm:"not null;default:0" json:"logo_height"`
	CreatedBy      uint      `gorm:"not null" json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type ClientBuild struct {
	ID                  uint       `gorm:"primaryKey" json:"id"`
	OrganizationID      uint       `gorm:"index:idx_cb_build_org_status,priority:1;index:idx_cb_build_org_created,priority:1;not null" json:"organization_id"`
	ProfileID           uint       `gorm:"not null" json:"profile_id"`
	ProfileName         string     `gorm:"size:64;not null" json:"profile_name"`
	AppName             string     `gorm:"size:32;not null" json:"app_name"`
	UpstreamVersion     string     `gorm:"size:32;not null" json:"upstream_version"`
	ManifestJSON        string     `gorm:"type:text;not null" json:"manifest_json"`
	PlatformsJSON       string     `gorm:"type:text;not null" json:"platforms_json"`
	Status              string     `gorm:"size:16;index:idx_cb_build_status;index:idx_cb_build_org_status,priority:2;not null" json:"status"`
	GitHubRunID         *int64     `gorm:"column:github_run_id" json:"github_run_id"`
	GitHubRunURL        string     `gorm:"column:github_run_url;size:512;not null;default:''" json:"github_run_url"`
	ErrorMessage        string     `gorm:"size:1024;not null;default:''" json:"error_message"`
	ArtifactCount       int        `gorm:"not null;default:0" json:"artifact_count"`
	CreatedBy           uint       `gorm:"not null" json:"created_by"`
	CreatedAt           time.Time  `gorm:"index:idx_cb_build_org_created,priority:2" json:"created_at"`
	DispatchedAt        *time.Time `json:"dispatched_at"`
	DispatchAttemptedAt *time.Time `json:"dispatch_attempted_at"`
	IngestingAt         *time.Time `json:"ingesting_at"`
	FinishedAt          *time.Time `json:"finished_at"`
	CancelRequestedAt   *time.Time `json:"cancel_requested_at"`
	ArtifactsPurgedAt   *time.Time `json:"artifacts_purged_at"`
}

type ClientBuildArtifact struct {
	ID               uint      `gorm:"primaryKey" json:"id"`
	OrganizationID   uint      `gorm:"index;not null" json:"organization_id"`
	BuildID          uint      `gorm:"uniqueIndex:idx_cb_artifact_build_file,priority:1;not null" json:"build_id"`
	Platform         string    `gorm:"size:32;not null" json:"platform"`
	FileName         string    `gorm:"size:255;uniqueIndex:idx_cb_artifact_build_file,priority:2;not null" json:"file_name"`
	SizeBytes        int64     `gorm:"not null" json:"size_bytes"`
	SHA256           string    `gorm:"size:64;not null" json:"sha256"`
	StoragePath      string    `gorm:"size:512;not null" json:"storage_path"`
	RemoteArtifactID int64     `gorm:"not null;default:0" json:"remote_artifact_id"`
	CreatedAt        time.Time `json:"created_at"`
}
