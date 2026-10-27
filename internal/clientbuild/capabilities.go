package clientbuild

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

type Capabilities struct {
	Enabled           bool
	Platforms         []string
	Limits            Limits
	ProvisioningState string
	Defaults          *Defaults
}

type Limits struct {
	MaxProfilesPerOrg     int
	MaxConcurrentPerOrg   int
	MaxActiveBuilds       int
	MaxArtifactBytes      int64
	ArtifactRetentionDays int
}

type Defaults struct {
	Server    string
	ServerKey string
	APIServer string
}

func (s *Service) Capabilities(ctx context.Context, orgID uint) (Capabilities, error) {
	var org model.Organization
	if err := s.db.WithContext(ctx).Select("id", "provisioning_disabled").
		First(&org, orgID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return Capabilities{}, ErrNotFound
		}
		return Capabilities{}, err
	}
	retentionDays := int(s.cfg.ArtifactRetention / (24 * time.Hour))
	if retentionDays < 1 {
		retentionDays = 1
	}
	caps := Capabilities{
		Enabled:   s.cfg.Enabled,
		Platforms: append([]string{}, s.cfg.Platforms...),
		Limits: Limits{
			MaxProfilesPerOrg:     s.cfg.MaxProfilesPerOrg,
			MaxConcurrentPerOrg:   s.cfg.MaxConcurrentPerOrg,
			MaxActiveBuilds:       s.cfg.MaxActiveBuilds,
			MaxArtifactBytes:      s.cfg.MaxArtifactBytes,
			ArtifactRetentionDays: retentionDays,
		},
		ProvisioningState: "missing",
	}
	if org.ProvisioningDisabled {
		caps.ProvisioningState = "disabled"
		return caps, nil
	}

	var sg model.ServerGroup
	err := store.ScopedByOrg(s.db.WithContext(ctx), orgID).First(&sg).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return caps, nil
	}
	if err != nil {
		return Capabilities{}, err
	}
	caps.ProvisioningState = sg.State
	if sg.State != model.ServerGroupDeployed {
		return caps, nil
	}
	server, err := DeriveServer(s.cfg.RelayHost, sg.HbbsPort)
	if err != nil || ValidateServerKey(sg.PubKey) != nil {
		return caps, nil
	}
	caps.Defaults = &Defaults{
		Server:    server,
		ServerKey: sg.PubKey,
		APIServer: s.cfg.PublicBaseURL,
	}
	return caps, nil
}
