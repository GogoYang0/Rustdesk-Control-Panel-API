package api

import (
	"github.com/GogoYang0/rustdesk-control-panel-api/gen"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/clientbuild"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

func clientBuildCapabilitiesToAPI(c clientbuild.Capabilities) gen.ClientBuildCapabilities {
	platforms := make([]gen.ClientBuildCapabilitiesPlatforms, 0, len(c.Platforms))
	for _, platform := range c.Platforms {
		platforms = append(platforms, gen.ClientBuildCapabilitiesPlatforms(platform))
	}
	out := gen.ClientBuildCapabilities{
		Enabled:   c.Enabled,
		Platforms: platforms,
		Limits: gen.ClientBuildLimits{
			MaxProfilesPerOrg:     c.Limits.MaxProfilesPerOrg,
			MaxConcurrentPerOrg:   c.Limits.MaxConcurrentPerOrg,
			MaxActiveBuilds:       c.Limits.MaxActiveBuilds,
			MaxArtifactBytes:      c.Limits.MaxArtifactBytes,
			ArtifactRetentionDays: c.Limits.ArtifactRetentionDays,
		},
		ProvisioningState: gen.ClientBuildCapabilitiesProvisioningState(c.ProvisioningState),
	}
	if c.Defaults != nil {
		out.Defaults = &gen.ClientBuildDefaults{
			Server:    c.Defaults.Server,
			ServerKey: c.Defaults.ServerKey,
			ApiServer: c.Defaults.APIServer,
		}
	}
	return out
}

func clientBuildProfileToAPI(row *model.ClientBuildProfile) gen.ClientBuildProfile {
	return gen.ClientBuildProfile{
		Id:         int64(row.ID),
		Name:       row.Name,
		AppName:    row.AppName,
		HasLogo:    row.LogoPath != "",
		LogoWidth:  row.LogoWidth,
		LogoHeight: row.LogoHeight,
		LogoSha256: row.LogoSHA256,
		CreatedAt:  row.CreatedAt,
		UpdatedAt:  row.UpdatedAt,
	}
}

func clientBuildProfilePageToAPI(page clientbuild.ProfilePage) gen.ClientBuildProfilePage {
	items := make([]gen.ClientBuildProfile, 0, len(page.Items))
	for i := range page.Items {
		items = append(items, clientBuildProfileToAPI(&page.Items[i]))
	}
	return gen.ClientBuildProfilePage{
		Items:    items,
		Page:     page.Page,
		PageSize: int64(page.PageSize),
		Total:    page.Total,
	}
}
