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

func clientBuildSummaryToAPI(row model.ClientBuild) (gen.ClientBuildSummary, error) {
	platforms, err := clientbuild.ParsePlatforms(row.PlatformsJSON)
	if err != nil {
		return gen.ClientBuildSummary{}, err
	}
	out := gen.ClientBuildSummary{
		Id:              int64(row.ID),
		ProfileId:       int64(row.ProfileID),
		ProfileName:     row.ProfileName,
		AppName:         row.AppName,
		UpstreamVersion: row.UpstreamVersion,
		Platforms:       make([]gen.ClientBuildSummaryPlatforms, 0, len(platforms)),
		Status:          gen.ClientBuildSummaryStatus(row.Status),
		GithubRunId:     row.GitHubRunID,
		ArtifactCount:   row.ArtifactCount,
		ArtifactsPurged: row.ArtifactsPurgedAt != nil,
		CreatedAt:       row.CreatedAt,
		DispatchedAt:    row.DispatchedAt,
		FinishedAt:      row.FinishedAt,
	}
	for _, platform := range platforms {
		out.Platforms = append(out.Platforms, gen.ClientBuildSummaryPlatforms(platform))
	}
	if row.GitHubRunURL != "" {
		url := row.GitHubRunURL
		out.GithubRunUrl = &url
	}
	if row.ErrorMessage != "" {
		msg := row.ErrorMessage
		out.ErrorMessage = &msg
	}
	return out, nil
}

func clientBuildManifestToAPI(m clientbuild.Manifest) gen.ClientBuildManifest {
	out := gen.ClientBuildManifest{
		SchemaVersion:   m.SchemaVersion,
		BuildId:         int64(m.BuildID),
		AppName:         m.AppName,
		Server:          m.Server,
		ServerKey:       m.ServerKey,
		ApiServer:       m.APIServer,
		UpstreamVersion: m.UpstreamVersion,
		Platforms:       append([]string{}, m.Platforms...),
	}
	if m.Logo != nil {
		out.Logo = &gen.ClientBuildManifestLogo{
			Sha256: m.Logo.SHA256,
			Width:  m.Logo.Width,
			Height: m.Logo.Height,
		}
	}
	return out
}

func clientBuildArtifactToAPI(row model.ClientBuildArtifact) gen.ClientBuildArtifact {
	return gen.ClientBuildArtifact{
		Id:        int64(row.ID),
		Platform:  row.Platform,
		FileName:  row.FileName,
		SizeBytes: row.SizeBytes,
		Sha256:    row.SHA256,
		CreatedAt: row.CreatedAt,
	}
}

func clientBuildDetailToAPI(detail *clientbuild.BuildDetail) (gen.ClientBuildDetail, error) {
	summary, err := clientBuildSummaryToAPI(detail.Build)
	if err != nil {
		return gen.ClientBuildDetail{}, err
	}
	out := gen.ClientBuildDetail{
		Id:              summary.Id,
		ProfileId:       summary.ProfileId,
		ProfileName:     summary.ProfileName,
		AppName:         summary.AppName,
		UpstreamVersion: summary.UpstreamVersion,
		Platforms:       make([]gen.ClientBuildDetailPlatforms, 0, len(summary.Platforms)),
		Status:          gen.ClientBuildDetailStatus(summary.Status),
		GithubRunId:     summary.GithubRunId,
		GithubRunUrl:    summary.GithubRunUrl,
		ErrorMessage:    summary.ErrorMessage,
		ArtifactCount:   summary.ArtifactCount,
		ArtifactsPurged: summary.ArtifactsPurged,
		CreatedAt:       summary.CreatedAt,
		DispatchedAt:    summary.DispatchedAt,
		FinishedAt:      summary.FinishedAt,
		Manifest:        clientBuildManifestToAPI(detail.Manifest),
		Artifacts:       make([]gen.ClientBuildArtifact, 0, len(detail.Artifacts)),
	}
	for _, platform := range summary.Platforms {
		out.Platforms = append(out.Platforms, gen.ClientBuildDetailPlatforms(platform))
	}
	for i := range detail.Artifacts {
		out.Artifacts = append(out.Artifacts, clientBuildArtifactToAPI(detail.Artifacts[i]))
	}
	return out, nil
}

func clientBuildPageToAPI(page clientbuild.BuildPage) (gen.ClientBuildPage, error) {
	items := make([]gen.ClientBuildSummary, 0, len(page.Items))
	for i := range page.Items {
		item, err := clientBuildSummaryToAPI(page.Items[i])
		if err != nil {
			return gen.ClientBuildPage{}, err
		}
		items = append(items, item)
	}
	return gen.ClientBuildPage{
		Items:    items,
		Page:     page.Page,
		PageSize: int64(page.PageSize),
		Total:    page.Total,
	}, nil
}
