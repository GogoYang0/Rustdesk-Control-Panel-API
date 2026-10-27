package clientbuild

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

func TestCapabilities_Deployed(t *testing.T) {
	f := newFixture(t)
	caps, err := f.svc.Capabilities(context.Background(), f.org.ID)
	require.NoError(t, err)
	require.True(t, caps.Enabled)
	require.Equal(t, "deployed", caps.ProvisioningState)
	require.NotNil(t, caps.Defaults)
	require.Equal(t, fmt.Sprintf("relay.example.com:%d", f.sg.HbbsPort+1), caps.Defaults.Server)
	require.Equal(t, f.sg.PubKey, caps.Defaults.ServerKey)
	require.Equal(t, "https://panel.example.com", caps.Defaults.APIServer)
	require.Equal(t, f.cfg.MaxProfilesPerOrg, caps.Limits.MaxProfilesPerOrg)
	require.Equal(t, f.cfg.MaxConcurrentPerOrg, caps.Limits.MaxConcurrentPerOrg)
	require.Len(t, caps.Platforms, len(SupportedPlatforms))
}

func TestCapabilities_MissingAndDisabled(t *testing.T) {
	f := newFixture(t)
	caps, err := f.svc.Capabilities(context.Background(), f.otherOrg.ID)
	require.NoError(t, err)
	require.Equal(t, "missing", caps.ProvisioningState)
	require.Nil(t, caps.Defaults)

	require.NoError(t, f.db.Model(&model.Organization{}).
		Where("id = ?", f.otherOrg.ID).Update("provisioning_disabled", true).Error)
	caps, err = f.svc.Capabilities(context.Background(), f.otherOrg.ID)
	require.NoError(t, err)
	require.Equal(t, "disabled", caps.ProvisioningState)
	require.Nil(t, caps.Defaults)
}

func TestCapabilities_FeatureDisabled(t *testing.T) {
	f := newFixture(t)
	f.svc.cfg.Enabled = false
	caps, err := f.svc.Capabilities(context.Background(), f.org.ID)
	require.NoError(t, err)
	require.False(t, caps.Enabled)
	require.NotEmpty(t, caps.Platforms)
	require.NotZero(t, caps.Limits.MaxActiveBuilds)
}
