package clientbuild

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

func testManifest(t *testing.T) Manifest {
	t.Helper()
	profile := &model.ClientBuildProfile{
		AppName: "Acme", LogoPath: "logos/1/2-abc.png",
		LogoSHA256: "0123456789abcdef", LogoWidth: 256, LogoHeight: 256,
	}
	sg := &model.ServerGroup{
		HbbsPort: 21116, PubKey: "dGVzdC1rZXktMDEyMzQ1Njc4OWFiY2RlZmdoaWo=",
	}
	m, err := NewManifest(42, profile, sg, "relay.example.com", "https://panel.example.com",
		"1.5.0", []string{"linux-x64", "windows-x64"})
	require.NoError(t, err)
	return m
}

func TestNewManifest(t *testing.T) {
	m := testManifest(t)
	require.Equal(t, 1, m.SchemaVersion)
	require.EqualValues(t, 42, m.BuildID)
	require.Equal(t, "Acme", m.AppName)
	require.Equal(t, "relay.example.com:21117", m.Server)
	require.Equal(t, "https://panel.example.com", m.APIServer)
	require.Equal(t, "dGVzdC1rZXktMDEyMzQ1Njc4OWFiY2RlZmdoaWo=", m.ServerKey)
	require.Equal(t, "1.5.0", m.UpstreamVersion)
	require.Equal(t, []string{"windows-x64", "linux-x64"}, m.Platforms)
	require.NotNil(t, m.Logo)
	require.Equal(t, "0123456789abcdef", m.Logo.SHA256)
	require.Equal(t, 256, m.Logo.Width)

	profileNoLogo := &model.ClientBuildProfile{AppName: "Acme"}
	sg := &model.ServerGroup{HbbsPort: 21116, PubKey: "dGVzdC1rZXktMDEyMzQ1Njc4OWFiY2RlZmdoaWo="}
	plain, err := NewManifest(7, profileNoLogo, sg, "relay.example.com", "https://panel.example.com",
		"1.5.0", []string{"linux-x64"})
	require.NoError(t, err)
	require.Nil(t, plain.Logo)

	badKey := *sg
	badKey.PubKey = `bad"key`
	_, err = NewManifest(7, profileNoLogo, &badKey, "relay.example.com", "https://panel.example.com",
		"1.5.0", []string{"linux-x64"})
	require.Error(t, err)
}

func TestManifestJSONRoundTrip(t *testing.T) {
	m := testManifest(t)
	raw, err := m.JSON()
	require.NoError(t, err)
	parsed, err := ParseManifest(string(raw))
	require.NoError(t, err)
	require.Equal(t, m, parsed)

	platforms, err := MarshalPlatforms([]string{"linux-x64", "windows-x64"})
	require.NoError(t, err)
	round, err := ParsePlatforms(platforms)
	require.NoError(t, err)
	require.Equal(t, []string{"linux-x64", "windows-x64"}, round)
}

func TestManifestRejectsIncompleteLogo(t *testing.T) {
	profile := &model.ClientBuildProfile{AppName: "Acme", LogoPath: "logos/1/2.png"}
	sg := &model.ServerGroup{HbbsPort: 21116, PubKey: "dGVzdC1rZXktMDEyMzQ1Njc4OWFiY2RlZmdoaWo="}
	_, err := NewManifest(7, profile, sg, "relay.example.com", "https://panel.example.com",
		"1.5.0", []string{"linux-x64"})
	require.Error(t, err)
}
