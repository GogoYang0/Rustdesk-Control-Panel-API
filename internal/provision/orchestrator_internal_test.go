package provision

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// RustDesk expects id_ed25519 to be base64 of the 64-byte secret key.
func TestGenerateKeyPair_RustDeskEncoding(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	raw, err := base64.StdEncoding.DecodeString(kp.PrivateKey)
	require.NoError(t, err)
	require.Len(t, raw, 64, "secret key must be the 64-byte seed||pub form")

	pub, err := base64.StdEncoding.DecodeString(kp.PublicKey)
	require.NoError(t, err)
	require.Len(t, pub, 32)

	require.False(t, strings.ContainsAny(kp.PrivateKey, "/:"), "RustDesk avoids these characters")
	require.Len(t, kp.Fingerprint, 32)
}

func TestHBBSArgs_MapPortsAndRelay(t *testing.T) {
	d := &DockerOrchestrator{OrgLabel: "org", RoleLabel: "role"}
	spec := InstanceSpec{
		Name:      "panel-org-7",
		OrgID:     7,
		HbbsPort:  21116,
		HbbrPort:  21117,
		Image:     "img:tag",
		RelayHost: "relay.example.com",
		DataDir:   "/data/org-7",
	}

	args := strings.Join(d.hbbsArgs(spec, "panel-org-7-hbbs"), " ")
	require.Contains(t, args, "-p 21116:21115")
	require.Contains(t, args, "-p 21116:21116")
	require.Contains(t, args, "-p 21116:21116/udp")
	require.NotContains(t, args, "21117:21117", "the relay port belongs to hbbr only")
	require.Contains(t, args, "img:tag hbbs -r relay.example.com:21117")
	require.Contains(t, args, "-v /data/org-7:/root")
}

func TestHBBRArgs_MapRelayPorts(t *testing.T) {
	d := &DockerOrchestrator{OrgLabel: "org", RoleLabel: "role"}
	spec := InstanceSpec{
		Name:      "panel-org-7",
		OrgID:     7,
		HbbsPort:  21116,
		HbbrPort:  21117,
		Image:     "img:tag",
		RelayHost: "relay.example.com",
		DataDir:   "/data/org-7",
	}

	args := strings.Join(d.hbbrArgs(spec, "panel-org-7-hbbr"), " ")
	require.Contains(t, args, "-p 21117:21117")
	require.Contains(t, args, "-p 21117:21118")
	require.Contains(t, args, "-p 21117:21119")
	require.Contains(t, args, "img:tag hbbr")
}

// IPv6 relay hosts must be bracketed by net.JoinHostPort.
func TestHBBSArgs_IPv6RelayHost(t *testing.T) {
	d := &DockerOrchestrator{OrgLabel: "org", RoleLabel: "role"}
	spec := InstanceSpec{
		Name: "n", HbbsPort: 21116, HbbrPort: 21117,
		Image: "img:tag", RelayHost: "2001:db8::1", DataDir: "/d",
	}
	args := strings.Join(d.hbbsArgs(spec, "n-hbbs"), " ")
	require.Contains(t, args, "[2001:db8::1]:21117")
}

func TestDeploy_RequiresConfiguration(t *testing.T) {
	d := &DockerOrchestrator{OrgLabel: "org", RoleLabel: "role"}
	err := d.Deploy(t.Context(), InstanceSpec{Name: "n"})
	require.Error(t, err, "missing image/relay/data dir must fail before touching docker")
}
