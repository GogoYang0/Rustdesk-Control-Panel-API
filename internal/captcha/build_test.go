package captcha

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBuild_UnknownProvider(t *testing.T) {
	_, err := Build(Options{Provider: "bogus"})
	require.Error(t, err)
}

func TestBuild_RequiresProviderSecrets(t *testing.T) {
	_, err := Build(Options{Provider: "altcha"})
	require.ErrorContains(t, err, "PANEL_CAPTCHA_ALTCHA_KEY")

	_, err = Build(Options{Provider: "geetest", GeetestID: "id"})
	require.ErrorContains(t, err, "PANEL_CAPTCHA_GEETEST_KEY")

	_, err = Build(Options{Provider: "cap", CapInstanceURL: "https://cap.example.com", CapSiteKey: "site"})
	require.ErrorContains(t, err, "PANEL_CAPTCHA_CAP_SECRET")
}

func TestBuild_AltchaDefaults(t *testing.T) {
	s, err := Build(Options{Provider: "altcha", AltchaKey: "key", ChallengeTTL: 5 * time.Minute})
	require.NoError(t, err)
	require.True(t, s.Enabled())
	require.Equal(t, "closed", s.failMode)

	ch, err := s.Challenge(t.Context())
	require.NoError(t, err)
	require.Equal(t, "altcha", ch.Provider)
}

func TestBuild_GeeTestNeedsCaptchaID(t *testing.T) {
	_, err := Build(Options{Provider: "geetest", GeetestKey: "key"})
	require.ErrorContains(t, err, "geetest")
}
