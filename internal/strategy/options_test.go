package strategy_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/strategy"
)

// TestAllowedOptions_MatchesDesignList pins the whole whitelist. The client
// applies whatever lands in config_options, so this list is the security
// boundary: adding a key must be a deliberate change here, in docs and in the
// contract, never a by-product of a refactor.
func TestAllowedOptions_MatchesDesignList(t *testing.T) {
	want := []string{
		"enable-audio", "enable-clipboard", "enable-file-transfer",
		"enable-file-copy-paste", "enable-camera", "enable-terminal",
		"enable-tunnel", "enable-remote-restart", "enable-record-session",
		"enable-block-input", "enable-privacy-mode", "enable-remote-modify",
		"enable-remote-printer", "enable-check-update", "disable-change-id",
		"disable-settings", "disable-installation", "disable-unlock-pin",
		"disable-tcp-listen", "disable-ab",
	}
	got := strategy.AllowedOptions()
	require.Equal(t, want, got)
	require.Less(t, len(got), strategy.MaxOptionsPerStrategy,
		"the whitelist must stay smaller than the defensive key cap")
}

func TestAllowedOptions_ReturnsCopy(t *testing.T) {
	first := strategy.AllowedOptions()
	require.NotEmpty(t, first)
	first[0] = "api-server"
	require.NotContains(t, strategy.AllowedOptions(), "api-server")
}

// TestNormalizeOptions_RejectsSystemKeys is the core security test: these keys
// redirect the client to another server or replace its key, i.e. device
// takeover. They must never pass, whatever their spelling.
func TestNormalizeOptions_RejectsSystemKeys(t *testing.T) {
	for _, key := range []string{
		"api-server", "custom-rendezvous-server", "relay-server",
		"key", "whitelist", "direct-server", "proxy-url",
	} {
		_, err := strategy.NormalizeOptions(map[string]string{key: "evil.example.com"})
		require.ErrorIs(t, err, strategy.ErrUnknownOption, "key %q must be rejected", key)
		require.Contains(t, err.Error(), key, "the error must name the offending key")
	}
}

func TestNormalizeOptions_RejectsCaseAndWhitespaceVariants(t *testing.T) {
	for _, key := range []string{
		"ENABLE-AUDIO", "Enable-Audio", " enable-audio", "enable-audio ",
		"enable-audio\t", "enable-audio\n", "enable_audio",
	} {
		_, err := strategy.NormalizeOptions(map[string]string{key: "Y"})
		require.ErrorIs(t, err, strategy.ErrUnknownOption, "key %q must be rejected verbatim", key)
	}
}

func TestNormalizeOptions_AcceptsWhitelistedValues(t *testing.T) {
	in := map[string]string{
		"enable-audio":          "Y",
		"enable-clipboard":      "N",
		"enable-record-session": "",
	}
	out, err := strategy.NormalizeOptions(in)
	require.NoError(t, err)
	require.Equal(t, in, out)

	// The result is a copy: mutating it must not touch the caller's map.
	out["enable-audio"] = "N"
	require.Equal(t, "Y", in["enable-audio"])
}

// TestNormalizeOptions_RejectsOversizedValue counts runes, not bytes: a 256
// character value of multi-byte runes must pass, 257 must fail.
func TestNormalizeOptions_RejectsOversizedValue(t *testing.T) {
	ok := strings.Repeat("开", strategy.MaxOptionValueLen)
	_, err := strategy.NormalizeOptions(map[string]string{"enable-audio": ok})
	require.NoError(t, err)

	tooLong := ok + "开"
	_, err = strategy.NormalizeOptions(map[string]string{"enable-audio": tooLong})
	require.ErrorIs(t, err, strategy.ErrInvalidOptionValue)
}

// TestNormalizeOptions_RejectsControlCharacters: the value is written into the
// client's config file, so line breaks and NULs are refused instead of being
// smuggled through JSON.
func TestNormalizeOptions_RejectsControlCharacters(t *testing.T) {
	for _, value := range []string{"Y\nN", "Y\r", "Y\x00", "Y\x1b[31m"} {
		_, err := strategy.NormalizeOptions(map[string]string{"enable-audio": value})
		require.ErrorIs(t, err, strategy.ErrInvalidOptionValue, "value %q must be rejected", value)
	}
}

func TestNormalizeOptions_NilIsEmpty(t *testing.T) {
	out, err := strategy.NormalizeOptions(nil)
	require.NoError(t, err)
	require.Empty(t, out)
}

func TestNormalizeOptions_RejectsDuplicateKeysAfterFold(t *testing.T) {
	// Go maps cannot hold the same key twice, so the only way to look
	// duplicated is a case variant, which the verbatim check already rejects.
	// This test documents that closure: no trimming or folding is performed.
	_, err := strategy.NormalizeOptions(map[string]string{
		"enable-audio": "Y", "ENABLE-AUDIO": "N",
	})
	require.ErrorIs(t, err, strategy.ErrUnknownOption)
}
