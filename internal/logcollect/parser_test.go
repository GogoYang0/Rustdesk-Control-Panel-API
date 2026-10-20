package logcollect

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
)

func testRules() []Rule {
	return []Rule{
		{
			Name:    "connection",
			Pattern: `^INFO connection from (?P<device>\d{9}) via (?P<addr>[\d.:]+)$`,
			Level:   "info",
			Kind:    "conn",
		},
		{
			Name:    "errors",
			Pattern: `^ERROR (?P<msg>.*)$`,
			Level:   "error",
			Kind:    "error",
		},
	}
}

// A configured rule maps the line onto level/kind, exposes the named groups as
// detail and lifts the device group out as the RustDesk id.
func TestParser_MatchesConfiguredRule(t *testing.T) {
	p, err := NewParser(testRules())
	require.NoError(t, err)
	require.Equal(t, 2, p.Rules())

	at := time.Date(2026, 10, 20, 6, 0, 0, 0, time.UTC)
	event, ok := p.Parse("INFO connection from 123456789 via 10.0.0.5:50000", at)
	require.True(t, ok)
	require.Equal(t, "connection", event.Rule)
	require.Equal(t, model.LogLevelInfo, event.Level)
	require.Equal(t, model.LogKindConn, event.Kind)
	require.Equal(t, "123456789", event.DeviceRustdeskID)
	require.Equal(t, "10.0.0.5:50000", event.Detail["addr"])
	require.Equal(t, at, event.OccurredAt)
	require.Contains(t, event.Detail, "raw")

	// The second rule serves the error shape.
	event, ok = p.Parse("ERROR relay quota exceeded", at)
	require.True(t, ok)
	require.Equal(t, model.LogKindError, event.Kind)
	require.Equal(t, "relay quota exceeded", event.Detail["msg"])
	require.Empty(t, event.DeviceRustdeskID)
}

// Unmatched lines are dropped and counted, never fatal (C7): the tailer keeps
// consuming the rest of the stream.
func TestParser_MalformedLine_Dropped_NotFatal(t *testing.T) {
	p, err := NewParser(testRules())
	require.NoError(t, err)

	at := time.Now()
	for i := 0; i < 3; i++ {
		_, ok := p.Parse("\x00garbage without any shape", at)
		require.False(t, ok)
	}
	require.EqualValues(t, 3, p.ParseErrors())

	// A good line right after the garbage still parses.
	_, ok := p.Parse("INFO connection from 987654321 via 192.0.2.1:1", at)
	require.True(t, ok)
	require.EqualValues(t, 3, p.ParseErrors())
}

// A bad regular expression fails at construction instead of silently dropping
// every line at runtime.
func TestParser_InvalidRule_Rejected(t *testing.T) {
	_, err := NewParser([]Rule{{Name: "broken", Pattern: "([unclosed"}})
	require.Error(t, err)
	_, err = NewParser([]Rule{{Name: "empty", Pattern: "  "}})
	require.Error(t, err)
}

// Unknown level/kind values clamp to the contract defaults.
func TestParser_NormalizesLevelAndKind(t *testing.T) {
	p, err := NewParser([]Rule{{Name: "r", Pattern: `^(?P<msg>.*)$`, Level: "DEBUG", Kind: "weird"}})
	require.NoError(t, err)
	event, ok := p.Parse("anything", time.Now())
	require.True(t, ok)
	require.Equal(t, model.LogLevelInfo, event.Level)
	require.Equal(t, model.LogKindOther, event.Kind)
}

// The rules shipped in configs/config.yaml must actually match the pinned
// server's log format: a silently wrong default would collect nothing while
// reporting "enabled".
func TestExampleConfigRules_MatchServerFormat(t *testing.T) {
	v := viper.New()
	v.SetConfigFile(filepath.Join("..", "..", "configs", "config.yaml"))
	require.NoError(t, v.ReadInConfig())
	var cfg struct {
		Logcollect struct {
			Rules []Rule `mapstructure:"rules"`
		} `mapstructure:"logcollect"`
	}
	require.NoError(t, v.Unmarshal(&cfg))
	require.NotEmpty(t, cfg.Logcollect.Rules, "the deployment config ships default rules")

	p, err := NewParser(cfg.Logcollect.Rules)
	require.NoError(t, err)

	cases := []struct {
		line   string
		level  string
		kind   string
		device string
	}{
		{"[2026-10-20T06:00:00Z INFO  hbbs] connection from 123456789", model.LogLevelInfo, model.LogKindConn, "123456789"},
		{"[2026-10-20T06:00:02Z INFO  hbbs] file transfer 123456789 -> 987654321", model.LogLevelInfo, model.LogKindFile, "123456789"},
		{"[2026-10-20T06:00:03Z WARN  hbbr] slow client", model.LogLevelWarn, model.LogKindOther, ""},
		{"[2026-10-20T06:00:04Z ERROR hbbs] relay quota exceeded", model.LogLevelError, model.LogKindError, ""},
	}
	for _, tc := range cases {
		event, ok := p.Parse(tc.line, time.Now())
		require.True(t, ok, "the shipped rules must match %q", tc.line)
		require.Equal(t, tc.level, event.Level, tc.line)
		require.Equal(t, tc.kind, event.Kind, tc.line)
		require.Equal(t, tc.device, event.DeviceRustdeskID, tc.line)
	}
}

// A rule like (?P<msg>.*) captures the whole line, so an oversized log line
// would be stored verbatim in the detail: every captured value is bounded,
// not just the raw copy (the scanner accepts up to maxLineBytes).
func TestParser_TruncatesCapturedValues(t *testing.T) {
	parser, err := NewParser([]Rule{
		{Name: "errors", Pattern: `^ERROR (?P<msg>.*)$`, Level: "error", Kind: "error"},
	})
	require.NoError(t, err)

	long := strings.Repeat("x", 3*maxDetailValueBytes)
	ev, ok := parser.Parse("ERROR "+long, time.Now())
	require.True(t, ok)

	msg, isString := ev.Detail["msg"].(string)
	require.True(t, isString)
	require.LessOrEqual(t, len(msg), maxDetailValueBytes+len("...(truncated)"),
		"a captured value must be bounded")
	require.Contains(t, msg, "(truncated)")
}

// Cutting at a byte offset can split a multi-byte character, and the resulting
// invalid UTF-8 would be stored as a replacement character once the detail is
// encoded as JSON: truncation must back off to a character boundary.
func TestParser_TruncationKeepsValidUTF8(t *testing.T) {
	// maxDetailValueBytes-1 ASCII bytes followed by a two-byte rune: the byte
	// limit lands inside that rune.
	long := strings.Repeat("a", maxDetailValueBytes-1) + "é" + strings.Repeat("b", 100)

	got := truncateValue(long)
	require.True(t, utf8.ValidString(got), "truncation must not split a multi-byte character")
	require.Contains(t, got, "...(truncated)")
}
