package logcollect

import (
	"testing"
	"time"

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
