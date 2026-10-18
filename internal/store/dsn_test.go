package store

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApplyPostgresTimeouts_KeywordDSNWithSpecialPassword(t *testing.T) {
	dsn := "host=localhost user=u password=p?ss dbname=panel_test"
	got := applyPostgresTimeouts(dsn)
	require.Equal(t, dsn+" connect_timeout=5", got)
}

func TestApplyPostgresTimeouts_URLDSN(t *testing.T) {
	got := applyPostgresTimeouts("postgres://u:p%3Fss@localhost/panel_test")
	require.Contains(t, got, "connect_timeout=5")
	require.Contains(t, got, "p%3Fss") // password must stay untouched
}

func TestApplyPostgresTimeouts_AlreadySet(t *testing.T) {
	dsn := "host=localhost connect_timeout=9"
	require.Equal(t, dsn, applyPostgresTimeouts(dsn))
}

func TestApplyMySQLTimeouts_PasswordWithQuestionMark(t *testing.T) {
	// the '?' in the password sits before the last '/', so it is not a param separator
	dsn := "u:p?ss@tcp(localhost:3306)/panel_test"
	got := applyMySQLTimeouts(dsn)
	require.Equal(t, dsn+"?timeout=5s&readTimeout=10s&writeTimeout=10s&parseTime=true", got)
}

func TestApplyMySQLTimeouts_ExistingParams(t *testing.T) {
	dsn := "root:mysql@tcp(localhost:3306)/panel_test?parseTime=true"
	got := applyMySQLTimeouts(dsn)
	require.Equal(t, dsn+"&timeout=5s&readTimeout=10s&writeTimeout=10s", got)
}

func TestApplyMySQLTimeouts_PartialTimeoutsBackfilled(t *testing.T) {
	// With only a dial timeout set, read/write/parseTime must still be backfilled,
	// and the explicit timeout=9s must be preserved exactly once (later values win).
	dsn := "root:mysql@tcp(localhost:3306)/panel_test?timeout=9s"
	got := applyMySQLTimeouts(dsn)
	require.Equal(t, 1, strings.Count(got, "timeout=")) // keep timeout=9s, do not append timeout=5s
	require.Contains(t, got, "timeout=9s")
	require.Contains(t, got, "readTimeout=10s")
	require.Contains(t, got, "writeTimeout=10s")
	require.Contains(t, got, "parseTime=true")
}

func TestApplyMySQLTimeouts_ParseTimePreserved(t *testing.T) {
	dsn := "root:mysql@tcp(localhost:3306)/panel_test?parseTime=false"
	got := applyMySQLTimeouts(dsn)
	require.Contains(t, got, "parseTime=false")
	require.Equal(t, 1, strings.Count(got, "parseTime="))
}

func TestApplyMySQLTimeouts_QuestionMarkInsideParamValue(t *testing.T) {
	// a '?' inside a param value must not confuse param detection (driver scans for the first '?' after the last '/')
	dsn := "root:mysql@tcp(localhost:3306)/panel_test?parseTime=false&connectionAttributes=app:worker?debug"
	got := applyMySQLTimeouts(dsn)
	require.Contains(t, got, "parseTime=false")
	require.Equal(t, 1, strings.Count(got, "parseTime="))
	require.Contains(t, got, "timeout=5s")
}
