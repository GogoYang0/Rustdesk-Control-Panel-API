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
	require.Contains(t, got, "p%3Fss") // 密码不被改写
}

func TestApplyPostgresTimeouts_AlreadySet(t *testing.T) {
	dsn := "host=localhost connect_timeout=9"
	require.Equal(t, dsn, applyPostgresTimeouts(dsn))
}

func TestApplyMySQLTimeouts_PasswordWithQuestionMark(t *testing.T) {
	// 密码里的 '?' 位于最后一个 '/' 之前，不得被当作参数分隔符
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
	// 只有 dial timeout 时，read/write/parseTime 仍需分别补齐，
	// 且操作者显式设置的 timeout=9s 必须保留且只出现一次（驱动后值覆盖前值）
	dsn := "root:mysql@tcp(localhost:3306)/panel_test?timeout=9s"
	got := applyMySQLTimeouts(dsn)
	require.Equal(t, 1, strings.Count(got, "timeout=")) // timeout=9s 保留，不再追加 timeout=5s
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
	// 参数值里的 '?' 不得影响参数区识别（驱动在最后一个 '/' 后找第一个 '?'）
	dsn := "root:mysql@tcp(localhost:3306)/panel_test?parseTime=false&connectionAttributes=app:worker?debug"
	got := applyMySQLTimeouts(dsn)
	require.Contains(t, got, "parseTime=false")
	require.Equal(t, 1, strings.Count(got, "parseTime="))
	require.Contains(t, got, "timeout=5s")
}
