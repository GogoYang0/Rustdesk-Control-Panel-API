package store

import (
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
	require.Equal(t, dsn+"?timeout=5s&readTimeout=10s&writeTimeout=10s", got)
}

func TestApplyMySQLTimeouts_ExistingParams(t *testing.T) {
	dsn := "root:mysql@tcp(localhost:3306)/panel_test?parseTime=true"
	got := applyMySQLTimeouts(dsn)
	require.Equal(t, dsn+"&timeout=5s&readTimeout=10s&writeTimeout=10s", got)
}
