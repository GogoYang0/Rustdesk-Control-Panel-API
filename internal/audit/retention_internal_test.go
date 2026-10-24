package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// verifyArchive is the gate between archiving and deleting rows; it must reject a
// truncated file or a digest mismatch.
func TestVerifyArchive_RejectsBadFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	require.NoError(t, os.WriteFile(path, []byte("{\"a\":1}\n{\"a\":2}\n"), 0o600))

	// Correct line count but wrong digest.
	require.Error(t, verifyArchive(path, strings.Repeat("0", 64), 2))
	// Correct digest but wrong line count.
	sum := sha256Hex(t, path)
	require.Error(t, verifyArchive(path, sum, 3))
	// Both correct.
	require.NoError(t, verifyArchive(path, sum, 2))
	// Missing file.
	require.Error(t, verifyArchive(filepath.Join(dir, "missing.jsonl"), sum, 2))
}

func sha256Hex(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
