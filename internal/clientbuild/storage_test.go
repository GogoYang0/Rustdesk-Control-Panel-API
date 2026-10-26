package clientbuild

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStorage_SaveLogoAndResolve(t *testing.T) {
	s, err := NewStorage(t.TempDir())
	require.NoError(t, err)
	rel, err := s.SaveLogo(7, 9, "abcdef0123456789", []byte("png"))
	require.NoError(t, err)
	require.Equal(t, "logos/7/9-abcdef0123456789.png", rel)
	f, err := s.Open(rel)
	require.NoError(t, err)
	f.Close()
	_, err = s.Open("../escape")
	require.Error(t, err)
	require.NoError(t, s.Remove(rel))
	require.NoError(t, s.Remove(rel), "removing a missing file is idempotent")
}

func TestStorage_WriteBundle(t *testing.T) {
	s, err := NewStorage(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, s.WriteBundle(42, []byte(`{"schema_version":1}`), []byte("logo")))
	require.True(t, s.BundleExists(42))
	f, err := s.OpenBundle(42)
	require.NoError(t, err)
	defer f.Close()
	gz, err := gzip.NewReader(f)
	require.NoError(t, err)
	tr := tar.NewReader(gz)
	names := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		names[hdr.Name] = true
	}
	require.True(t, names["manifest.json"])
	require.True(t, names["logo.png"])
}

func TestStorage_ArtifactDirsAndStaging(t *testing.T) {
	s, err := NewStorage(t.TempDir())
	require.NoError(t, err)
	dir, err := s.ArtifactDir(3, 4)
	require.NoError(t, err)
	require.Contains(t, dir, "artifacts")
	require.NoError(t, s.RemoveBuildArtifacts(3, 4))
	stage, err := s.NewStaging(4)
	require.NoError(t, err)
	require.Contains(t, stage, "staging")
	_, err = s.Open("../../outside")
	require.Error(t, err)
}
