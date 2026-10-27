package clientbuild

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Storage struct {
	root string
}

func NewStorage(root string) (*Storage, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("client build asset directory is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve client build asset directory: %w", err)
	}
	for _, sub := range []string{"logos", "bundles", "artifacts", "staging"} {
		if err := os.MkdirAll(filepath.Join(abs, sub), 0o700); err != nil {
			return nil, fmt.Errorf("create client build asset directory: %w", err)
		}
	}
	return &Storage{root: abs}, nil
}

func (s *Storage) Root() string { return s.root }

func (s *Storage) SaveLogo(orgID, profileID uint, sha string, data []byte) (string, error) {
	if len(sha) != 16 {
		return "", fmt.Errorf("logo digest must be 16 hex characters")
	}
	if _, err := hex.DecodeString(sha); err != nil {
		return "", fmt.Errorf("logo digest must be hex: %w", err)
	}
	rel := path.Join("logos", strconv.FormatUint(uint64(orgID), 10),
		fmt.Sprintf("%d-%s.png", profileID, sha))
	if err := s.writeAtomic(rel, data); err != nil {
		return "", err
	}
	return rel, nil
}

func (s *Storage) Open(rel string) (*os.File, error) {
	abs, err := s.resolve(rel)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("client build asset is not a regular file")
	}
	return f, nil
}

func (s *Storage) Remove(rel string) error {
	abs, err := s.resolve(rel)
	if err != nil {
		return err
	}
	if err := os.Remove(abs); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s *Storage) WriteBundle(buildID uint, manifest, logo []byte) error {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := writeTarFile(tw, "manifest.json", manifest); err != nil {
		return err
	}
	if len(logo) > 0 {
		if err := writeTarFile(tw, "logo.png", logo); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	rel := path.Join("bundles", fmt.Sprintf("%d.tar.gz", buildID))
	return s.writeAtomic(rel, buf.Bytes())
}

func (s *Storage) OpenBundle(buildID uint) (*os.File, error) {
	return s.Open(path.Join("bundles", fmt.Sprintf("%d.tar.gz", buildID)))
}

func (s *Storage) BundleExists(buildID uint) bool {
	abs, err := s.resolve(path.Join("bundles", fmt.Sprintf("%d.tar.gz", buildID)))
	if err != nil {
		return false
	}
	info, err := os.Stat(abs)
	return err == nil && info.Mode().IsRegular()
}

func (s *Storage) RemoveBundle(buildID uint) error {
	return s.Remove(path.Join("bundles", fmt.Sprintf("%d.tar.gz", buildID)))
}

func (s *Storage) NewStaging(buildID uint) (string, error) {
	return os.MkdirTemp(filepath.Join(s.root, "staging"), fmt.Sprintf("%d-", buildID))
}

func (s *Storage) ArtifactDir(orgID, buildID uint) (string, error) {
	dir := filepath.Join(s.root, "artifacts",
		strconv.FormatUint(uint64(orgID), 10),
		strconv.FormatUint(uint64(buildID), 10))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func (s *Storage) RemoveBuildArtifacts(orgID, buildID uint) error {
	dir := filepath.Join(s.root, "artifacts",
		strconv.FormatUint(uint64(orgID), 10),
		strconv.FormatUint(uint64(buildID), 10))
	return os.RemoveAll(dir)
}

func (s *Storage) writeAtomic(rel string, data []byte) error {
	abs, err := s.resolve(rel)
	if err != nil {
		return err
	}
	dir := filepath.Dir(abs)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(name)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, abs); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

func (s *Storage) resolve(rel string) (string, error) {
	if rel == "" || filepath.IsAbs(rel) {
		return "", fmt.Errorf("invalid client build asset path")
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == "." || clean == ".." ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid client build asset path")
	}
	abs := filepath.Join(s.root, clean)
	within, err := filepath.Rel(s.root, abs)
	if err != nil || within == ".." ||
		strings.HasPrefix(within, ".."+string(filepath.Separator)) || filepath.IsAbs(within) {
		return "", fmt.Errorf("client build asset path escapes the asset directory")
	}
	return abs, nil
}

func writeTarFile(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0o600,
		Size:    int64(len(data)),
		ModTime: time.Now().UTC(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}
