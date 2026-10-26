package clientbuild

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GogoYang0/rustdesk-control-panel-api/internal/model"
	"github.com/GogoYang0/rustdesk-control-panel-api/internal/store"
)

type zipEntry struct {
	Name string
	Body []byte
	Mode os.FileMode
}

func makeZip(t *testing.T, entries ...zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		hdr := &zip.FileHeader{Name: e.Name, Method: zip.Deflate}
		if e.Mode != 0 {
			hdr.SetMode(e.Mode)
		}
		w, err := zw.CreateHeader(hdr)
		require.NoError(t, err)
		_, err = w.Write(e.Body)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// fakeArtifacts wires one remote artifact per zip name. Names must already be
// the panel-client-<buildID>-<platform> form.
func (f *fixture) fakeArtifacts(buildID uint, zips map[string][]byte) {
	names := make([]string, 0, len(zips))
	for name := range zips {
		names = append(names, name)
	}
	sort.Strings(names)
	byID := map[int64]string{}
	remote := make([]RemoteArtifact, 0, len(names))
	for i, name := range names {
		id := int64(100 + i)
		byID[id] = name
		remote = append(remote, RemoteArtifact{ID: id, Name: name, SizeBytes: int64(len(zips[name]))})
	}
	f.github.listArtifactsFn = func(context.Context, int64) ([]RemoteArtifact, error) {
		return remote, nil
	}
	f.github.downloadFn = func(_ context.Context, id int64, dest string, _ int64) (int64, error) {
		data := zips[byID[id]]
		require.NoError(f.t, os.WriteFile(dest, data, 0o600))
		return int64(len(data)), nil
	}
}

func (f *fixture) ingest(t *testing.T, d *BuildDetail) error {
	t.Helper()
	runID := int64(4242)
	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).Model(&model.ClientBuild{}).
		Where("id = ?", d.Build.ID).Updates(map[string]any{
		"status": model.ClientBuildStatusIngesting, "ingesting_at": f.now, "github_run_id": runID,
	}).Error)
	d.Build.Status = model.ClientBuildStatusIngesting
	d.Build.GitHubRunID = &runID
	return f.svc.ingestRun(context.Background(), &d.Build)
}

func TestIngest_SuccessAndOpenArtifact(t *testing.T) {
	f := newFixture(t)
	p := f.createProfile(t, "Acme", "Acme")
	d := f.createBuild(t, p.ID, []string{"linux-x64"})
	zipName := "panel-client-" + itoa(d.Build.ID) + "-linux-x64"
	file := zipName + ".AppImage"
	zipData := makeZip(t, zipEntry{Name: file, Body: []byte("appimage-bytes")})
	f.fakeArtifacts(d.Build.ID, map[string][]byte{zipName: zipData})
	deleted := int64(0)
	f.github.deleteFn = func(_ context.Context, id int64) error { deleted = id; return nil }

	require.NoError(t, f.ingest(t, d))
	got, err := f.svc.GetBuild(context.Background(), f.org.ID, d.Build.ID)
	require.NoError(t, err)
	require.Equal(t, model.ClientBuildStatusSucceeded, got.Build.Status)
	require.Equal(t, 1, got.Build.ArtifactCount)
	require.Len(t, got.Artifacts, 1)
	require.Equal(t, file, got.Artifacts[0].FileName)
	require.EqualValues(t, len("appimage-bytes"), got.Artifacts[0].SizeBytes)
	sum := sha256.Sum256([]byte("appimage-bytes"))
	require.Equal(t, hex.EncodeToString(sum[:]), got.Artifacts[0].SHA256)
	require.EqualValues(t, 100, deleted)
	require.Contains(t, f.recorder.actions(), "client_build.succeeded")

	opened, err := f.svc.OpenArtifact(context.Background(), f.org.ID, d.Build.ID, got.Artifacts[0].ID, f.user.ID)
	require.NoError(t, err)
	raw, err := io.ReadAll(opened.File)
	opened.File.Close()
	require.NoError(t, err)
	require.Equal(t, "appimage-bytes", string(raw))
	require.Contains(t, f.recorder.actions(), "client_build.artifact.download")

	_, err = f.svc.OpenArtifact(context.Background(), f.otherOrg.ID, d.Build.ID, got.Artifacts[0].ID, f.user.ID)
	require.ErrorIs(t, err, ErrNotFound)

	require.NoError(t, store.ScopedByOrg(f.db, f.org.ID).Model(&model.ClientBuild{}).
		Where("id = ?", d.Build.ID).Update("artifacts_purged_at", time.Now()).Error)
	_, err = f.svc.OpenArtifact(context.Background(), f.org.ID, d.Build.ID, got.Artifacts[0].ID, f.user.ID)
	require.ErrorIs(t, err, ErrArtifactUnavailable)
}

func TestIngest_WindowsNeedsBothFiles(t *testing.T) {
	f := newFixture(t)
	p := f.createProfile(t, "Acme", "Acme")
	d := f.createBuild(t, p.ID, []string{"windows-x64"})
	zipName := "panel-client-" + itoa(d.Build.ID) + "-windows-x64"
	prefix := zipName
	f.fakeArtifacts(d.Build.ID, map[string][]byte{
		zipName: makeZip(t,
			zipEntry{Name: prefix + ".exe", Body: []byte("exe")},
			zipEntry{Name: prefix + ".zip", Body: []byte("zip")},
		),
	})
	require.NoError(t, f.ingest(t, d))
	got, err := f.svc.GetBuild(context.Background(), f.org.ID, d.Build.ID)
	require.NoError(t, err)
	require.Len(t, got.Artifacts, 2)
}

func TestIngest_ValidationFailures(t *testing.T) {
	cases := []struct {
		name  string
		files []zipEntry
		max   int64
	}{
		{"only exe", []zipEntry{{Name: "panel-client-1-windows-x64.exe", Body: []byte("x")}}, 0},
		{"zip slip", []zipEntry{{Name: "../evil.AppImage", Body: []byte("x")}}, 0},
		{"backslash", []zipEntry{{Name: `dir\evil.AppImage`, Body: []byte("x")}}, 0},
		{"directory", []zipEntry{{Name: "dir/", Body: nil, Mode: os.ModeDir | 0o755}}, 0},
		{"symlink", []zipEntry{{Name: "link.AppImage", Body: []byte("/etc/passwd"), Mode: os.ModeSymlink | 0o777}}, 0},
		{"wrong extension", []zipEntry{{Name: "panel-client-1-windows-x64.dmg", Body: []byte("x")}}, 0},
		{"duplicate", []zipEntry{{Name: "panel-client-1-windows-x64.exe", Body: []byte("x")}, {Name: "panel-client-1-windows-x64.exe", Body: []byte("y")}}, 0},
		{"oversize", []zipEntry{{Name: "panel-client-1-linux-x64.AppImage", Body: []byte("12345")}}, 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			p := f.createProfile(t, "Acme", "Acme")
			platform := "windows-x64"
			if tc.name == "oversize" || tc.name == "zip slip" || tc.name == "backslash" ||
				tc.name == "directory" || tc.name == "symlink" {
				platform = "linux-x64"
			}
			if tc.name == "only exe" || tc.name == "wrong extension" || tc.name == "duplicate" {
				platform = "windows-x64"
			}
			if tc.max > 0 {
				f.svc.cfg.MaxArtifactBytes = tc.max
			}
			d := f.createBuild(t, p.ID, []string{platform})
			zipName := "panel-client-" + itoa(d.Build.ID) + "-" + platform
			f.fakeArtifacts(d.Build.ID, map[string][]byte{zipName: makeZip(t, tc.files...)})
			require.Error(t, f.ingest(t, d))
			got, err := f.svc.GetBuild(context.Background(), f.org.ID, d.Build.ID)
			require.NoError(t, err)
			require.Equal(t, model.ClientBuildStatusFailed, got.Build.Status)
			require.Empty(t, got.Artifacts)
			require.Contains(t, f.recorder.actions(), "client_build.failed")
		})
	}
}

func TestIngest_MissingAndExtraArtifacts(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		f := newFixture(t)
		p := f.createProfile(t, "Acme", "Acme")
		d := f.createBuild(t, p.ID, []string{"linux-x64", "windows-x64"})
		zipName := "panel-client-" + itoa(d.Build.ID) + "-linux-x64"
		f.fakeArtifacts(d.Build.ID, map[string][]byte{
			zipName: makeZip(t, zipEntry{Name: zipName + ".AppImage", Body: []byte("x")}),
		})
		require.Error(t, f.ingest(t, d))
		got, _ := f.svc.GetBuild(context.Background(), f.org.ID, d.Build.ID)
		require.Equal(t, model.ClientBuildStatusFailed, got.Build.Status)
		require.Empty(t, got.Artifacts)
	})
	t.Run("extra", func(t *testing.T) {
		f := newFixture(t)
		p := f.createProfile(t, "Acme", "Acme")
		d := f.createBuild(t, p.ID, []string{"linux-x64"})
		zipName := "panel-client-" + itoa(d.Build.ID) + "-linux-x64"
		f.fakeArtifacts(d.Build.ID, map[string][]byte{
			zipName:          makeZip(t, zipEntry{Name: zipName + ".AppImage", Body: []byte("x")}),
			"unexpected-log": makeZip(t, zipEntry{Name: "log.txt", Body: []byte("x")}),
		})
		require.Error(t, f.ingest(t, d))
		got, _ := f.svc.GetBuild(context.Background(), f.org.ID, d.Build.ID)
		require.Equal(t, model.ClientBuildStatusFailed, got.Build.Status)
	})
}

func TestOpenArtifact_AuditFailClosed(t *testing.T) {
	f := newFixture(t)
	p := f.createProfile(t, "Acme", "Acme")
	d := f.createBuild(t, p.ID, []string{"linux-x64"})
	zipName := "panel-client-" + itoa(d.Build.ID) + "-linux-x64"
	f.fakeArtifacts(d.Build.ID, map[string][]byte{
		zipName: makeZip(t, zipEntry{Name: zipName + ".AppImage", Body: []byte("x")}),
	})
	require.NoError(t, f.ingest(t, d))
	got, err := f.svc.GetBuild(context.Background(), f.org.ID, d.Build.ID)
	require.NoError(t, err)
	f.svc.auditor = &fakeRecorder{fail: errors.New("audit down")}
	file, err := f.svc.OpenArtifact(context.Background(), f.org.ID, d.Build.ID, got.Artifacts[0].ID, f.user.ID)
	require.ErrorIs(t, err, ErrUnaudited)
	require.Nil(t, file)
}

func itoa(v uint) string {
	return fmtUint(v)
}

func fmtUint(v uint) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
